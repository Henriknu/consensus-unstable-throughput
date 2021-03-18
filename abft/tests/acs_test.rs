use abft::{
    buffer::{ABFTBuffer, ABFTBufferCommand, ABFTReceiver},
    messaging::{ProtocolMessageSender, ToProtocolMessage},
    proto::ProtocolMessage,
    protocols::{
        acs::{
            buffer::{ACSBuffer, ACSBufferCommand},
            ACSError, ACS,
        },
        mvba::buffer::{MVBABufferCommand, MVBAReceiver},
        prbc::{
            buffer::{PRBCBuffer, PRBCBufferCommand, PRBCReceiver},
            PRBCError, PRBCResult, PRBC,
        },
    },
    ABFTError, EncryptedTransactionSet, ABFT,
};

use abft::Value;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use futures::future::join_all;

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};

use tokio::sync::mpsc::{self, Sender};

use log::{debug, error, info};

const N_PARTIES: usize = THRESHOLD * 3 + 1;
const THRESHOLD: usize = 3;
const BUFFER_CAPACITY: usize = N_PARTIES * N_PARTIES * 50 + 100;

struct ChannelSender {
    senders: HashMap<u32, Sender<ProtocolMessage>>,
}

#[async_trait]
impl ProtocolMessageSender for ChannelSender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: u32,
        send_id: u32,
        recv_id: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    ) {
        if !self.senders.contains_key(&recv_id) {
            return;
        }

        let sender = &self.senders[&recv_id];
        if let Err(e) = sender
            .send(message.to_protocol_message(id, send_id, recv_id, view, prbc_index))
            .await
        {
            error!("Got error when sending message: {}", e);
        }
    }

    async fn broadcast<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: u32,
        send_id: u32,
        n_parties: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    ) {
        let message = message.to_protocol_message(id, send_id, 0, view, prbc_index);

        for i in (0..n_parties) {
            if !self.senders.contains_key(&i) {
                continue;
            }
            let mut inner = message.clone();
            let mut header = inner.header.take().unwrap();
            header.recv_id = i;
            inner.header.replace(header);
            let sender = &self.senders[&i];
            if let Err(e) = sender.send(inner).await {
                error!("Got error when sending message: {}", e);
            }
        }
    }
}

struct ACSBufferManager {
    sender: Sender<ACSBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for ACSBufferManager {
    async fn drain_rbc(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::PRBC {
                send_id,
                inner: PRBCBufferCommand::RBC,
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }

    async fn drain_prbc_done(&self, send_id: u32) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::PRBC {
                send_id,
                inner: PRBCBufferCommand::PRBC,
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }
}

#[async_trait]
impl MVBAReceiver for ACSBufferManager {
    async fn drain_pp_receive(
        &self,
        view: u32,
        send_id: u32,
    ) -> abft::protocols::mvba::proposal_promotion::PPResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::PPReceive { view, send_id },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_elect(&self, view: u32) -> abft::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::ElectCoinShare { view },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_view_change(&self, view: u32) -> abft::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ACSBufferCommand::MVBA {
                inner: MVBABufferCommand::ViewChange { view },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn acs_correctness() {
    use env_logger::{Builder, Target};

    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();

    let mut mvba_signers = Signer::generate_signers(N_PARTIES, N_PARTIES - THRESHOLD - 1);
    let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD + 1);

    assert_eq!(mvba_signers.len(), N_PARTIES);
    assert_eq!(coins.len(), N_PARTIES);

    let mut prbc_signers = Signer::generate_signers(N_PARTIES, THRESHOLD);

    assert_eq!(prbc_signers.len(), N_PARTIES);

    let mut channels: Vec<_> = (0..N_PARTIES)
        .map(|_| {
            let (tx, rx) = mpsc::channel(BUFFER_CAPACITY);
            (tx, Some(rx))
        })
        .collect();

    let mut handles = Vec::with_capacity(N_PARTIES);

    for i in 0..N_PARTIES {
        let mut recv = channels[i].1.take().unwrap();
        let senders: HashMap<u32, Sender<_>> = channels
            .iter()
            .enumerate()
            .filter_map(|(j, channel)| {
                if i != j {
                    Some((j as u32, channel.0.clone()))
                } else {
                    None
                }
            })
            .collect();

        let mvba_signer = Arc::new(mvba_signers.remove(0));
        let prbc_signer = Arc::new(prbc_signers.remove(0));
        let coin = Arc::new(coins.remove(0));

        let f = Arc::new(ChannelSender { senders });

        //let value = Value::new(i * 1000);
        let value = EncryptedTransactionSet::default();

        let acs = Arc::new(ACS::init(0, i as u32, N_PARTIES as u32, value));

        // Setup buffer manager

        let mut buffer = ACSBuffer::new();
        let buffer_acs = acs.clone();
        let buffer_mvba_signer = mvba_signer.clone();
        let buffer_prbc_signer = prbc_signer.clone();
        let buffer_coin = coin.clone();
        let buffer_f = f.clone();

        let (buff_cmd_send, mut buff_cmd_recv) = mpsc::channel::<ACSBufferCommand>(BUFFER_CAPACITY);

        let r = Arc::new(ACSBufferManager {
            sender: buff_cmd_send.clone(),
        });

        let _ = tokio::spawn(async move {
            while let Some(command) = buff_cmd_recv.recv().await {
                let messages = buffer.execute(command);

                info!("Buffer {} retrieved {} messages", i, messages.len());

                for message in messages {
                    match buffer_acs
                        .handle_protocol_message(
                            message,
                            &*buffer_f,
                            &buffer_prbc_signer,
                            &buffer_mvba_signer,
                            &buffer_coin,
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(ACSError::NotReadyForPRBCMessage(early_message)) => {
                            let index = early_message.header.as_ref().unwrap().prbc_index;
                            buffer.execute(ACSBufferCommand::PRBC {
                                inner: PRBCBufferCommand::Store {
                                    message: early_message,
                                },
                                send_id: index,
                            });
                        }
                        Err(ACSError::NotReadyForMVBAMessage(early_message)) => {
                            buffer.execute(ACSBufferCommand::MVBA {
                                inner: MVBABufferCommand::Store {
                                    message: early_message,
                                },
                            });
                        }

                        Err(e) => error!(
                            "Party {} got error when handling protocol message: {}",
                            i, e
                        ),
                    }
                }
            }
        });

        // Setup messaging manager

        let msg_buff_send = buff_cmd_send.clone();

        let msg_acs = acs.clone();
        let msg_mvba_signer = mvba_signer.clone();
        let msg_prbc_signer = prbc_signer.clone();
        let msg_coin = coin.clone();
        let msg_f = f.clone();

        let _ = tokio::spawn(async move {
            while let Some(message) = recv.recv().await {
                debug!("Received message at {}", i);
                match msg_acs
                    .handle_protocol_message(
                        message,
                        &*msg_f,
                        &msg_prbc_signer,
                        &msg_mvba_signer,
                        &msg_coin,
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(ACSError::NotReadyForPRBCMessage(early_message)) => {
                        let index = early_message.header.as_ref().unwrap().prbc_index;
                        msg_buff_send
                            .send(ACSBufferCommand::PRBC {
                                inner: PRBCBufferCommand::Store {
                                    message: early_message,
                                },
                                send_id: index,
                            })
                            .await
                            .unwrap();
                    }
                    Err(ACSError::NotReadyForMVBAMessage(early_message)) => {
                        msg_buff_send
                            .send(ACSBufferCommand::MVBA {
                                inner: MVBABufferCommand::Store {
                                    message: early_message,
                                },
                            })
                            .await
                            .unwrap();
                    }

                    Err(e) => error!(
                        "Party {} got error when handling protocol message: {}",
                        i, e
                    ),
                }
            }
        });

        // setup main thread

        let main_receiver = r.clone();

        let main_handle = tokio::spawn(async move {
            match acs
                .invoke(main_receiver, f, prbc_signer, &*mvba_signer, &*coin)
                .await
            {
                Ok(value) => return Ok(value),
                Err(e) => {
                    error!("Party {} got error when invoking acs: {}", i, e);
                    return Err(e);
                }
            }
        });

        handles.push(main_handle);
    }

    let results = join_all(handles).await;

    println!();
    println!("-------------------------------------------------------------");
    println!();

    let mut cmp_value = None;

    for (i, join_result) in results.iter().enumerate() {
        match join_result {
            Ok(prbc_result) => match prbc_result {
                Ok(value) => {
                    println!("Value returned party {} = {:?}", i, value);
                    if cmp_value.is_none() {
                        cmp_value.replace(value.clone());
                    }
                    assert_eq!(*value, cmp_value.clone().unwrap());
                }

                Err(e) => {
                    panic!("Party {} got a error when runningm mvba: {}", i, e);
                }
            },
            Err(e) => {
                panic!("Party {} got a error when joining: {}", i, e);
            }
        }
    }
}
