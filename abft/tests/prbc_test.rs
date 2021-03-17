use abft::{
    messaging::{ProtocolMessage, ProtocolMessageSender, ToProtocolMessage},
    protocols::prbc::{
        buffer::{PRBCBuffer, PRBCBufferCommand, PRBCReceiver},
        PRBCError, PRBCResult, PRBC,
    },
};

use abft::Value;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use futures::future::join_all;

use consensus_core::crypto::sign::Signer;

use tokio::sync::mpsc::{self, Sender};

use log::{debug, error, info};

const N_PARTIES: usize = THRESHOLD * 3 + 1;
const THRESHOLD: usize = 10;
const BUFFER_CAPACITY: usize = THRESHOLD * 30;

struct ChannelSender {
    senders: HashMap<usize, Sender<ProtocolMessage>>,
}

#[async_trait]
impl ProtocolMessageSender for ChannelSender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
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
        id: usize,
        send_id: usize,
        n_parties: usize,
        view: usize,
        prbc_index: usize,
        message: M,
    ) {
        let message = message.to_protocol_message(id, send_id, 0, view, prbc_index);

        for i in (0..n_parties) {
            if !self.senders.contains_key(&i) {
                continue;
            }
            let mut inner = message.clone();
            inner.header.recv_id = i;
            let sender = &self.senders[&i];
            if let Err(e) = sender.send(inner).await {
                error!("Got error when sending message: {}", e);
            }
        }
    }
}

struct PRBCBufferManager {
    sender: Sender<PRBCBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for PRBCBufferManager {
    async fn drain_rbc(&self, _send_id: usize) -> PRBCResult<()> {
        self.sender.send(PRBCBufferCommand::RBC).await?;
        Ok(())
    }

    async fn drain_prbc_done(&self, _send_id: usize) -> PRBCResult<()> {
        self.sender.send(PRBCBufferCommand::PRBC).await?;
        Ok(())
    }
}

#[tokio::test]
async fn prbc_correctness() {
    env_logger::init();

    let mut signers = Signer::generate_signers(N_PARTIES, THRESHOLD);

    assert_eq!(signers.len(), N_PARTIES);

    let mut channels: Vec<_> = (0..N_PARTIES)
        .map(|_| {
            let (tx, rx) = mpsc::channel(BUFFER_CAPACITY);
            (tx, Some(rx))
        })
        .collect();

    let mut handles = Vec::with_capacity(N_PARTIES);

    for i in 0..N_PARTIES {
        let mut recv = channels[i].1.take().unwrap();
        let senders: HashMap<usize, Sender<_>> = channels
            .iter()
            .enumerate()
            .filter_map(|(j, channel)| {
                if i != j {
                    Some((j, channel.0.clone()))
                } else {
                    None
                }
            })
            .collect();

        let signer = Arc::new(signers.remove(0));

        let f = Arc::new(ChannelSender { senders });

        let value;

        if i == 0 {
            value = Some(Value::new(1000));
        } else {
            value = None;
        }

        let prbc = Arc::new(PRBC::init(0, i, N_PARTIES, 0));

        // Setup buffer manager

        let mut buffer = PRBCBuffer::new();

        let buffer_prbc = prbc.clone();

        let buffer_signer = signer.clone();

        let buffer_f = f.clone();

        let (buff_cmd_send, mut buff_cmd_recv) =
            mpsc::channel::<PRBCBufferCommand>(BUFFER_CAPACITY);

        let r = Arc::new(PRBCBufferManager {
            sender: buff_cmd_send.clone(),
        });

        let _ = tokio::spawn(async move {
            while let Some(command) = buff_cmd_recv.recv().await {
                let messages = buffer.execute(command);

                info!("Buffer {} retrieved {} messages", i, messages.len());

                for message in messages {
                    match buffer_prbc
                        .handle_protocol_message(message, &*buffer_f, &buffer_signer)
                        .await
                    {
                        Ok(_) => {}
                        Err(PRBCError::NotReadyForMessage(early_message)) => {
                            buffer.execute(PRBCBufferCommand::Store {
                                message: early_message,
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

        let msg_prbc = prbc.clone();

        let msg_signer = signer.clone();

        let msg_f = f.clone();

        let _ = tokio::spawn(async move {
            while let Some(message) = recv.recv().await {
                debug!("Received message at {}", i);
                match msg_prbc
                    .handle_protocol_message(message, &*msg_f, &msg_signer)
                    .await
                {
                    Ok(_) => {}
                    Err(PRBCError::NotReadyForMessage(early_message)) => msg_buff_send
                        .send(PRBCBufferCommand::Store {
                            message: early_message,
                        })
                        .await
                        .unwrap(),

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
            match prbc.invoke(value, &*main_receiver, &*f, &signer).await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    error!("Party {} got error when invoking prbc: {}", i, e);
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