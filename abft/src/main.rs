use abft::{
    messaging::{ProtocolMessage, ProtocolMessageSender, ToProtocolMessage},
    protocols::prbc::{
        buffer::{PRBCBuffer, PRBCBufferCommand},
        PRBCError, PRBC,
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
const THRESHOLD: usize = 33;
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
        message: M,
    ) {
        if !self.senders.contains_key(&recv_id) {
            return;
        }
        debug!("Sending message to party {}", recv_id);

        let sender = &self.senders[&recv_id];
        if let Err(e) = sender
            .send(message.to_protocol_message(id, send_id, recv_id, view))
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
        message: M,
    ) {
        let message = message.to_protocol_message(id, send_id, 0, view);

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

#[tokio::main]
async fn main() {
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

        let signer = signers.remove(0);

        let f = ChannelSender { senders };

        let value;
        let send_id;

        if i == 0 {
            value = Some(Value::new(1000));
            send_id = None;
        } else {
            value = None;
            send_id = Some(0usize);
        }

        let prbc = Arc::new(PRBC::init(0, i, N_PARTIES, send_id, f, signer));

        // Setup buffer manager

        let mut buffer = PRBCBuffer::new();

        let buffer_prbc = prbc.clone();

        let (buff_cmd_send, mut buff_cmd_recv) =
            mpsc::channel::<PRBCBufferCommand>(BUFFER_CAPACITY);

        let _ = tokio::spawn(async move {
            while let Some(command) = buff_cmd_recv.recv().await {
                let messages = buffer.execute(command);

                info!("Buffer {} retrieved {} messages", i, messages.len());

                for message in messages {
                    match buffer_prbc.handle_protocol_message(message).await {
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

        let _ = tokio::spawn(async move {
            while let Some(message) = recv.recv().await {
                debug!("Received message at {}", i);
                match msg_prbc.handle_protocol_message(message).await {
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

        let main_buff_send = buff_cmd_send.clone();

        let main_handle = tokio::spawn(async move {
            match prbc.invoke(value, main_buff_send).await {
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

    for (i, result) in results.iter().enumerate() {
        if let Ok(value) = result {
            println!("Value returned party {} = {:?}", i, value);
        }
    }
}
