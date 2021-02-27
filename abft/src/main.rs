mod protocols;

use self::protocols::mvba::{error::MVBAError, messages, Value, MVBA};

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;

use futures::future::join_all;

use consensus_core::{
    crypto::{commoncoin::Coin, sign::Signer},
    data::message_buffer::MessageBuffer,
};
use protocols::mvba::messages::{MVBAReceiver, MVBASender, ProtocolMessage};
use tokio::sync::mpsc::{self, Receiver, Sender};

use log::{debug, error, info};

const N_PARTIES: usize = 4;
const THRESHOLD: usize = 1;

struct ChannelSender {
    senders: HashMap<usize, Sender<ProtocolMessage>>,
}

#[async_trait]
impl MVBASender for ChannelSender {
    async fn send(&self, index: usize, message: ProtocolMessage) {
        if !self.senders.contains_key(&index) {
            return;
        }
        debug!("Sending message to party {}", index);

        let sender = &self.senders[&index];
        if let Err(e) = sender.send(message).await {
            error!("Got error when sending message: {}", e);
        }
    }
}

struct ChannelReceiver {
    recv: Receiver<ProtocolMessage>,
}

#[async_trait]
impl MVBAReceiver for ChannelReceiver {
    async fn receive(&mut self) -> Option<ProtocolMessage> {
        self.recv.recv().await
    }
}
#[tokio::main]
async fn main() {
    env_logger::init();

    let mut signers = Signer::generate_signers(N_PARTIES, THRESHOLD);
    let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD);

    assert_eq!(signers.len(), N_PARTIES);
    assert_eq!(coins.len(), N_PARTIES);

    let mut channels: Vec<_> = (0..N_PARTIES)
        .map(|_| {
            let (tx, rx) = mpsc::channel(20);
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
        let coin = coins.remove(0);

        let f = ChannelSender { senders };
        //let r = ChannelReceiver { recv };

        let mvba = Arc::new(MVBA::init(
            0,
            i,
            N_PARTIES,
            Value { inner: i * 1000 },
            f,
            signer,
            coin,
        ));

        let mvba2 = mvba.clone();

        let main_handle = tokio::spawn(async move {
            debug!("Started main {}", i);
            mvba.invoke().await
        });
        tokio::spawn(async move {
            debug!("Started messaging for {}", i);
            while let Some(message) = recv.recv().await {
                debug!("Received message at {}", i);
                let mvba_c = mvba2.clone();
                tokio::spawn(async move {
                    let mut message = Some(message);
                    loop {
                        if let Err(e) = mvba_c
                            .handle_protocol_message(message.take().unwrap())
                            .await
                        {
                            error!("Got error when handling message at {}: {}", i, e);

                            if let MVBAError::NotReadyForMessage(early_message) = e {
                                message = Some(early_message);
                            }
                        }

                        if let None = message {
                            break;
                        }

                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                });
            }
        });

        handles.push(main_handle);
    }

    let results = join_all(handles).await;

    for (i, result) in results.iter().enumerate() {
        if let Ok(value) = result {
            debug!("Value returned party {} = {:?}", i, value);
        }
    }
}
