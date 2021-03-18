use std::{collections::HashMap, ops::Deref, sync::Arc};

use futures::future::join_all;

use abft::protocols::{
    acs::SignatureVector,
    mvba::{
        buffer::{MVBABuffer, MVBABufferCommand},
        error::MVBAError,
        MVBA,
    },
};

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};
use tokio::sync::mpsc::{self, Sender};

use log::error;

const N_PARTIES: usize = THRESHOLD * 3 + 1;
const THRESHOLD: usize = 1;
const BUFFER_CAPACITY: usize = THRESHOLD * 30;

use abft::test_helpers::{ChannelSender, MVBABufferManager};

#[tokio::test(flavor = "multi_thread")]
async fn mvba_correctness() {
    env_logger::init();

    let mut signers = Signer::generate_signers(N_PARTIES, N_PARTIES - THRESHOLD - 1);
    let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD + 1);

    assert_eq!(signers.len(), N_PARTIES);
    assert_eq!(coins.len(), N_PARTIES);

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

        let signer = Arc::new(signers.remove(0));
        let coin = Arc::new(coins.remove(0));

        let f: Arc<ChannelSender> = Arc::new(ChannelSender { senders });

        let signature_vector = SignatureVector {
            inner: Default::default(),
        };

        let mvba = Arc::new(MVBA::init(0, i as u32, N_PARTIES as u32, signature_vector));

        // Setup buffer manager

        let mut buffer = MVBABuffer::new();

        let buffer_mvba = mvba.clone();

        let buffer_signer = signer.clone();

        let buffer_coin = coin.clone();

        let buffer_f = f.clone();

        let (buff_cmd_send, mut buff_cmd_recv) =
            mpsc::channel::<MVBABufferCommand>(BUFFER_CAPACITY);

        let r = Arc::new(MVBABufferManager {
            sender: buff_cmd_send.clone(),
        });

        tokio::spawn(async move {
            while let Some(command) = buff_cmd_recv.recv().await {
                let messages = buffer.execute(command);

                for message in messages {
                    match buffer_mvba
                        .handle_protocol_message(
                            message,
                            buffer_f.deref(),
                            &buffer_signer,
                            &buffer_coin,
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(MVBAError::NotReadyForMessage(early_message)) => {
                            buffer.execute(MVBABufferCommand::Store {
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

        let msg_mvba = mvba.clone();

        let msg_signer = signer.clone();

        let msg_coin = coin.clone();

        let msg_f = f.clone();

        tokio::spawn(async move {
            while let Some(message) = recv.recv().await {
                match msg_mvba
                    .handle_protocol_message(message, msg_f.deref(), &msg_signer, &msg_coin)
                    .await
                {
                    Ok(_) => {}
                    Err(MVBAError::NotReadyForMessage(early_message)) => msg_buff_send
                        .send(MVBABufferCommand::Store {
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

        let main_handle =
            tokio::spawn(async move { mvba.invoke(r, f.deref(), &signer, &coin).await });

        handles.push(main_handle);
    }

    let results = join_all(handles).await;

    println!();
    println!("-------------------------------------------------------------");
    println!();

    let mut cmp_value = None;

    for (i, join_result) in results.iter().enumerate() {
        match join_result {
            Ok(mvba_result) => match mvba_result {
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
