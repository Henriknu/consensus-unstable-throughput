use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("acs", move |b| {
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();
        b.to_async(rt).iter(|| acs_correctness());
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = criterion_benchmark
}

criterion_main!(benches);

use abft::{
    protocols::{
        acs::{
            buffer::{ACSBuffer, ACSBufferCommand},
            ACSError, ACS,
        },
        mvba::buffer::MVBABufferCommand,
        prbc::buffer::PRBCBufferCommand,
    },
    EncodedEncryptedValue,
};

use std::{collections::HashMap, sync::Arc};

use futures::future::join_all;

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};

use tokio::sync::mpsc::{self, Sender};

use log::{debug, error, info};

const N_PARTIES: usize = THRESHOLD * 3 + 1;
const THRESHOLD: usize = 1;
const BUFFER_CAPACITY: usize = N_PARTIES * N_PARTIES * 50 + 100;

use abft::test_helpers::{ACSBufferManager, ChannelSender};

async fn acs_correctness() {
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
        let value = EncodedEncryptedValue::default();

        let acs = Arc::new(ACS::init(
            0,
            i as u32,
            THRESHOLD as u32,
            N_PARTIES as u32,
            100,
        ));

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
                            let index = early_message.prbc_index;
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
                        let index = early_message.prbc_index;
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
                .invoke(value, main_receiver, f, prbc_signer, &*mvba_signer, &*coin)
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

    let mut cmp_value = None;

    for (i, join_result) in results.iter().enumerate() {
        match join_result {
            Ok(prbc_result) => match prbc_result {
                Ok(value) => {
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
