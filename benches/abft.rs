use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("abft", move |b| {
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();
        b.to_async(rt).iter(|| abft_correctness());
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = criterion_benchmark
}

criterion_main!(benches);
use abft::{
    buffer::{ABFTBuffer, ABFTBufferCommand},
    protocols::{
        acs::buffer::ACSBufferCommand, mvba::buffer::MVBABufferCommand,
        prbc::buffer::PRBCBufferCommand,
    },
    ABFTError, ABFT,
};

use std::{collections::HashMap, sync::Arc};

use futures::future::join_all;

use consensus_core::{
    crypto::{commoncoin::Coin, encrypt::Encrypter, sign::Signer},
    data::transaction::TransactionSet,
};

use tokio::sync::mpsc::{self, Sender};

use log::{debug, error, info};

use abft::test_helpers::{ABFTBufferManager, ChannelSender};

const N_PARTIES: usize = THRESHOLD * 4;
const THRESHOLD: usize = 2;
const BATCH_SIZE: u32 = 10_000;
const BUFFER_CAPACITY: usize = N_PARTIES * N_PARTIES * 50 + 1000;
const SEED_TRANSACTION_SET: u32 = 899923234;

async fn abft_correctness() {
    let mut mvba_signers = Signer::generate_signers(N_PARTIES, N_PARTIES - THRESHOLD - 1);
    let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD + 1);

    assert_eq!(mvba_signers.len(), N_PARTIES);
    assert_eq!(coins.len(), N_PARTIES);

    let mut prbc_signers = Signer::generate_signers(N_PARTIES, THRESHOLD);

    assert_eq!(prbc_signers.len(), N_PARTIES);

    let mut encrypters = Encrypter::generate_keys(N_PARTIES, THRESHOLD);

    assert_eq!(encrypters.len(), N_PARTIES);

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

        let signer_mvba = mvba_signers.remove(0);
        let signer_prbc = Arc::new(prbc_signers.remove(0));
        let coin = coins.remove(0);
        let encrypter = encrypters.remove(0);

        let f = Arc::new(ChannelSender { senders });

        let (buff_cmd_send, mut buff_cmd_recv) =
            mpsc::channel::<ABFTBufferCommand>(BUFFER_CAPACITY);

        let r = Arc::new(ABFTBufferManager {
            sender: buff_cmd_send.clone(),
        });

        let abft = Arc::new(ABFT::init(
            0,
            i as u32,
            THRESHOLD as u32,
            N_PARTIES as u32,
            BATCH_SIZE,
            signer_prbc,
            signer_mvba,
            coin,
            encrypter,
        ));

        // Setup buffer manager

        let mut buffer = ABFTBuffer::new();
        let buffer_abft = abft.clone();
        let buffer_f = f.clone();

        let _ = tokio::spawn(async move {
            while let Some(command) = buff_cmd_recv.recv().await {
                let messages = buffer.execute(command);

                info!("Buffer {} retrieved {} messages", i, messages.len());

                for message in messages {
                    match buffer_abft
                        .handle_protocol_message(message, &*buffer_f)
                        .await
                    {
                        Ok(_) => {}
                        Err(ABFTError::NotReadyForPRBCMessage(early_message)) => {
                            let index = early_message.prbc_index;
                            buffer.execute(ABFTBufferCommand::ACS {
                                inner: ACSBufferCommand::PRBC {
                                    inner: PRBCBufferCommand::Store {
                                        message: early_message,
                                    },
                                    send_id: index,
                                },
                            });
                        }
                        Err(ABFTError::NotReadyForMVBAMessage(early_message)) => {
                            buffer.execute(ABFTBufferCommand::ACS {
                                inner: ACSBufferCommand::MVBA {
                                    inner: MVBABufferCommand::Store {
                                        message: early_message,
                                    },
                                },
                            });
                        }

                        Err(ABFTError::NotReadyForABFTDecryptionShareMessage(early_message)) => {
                            buffer.execute(ABFTBufferCommand::Store {
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

        let msg_abft = abft.clone();
        let msg_f = f.clone();

        let _ = tokio::spawn(async move {
            while let Some(message) = recv.recv().await {
                debug!("Received message at {}", i);
                match msg_abft.handle_protocol_message(message, &*msg_f).await {
                    Ok(_) => {}
                    Err(ABFTError::NotReadyForPRBCMessage(early_message)) => {
                        let index = early_message.prbc_index;
                        msg_buff_send
                            .send(ABFTBufferCommand::ACS {
                                inner: ACSBufferCommand::PRBC {
                                    inner: PRBCBufferCommand::Store {
                                        message: early_message,
                                    },
                                    send_id: index,
                                },
                            })
                            .await
                            .unwrap();
                    }
                    Err(ABFTError::NotReadyForMVBAMessage(early_message)) => {
                        msg_buff_send
                            .send(ABFTBufferCommand::ACS {
                                inner: ACSBufferCommand::MVBA {
                                    inner: MVBABufferCommand::Store {
                                        message: early_message,
                                    },
                                },
                            })
                            .await
                            .unwrap();
                    }

                    Err(ABFTError::NotReadyForABFTDecryptionShareMessage(early_message)) => {
                        msg_buff_send
                            .send(ABFTBufferCommand::Store {
                                message: early_message,
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

        let transactions = TransactionSet::generate_transactions(SEED_TRANSACTION_SET, BATCH_SIZE)
            .random_selection(N_PARTIES);

        info!(
            "Proposing transaction set with {} transactions.",
            transactions.len()
        );

        info!("Invoking ABFT");

        let main_handle = tokio::spawn(async move {
            match abft.invoke(f, r, transactions).await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    error!("Party {} got error when invoking abft: {}", i, e);
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
