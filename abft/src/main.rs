use bincode::deserialize;
use clap::{App, Arg};
use consensus_core::crypto::KeySet;
use futures::future::join_all;
use log::{error, info, warn};

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};
use tonic::{
    transport::{Channel, Uri},
    Request, Response,
};

use abft::{
    buffer::{ABFTBuffer, ABFTBufferCommand},
    proto::{
        abft_client::AbftClient,
        abft_server::{Abft, AbftServer},
        FinishedMessage, FinishedResponse, ProtocolMessage, ProtocolResponse,
    },
    protocols::{
        acs::buffer::ACSBufferCommand, mvba::buffer::MVBABufferCommand,
        prbc::buffer::PRBCBufferCommand,
    },
    test_helpers::{ABFTBufferManager, ChannelSender},
    ABFTError, Value, ABFT,
};

use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};

#[tokio::main]
async fn main() {
    let args = Arc::new(parse_args());

    init_logger();

    // client managers

    let client_manager_sender = Arc::new(spawn_client_managers(args.index, args.n_parties));

    // Buffer manager

    let (buff_cmd_send, buff_cmd_recv) =
        mpsc::channel::<ABFTBufferCommand>((args.n_parties * args.n_parties * 50 + 100) as usize);

    let buffer_handle = Arc::new(ABFTBufferManager {
        sender: buff_cmd_send.clone(),
    });

    // Finished manager - handle "finished" messages from peers, know when one can gracefully exit without stalling others.

    let (fin_tx, fin_rx) = mpsc::channel::<u32>(args.n_parties as usize);

    // ABFT protocol instance

    let protocol = init_protocol(
        args.id,
        args.index,
        args.n_parties,
        args.crypto.clone(),
        client_manager_sender,
        buffer_handle,
    );

    // Buffer

    let buffer_protocol = protocol.clone();

    spawn_buffer_manager(buffer_protocol, buff_cmd_recv, args.index);

    // server

    let server_args = args.clone();

    let server_protocol = protocol.clone();

    let server_buff_send = buff_cmd_send.clone();

    let server_finished_send = fin_tx.clone();

    tokio::spawn(async move {
        let service = ABFTService {
            index: server_args.index,
            protocol: server_protocol,
            buff_send: server_buff_send,
            finished_send: server_finished_send,
        };

        let server = AbftServer::new(service);

        let addr: SocketAddr = server_args.server_endpoint.parse().unwrap();

        println!("Server Addr: {}", addr);

        match tonic::transport::Server::builder()
            .add_service(server)
            .serve(addr)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                error!("Got error at abft rpc server: {} ", e);
            }
        }
    });

    info!("Invoking ABFT");

    match protocol.invoke(Value::new(args.index * 1000)).await {
        Ok(value) => {
            println!(
                "Party {} terminated ABFT with value: {:?}",
                args.index, value
            );
        }
        Err(e) => {
            error!("Party {} got error when invoking abft: {}", args.index, e);
        }
    }

    send_finished(&*args).await;

    wait_for_finish_and_exit(fin_rx, &*args).await;
}

async fn send_finished(args: &ABFTCliArgs) {
    let mut handles = Vec::with_capacity((args.n_parties - 1) as usize);
    let id = args.id;
    let index = args.index;

    for i in 0..(args.n_parties as usize) {
        if i != args.index as usize {
            handles.push(tokio::spawn(async move {
                // Attempt to establish a channel, sleeping a couple of seconds until we succesfully are able to connect.
                let channel: Channel;

                loop {
                    let addr = get_client_uri(i);

                    match Channel::builder(addr)
                        .timeout(Duration::from_secs(5))
                        .connect()
                        .await
                    {
                        Ok(c) => {
                            info!("Party {} connected with Party {}", index, i);
                            channel = c;
                            break;
                        }
                        Err(e) => {
                            info!(
                                "Party {} could not connect with Party {}, with error: {}",
                                index, i, e
                            );
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }

                let mut client = AbftClient::new(channel);

                match client
                    .finished(FinishedMessage {
                        protocol_id: id,
                        send_id: index,
                        recv_id: i as u32,
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Party {} got non-ok status code when sending finish to {}: {}",
                            index, i, e
                        );
                    }
                }
            }));
        }
    }

    join_all(handles).await;
}

async fn wait_for_finish_and_exit(mut fin_rx: Receiver<u32>, args: &ABFTCliArgs) {
    let mut finished = HashSet::<u32>::with_capacity(args.n_parties as usize);

    info!("Party {} waiting to gracefully exit", args.index);

    while let Some(index) = fin_rx.recv().await {
        info!("Party {} got finished message from {}", args.index, index);

        if !finished.contains(&index) {
            finished.insert(index);
        }
        if finished.len() == (args.n_parties - 1) as usize {
            break;
        }
    }

    info!("Party {} gracefully exit", args.index);
}

fn spawn_client_managers(own_index: u32, n_parties: u32) -> ChannelSender {
    let mut channels: Vec<_> = (0..n_parties)
        .map(|_| {
            let (tx, rx) =
                mpsc::channel::<ProtocolMessage>((n_parties * n_parties * 50 + 100) as usize);
            (tx, Some(rx))
        })
        .collect();

    for i in 0..(n_parties as usize) {
        if i != own_index as usize {
            let mut recv = channels[i].1.take().unwrap();

            tokio::spawn(async move {
                // Attempt to establish a channel, sleeping a couple of seconds until we succesfully are able to connect.
                let channel: Channel;

                loop {
                    let addr = get_client_uri(i);

                    match Channel::builder(addr)
                        .timeout(Duration::from_secs(5))
                        .connect()
                        .await
                    {
                        Ok(c) => {
                            info!("Party {} connected with Party {}", own_index, i);
                            channel = c;
                            break;
                        }
                        Err(e) => {
                            info!(
                                "Party {} could not connect with Party {}, with error: {}",
                                own_index, i, e
                            );
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }

                let mut client = AbftClient::new(channel);

                while let Some(message) = recv.recv().await {
                    match client.protocol_exchange(message).await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Got non-ok status code when sending message: {}", e);
                        }
                    }
                }
            });
        }
    }

    let senders: HashMap<u32, Sender<_>> = channels
        .into_iter()
        .enumerate()
        .filter_map(|(j, channel)| {
            if (own_index as usize) != j {
                Some((j as u32, channel.0))
            } else {
                None
            }
        })
        .collect();

    ChannelSender { senders }
}

fn spawn_buffer_manager(
    protocol: Arc<ABFT<ChannelSender, ABFTBufferManager, Value>>,
    mut buff_cmd_recv: Receiver<ABFTBufferCommand>,
    own_index: u32,
) {
    let mut buffer = ABFTBuffer::new();

    tokio::spawn(async move {
        while let Some(command) = buff_cmd_recv.recv().await {
            let messages = buffer.execute(command);

            info!("Buffer {} retrieved {} messages", own_index, messages.len());

            for message in messages {
                match protocol.handle_protocol_message(message).await {
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
                        own_index, e
                    ),
                }
            }
        }
    });
}

fn parse_args() -> ABFTCliArgs {
    let matches = App::new("ABFT")
        .version("1.0")
        .about("Asynchronous BFT consensus")
        .arg(
            Arg::with_name("Protocol ID")
                .long("id")
                .value_name("INTEGER")
                .help("Unique id for protocol instance")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Party Index")
                .short("i")
                .value_name("INTEGER")
                .help("Integer index of server in party configuration")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Number of parties")
                .short("n")
                .value_name("INTEGER")
                .help("Number of unique parties in configuration")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Crypto")
                .long("crypto")
                .value_name("PATH")
                .help("Custom path to crypto material")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("connection")
                .short("C")
                .value_name("PATH")
                .help("Endpoint to listen at for server")
                .takes_value(true),
        )
        .get_matches();

    let id = matches
        .value_of("Protocol ID")
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let index = matches
        .value_of("Party Index")
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let n_parties = matches
        .value_of("Number of parties")
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let crypto = String::from(matches.value_of("Crypto").unwrap_or("abft/crypto"));

    let server_endpoint = String::from(
        matches
            .value_of("connection")
            .unwrap_or(format!("[::1]:5000{}", index).as_str()),
    );

    // more program logic goes here...
    //

    ABFTCliArgs {
        id,
        index,
        n_parties,
        crypto,
        server_endpoint,
    }
}

fn init_protocol(
    id: u32,
    index: u32,
    n_parties: u32,
    crypto: String,
    send_handle: Arc<ChannelSender>,
    recv_handle: Arc<ABFTBufferManager>,
) -> Arc<ABFT<ChannelSender, ABFTBufferManager, Value>> {
    let bytes = std::fs::read(format!("{}/key_material{}", crypto, index)).unwrap();

    let keyset: KeySet = deserialize(&bytes).unwrap();

    let abft = Arc::new(ABFT::init(
        id,
        index,
        n_parties,
        send_handle,
        recv_handle,
        Arc::new(keyset.signer_prbc),
        keyset.signer_mvba,
        keyset.coin.into(),
        keyset.encrypter.into(),
    ));

    abft
}

fn init_logger() {
    use env_logger::{Builder, Target};

    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();
}

/// Check if env is set via K8s. If not, return localhost default.
fn get_client_uri(index: usize) -> Uri {
    if let Ok(host) = std::env::var(format!("ABFT_{}_SERVICE_SERVICE_HOST", index)) {
        if let Ok(port) = std::env::var(format!("ABFT_{}_SERVICE_SERVICE_PORT", index)) {
            return format!("http://{}:{}", host, port).parse().unwrap();
        }
    }

    format!("http://[::1]:5000{}", index).parse().unwrap()
}

#[derive(Debug, Clone, Default)]
pub struct ABFTCliArgs {
    id: u32,
    index: u32,
    n_parties: u32,
    crypto: String,
    server_endpoint: String,
}

pub struct ABFTService {
    index: u32,
    protocol: Arc<ABFT<ChannelSender, ABFTBufferManager, Value>>,
    buff_send: Sender<ABFTBufferCommand>,
    finished_send: Sender<u32>,
}

#[tonic::async_trait]
impl Abft for ABFTService {
    async fn protocol_exchange(
        &self,
        request: Request<abft::proto::ProtocolMessage>,
    ) -> Result<Response<abft::proto::ProtocolResponse>, tonic::Status> {
        let message = request.into_inner();

        match self.protocol.handle_protocol_message(message).await {
            Ok(_) => {}
            Err(ABFTError::NotReadyForPRBCMessage(early_message)) => {
                let index = early_message.prbc_index;
                self.buff_send
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
                self.buff_send
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
                self.buff_send
                    .send(ABFTBufferCommand::Store {
                        message: early_message,
                    })
                    .await
                    .unwrap();
            }

            Err(e) => error!(
                "Party {} got error when handling protocol message: {}",
                self.index, e
            ),
        }

        Ok(Response::new(ProtocolResponse {}))
    }
    async fn finished(
        &self,
        request: Request<abft::proto::FinishedMessage>,
    ) -> Result<Response<abft::proto::FinishedResponse>, tonic::Status> {
        let message = request.into_inner();

        match self.finished_send.send(message.send_id).await {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Party {} got error when handling protocol message: {}",
                    message.recv_id, e
                )
            }
        }

        Ok(Response::new(FinishedResponse {}))
    }
}
