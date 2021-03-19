use bincode::deserialize;
use clap::{App, Arg};
use consensus_core::crypto::KeySet;
use log::{error, info};

use std::collections::HashMap;
use tonic::{Request, Response};

use abft::{
    buffer::{ABFTBuffer, ABFTBufferCommand},
    proto::{
        abft_client::AbftClient,
        abft_server::{Abft, AbftServer},
        ProtocolMessage, ProtocolResponse,
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
    let id = 0;
    let own_index = 0;
    let n_parties = 2;

    let args = Arc::new(parse_args());

    init_logger();

    // client managers

    let client_manager_sender = Arc::new(spawn_client_managers(0, 2));

    // Buffer manager

    let (buff_cmd_send, buff_cmd_recv) =
        mpsc::channel::<ABFTBufferCommand>(n_parties * n_parties * 50 + 100);

    let buffer_handle = Arc::new(ABFTBufferManager {
        sender: buff_cmd_send.clone(),
    });

    // ABFT protocol instance

    let protocol = init_protocol(
        id,
        own_index,
        n_parties as u32,
        client_manager_sender,
        buffer_handle,
    );

    // Buffer

    let buffer_protocol = protocol.clone();

    spawn_buffer_manager(buffer_protocol, buff_cmd_recv, own_index);

    // server

    let server_args = args.clone();

    let server_protocol = protocol.clone();

    let server_buff_send = buff_cmd_send.clone();

    tokio::spawn(async move {
        let service = ABFTService {
            index: own_index,
            protocol: server_protocol,
            buff_send: server_buff_send,
        };

        let server = AbftServer::new(service);

        match tonic::transport::Server::builder()
            .add_service(server)
            .serve(server_args.server.parse().unwrap())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                error!("Got error at abft rpc server: {} ", e);
            }
        }
    });

    match protocol.invoke(Value::new(own_index * 1000)).await {
        Ok(value) => {
            println!(
                "Party {} terminated ABFT with value: {:?}",
                own_index, value
            );
        }
        Err(e) => {
            error!("Party {} got error when invoking abft: {}", own_index, e);
        }
    }
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
                // client

                let mut client = AbftClient::connect(format!("http://[::1]:1000{}", &i))
                    .await
                    .unwrap();

                while let Some(message) = recv.recv().await {
                    match client.protocol_exchange(message).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Got error when sending message: {}", e);
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
            Arg::with_name("server")
                .short("S")
                .long("server")
                .value_name("PORT")
                .help("Endpoint to listen at for server")
                .takes_value(true),
        )
        .get_matches();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let server = String::from(matches.value_of("server").unwrap_or("[::1]:10000"));
    println!("Server endpoint: {}", server);

    // more program logic goes here...

    ABFTCliArgs { server }
}

fn init_protocol(
    id: u32,
    index: u32,
    n_parties: u32,
    send_handle: Arc<ChannelSender>,
    recv_handle: Arc<ABFTBufferManager>,
) -> Arc<ABFT<ChannelSender, ABFTBufferManager, Value>> {
    let bytes = std::fs::read(format!("abft/crypto/key_material{}", index)).unwrap();

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

#[derive(Debug, Clone, Default)]
pub struct ABFTCliArgs {
    server: String,
}

pub struct ABFTService {
    index: u32,
    protocol: Arc<ABFT<ChannelSender, ABFTBufferManager, Value>>,
    buff_send: Sender<ABFTBufferCommand>,
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
}
