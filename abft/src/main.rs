use async_stream::try_stream;
use clap::{App, Arg, SubCommand};
use futures_core::Stream;
use futures_util::{stream, StreamExt};
use log::{error, info};

use std::{collections::HashMap, pin::Pin};
use tonic::{Request, Response};

use abft::{
    buffer::{ABFTBuffer, ABFTBufferCommand, ABFTReceiver},
    proto::{
        abft_client::AbftClient,
        abft_server::{Abft, AbftServer},
    },
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
    ABFTError, Value, ABFT,
};

use async_trait::async_trait;
use bincode::deserialize;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Sender};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arc::new(parse_args());

    init_logger();

    // server

    let server_args = args.clone();

    /*

    let server_handle = tokio::spawn(async move {
        let service = ABFTService {};

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

    server_handle.await?;


    */

    Ok(())
}

fn parse_args() -> ABFTCliArgs {
    let matches = App::new("ABFT")
        .version("1.0")
        .about("Asynchronous BFT consensus")
        .arg(
            Arg::with_name("client")
                .short("C")
                .long("client")
                .value_name("PORT")
                .help("Endpoint to listen at for client")
                .takes_value(true),
        )
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
    let client = String::from(matches.value_of("client").unwrap_or("http://[::1]:10000"));
    println!("Client endpoint: {}", client);

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let server = String::from(matches.value_of("server").unwrap_or("[::1]:10000"));
    println!("Server endpoint: {}", server);

    // more program logic goes here...

    ABFTCliArgs { client, server }
}

fn init_logger() {
    use env_logger::{Builder, Target};

    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();
}

#[derive(Debug, Clone, Default)]
pub struct ABFTCliArgs {
    client: String,
    server: String,
}

/*
pub struct ABFTService {
    protocol: Arc<ABFT<RPCSender, ABFTBufferManager, Value>>,
    buff_send: Sender<ABFTBufferCommand>,
}

#[tonic::async_trait]
impl Abft for ABFTService {
    async fn send(
        &self,
        request: tonic::Request<rpc::ProtocolMessage>,
    ) -> Result<tonic::Response<rpc::ProtocolResponse>, tonic::Status> {
        let message = request.into_inner().into();

        match self.protocol.handle_protocol_message(message).await {
            Ok(_) => {}
            Err(ABFTError::NotReadyForPRBCMessage(early_message)) => {
                let index = early_message.header.prbc_index;
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
                self.protocol.index(),
                e
            ),
        }

        Ok(Response::new(rpc::ProtocolResponse::default()))
    }
}

pub struct RPCSender {
    clients: HashMap<usize, AbftClient<tonic::transport::Channel>>,
}

#[async_trait]
impl ProtocolMessageSender for RPCSender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
        message: M,
    ) {
        if !self.clients.contains_key(&recv_id) {
            return;
        }

        let client = &self.clients[&recv_id];
        if let Err(e) = client
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
            if !self.clients.contains_key(&i) {
                continue;
            }
            let mut inner = message.clone();
            inner.header.recv_id = i;
            let sender = &self.clients[&i];
            if let Err(e) = sender.send(inner).await {
                error!("Got error when sending message: {}", e);
            }
        }
    }
}

struct ABFTBufferManager {
    sender: Sender<ABFTBufferCommand>,
}

#[async_trait]
impl PRBCReceiver for ABFTBufferManager {
    async fn drain_rbc(&self, send_id: usize) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::PRBC {
                    send_id,
                    inner: PRBCBufferCommand::RBC,
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }

    async fn drain_prbc_done(&self, send_id: usize) -> PRBCResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::PRBC {
                    send_id,
                    inner: PRBCBufferCommand::PRBC,
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }
        Ok(())
    }
}

#[async_trait]
impl MVBAReceiver for ABFTBufferManager {
    async fn drain_pp_receive(
        &self,
        view: usize,
        send_id: usize,
    ) -> abft::protocols::mvba::proposal_promotion::PPResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::PPReceive { view, send_id },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_elect(&self, view: usize) -> abft::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::ElectCoinShare { view },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }

    async fn drain_view_change(&self, view: usize) -> abft::protocols::mvba::error::MVBAResult<()> {
        if let Err(e) = self
            .sender
            .send(ABFTBufferCommand::ACS {
                inner: ACSBufferCommand::MVBA {
                    inner: MVBABufferCommand::ViewChange { view },
                },
            })
            .await
        {
            error!("Got error when draining buffer: {}", e);
        }

        Ok(())
    }
}

#[async_trait]
impl ABFTReceiver for ABFTBufferManager {
    async fn drain_decryption_shares(&self) -> abft::ABFTResult<()> {
        self.sender
            .send(ABFTBufferCommand::ABFTDecryptionShare)
            .await?;

        Ok(())
    }
}
 */
