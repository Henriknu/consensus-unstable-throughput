use bincode::deserialize;
use clap::{App, Arg};
use consensus_core::{
    crypto::hash::hash_sha256, crypto::KeySet, data::transaction::TransactionSet,
};
use futures::future::join_all;
use log::{error, info, warn};
use rand::{prelude::SliceRandom, SeedableRng};
use std::process::Command;

use std::{
    collections::{HashMap, HashSet},
    io::BufRead,
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
        FinishedMessage, FinishedResponse, ProtocolMessage, ProtocolResponse, SetupAck,
        SetupAckResponse,
    },
    protocols::{
        acs::buffer::ACSBufferCommand, mvba::buffer::MVBABufferCommand,
        prbc::buffer::PRBCBufferCommand,
    },
    test_helpers::{ABFTBufferManager, ChannelSender},
    ABFTError, ABFT,
};

use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};

const RECV_TIMEOUT_SECS: u64 = 20;
const CLIENT_RETRY_TIMEOUT_SECS: u64 = 1;
const SERVER_PORT_NUMBER: u64 = 50000;
const SEED_TRANSACTION_SET: u32 = 899923234;

#[tokio::main]
async fn main() {
    // Configure logging

    init_logger();

    warn!("Booting up ...");

    let args = Arc::new(parse_args());

    // If enabled, calculate which nodes are affected by unstable network and invoke NetEm.

    let enabled_unstable = (args.m_parties != 0) && enable_unstable_network(&args);

    for i in 1..args.iterations {
        warn!("Running iteration {}", i);
        // client managers

        let (client_manager_sender, client_ready_rx) = spawn_client_managers(&args);

        // Buffer manager

        let (buff_cmd_send, buff_cmd_recv) = mpsc::channel::<ABFTBufferCommand>(
            (args.n_parties * args.n_parties * 50 + 100) as usize,
        );

        let buffer_handle = Arc::new(ABFTBufferManager {
            sender: buff_cmd_send.clone(),
        });

        // Setup manager - handle "setup" messages from peers, ensure that all clients are setup when invoking ABFT, for precise timing.

        let (setup_tx, setup_rx) = mpsc::channel::<u32>(args.n_parties as usize);

        // Finished manager - handle "finished" messages from peers, know when one can gracefully exit without stalling others.

        let (fin_tx, fin_rx) = mpsc::channel::<u32>(args.n_parties as usize);

        // ABFT protocol instance

        let protocol = init_protocol(
            args.id,
            args.index,
            args.f_tolerance,
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

        let server_setup_send = setup_tx.clone();

        let server_finished_send = fin_tx.clone();

        tokio::spawn(async move {
            let service = ABFTService {
                index: server_args.index,
                protocol: server_protocol,
                buff_send: server_buff_send,
                setup_send: server_setup_send,
                finished_send: server_finished_send,
            };

            let server = AbftServer::new(service);

            let addr: SocketAddr = server_args.server_endpoint;

            warn!("Server Addr: {}", addr);

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

        // wait for setup to complete

        wait_for_clients(client_ready_rx, &*args).await;

        send_setup_ack(&*args).await;

        wait_for_setup_ack(setup_rx, &*args).await;

        // Invoke protocol

        let value = TransactionSet::generate_transactions(SEED_TRANSACTION_SET, args.batch_size)
            .random_selection(args.n_parties as usize);

        warn!(
            "Proposing transaction set with {} transactions.",
            value.len()
        );

        warn!("Invoking ABFT");

        match protocol.invoke(value).await {
            Ok(value) => {
                warn!(
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

    if enabled_unstable {
        disable_unstable_network();
    }
}

async fn wait_for_clients(mut client_ready_rx: Receiver<u32>, args: &ABFTCliArgs) {
    let mut connected = HashSet::<u32>::with_capacity(args.n_parties as usize);

    info!(
        "Party {} waiting for clients to succesfully connect",
        args.index
    );

    while let Some(index) = client_ready_rx.recv().await {
        info!("Party {}'s client {} connected", args.index, index);

        if !connected.contains(&index) {
            connected.insert(index);
        }
        if connected.len() == (args.n_parties - 1) as usize {
            break;
        }
    }

    warn!("Party {} all connected", args.index);
}

async fn send_setup_ack(args: &ABFTCliArgs) {
    let mut handles = Vec::with_capacity((args.n_parties - 1) as usize);
    let id = args.id;
    let index = args.index;

    for i in 0..(args.n_parties as usize) {
        let uri = args.hosts[&(i as u32)].to_string().parse::<Uri>().unwrap();
        if i != args.index as usize {
            handles.push(tokio::spawn(async move {
                // Attempt to establish a channel, sleeping a couple of seconds until we succesfully are able to connect.
                let channel: Channel;

                loop {
                    match Channel::builder(uri.clone())
                        .timeout(Duration::from_secs(RECV_TIMEOUT_SECS))
                        .connect()
                        .await
                    {
                        Ok(c) => {
                            info!("Party {} connected with Party {}", index, i);
                            channel = c;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Party {} could not setup with Party {}, with error: {}",
                                index, i, e
                            );
                            tokio::time::sleep(Duration::from_secs(CLIENT_RETRY_TIMEOUT_SECS))
                                .await;
                        }
                    }
                }

                let mut client = AbftClient::new(channel);

                loop {
                    match client
                        .setup_ack(SetupAck {
                            protocol_id: id,
                            send_id: index,
                            recv_id: i as u32,
                        })
                        .await
                    {
                        Ok(_) => {
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Party {} got non-ok status code when sending setup_ack to {}: {}",
                                index, i, e
                            );
                        }
                    }
                }
            }));
        }
    }

    join_all(handles).await;
}

async fn wait_for_setup_ack(mut setup_rx: Receiver<u32>, args: &ABFTCliArgs) {
    let mut setup_acked = HashSet::<u32>::with_capacity(args.n_parties as usize);

    info!(
        "Party {} waiting for all parties to finish setup",
        args.index
    );

    while let Some(index) = setup_rx.recv().await {
        info!("Party {} got setup ack from {}", args.index, index);

        if !setup_acked.contains(&index) {
            setup_acked.insert(index);
        }
        if setup_acked.len() == (args.n_parties - 1) as usize {
            break;
        }
    }

    info!("Party {} finished setup", args.index);
}

async fn send_finished(args: &ABFTCliArgs) {
    let mut handles = Vec::with_capacity((args.n_parties - 1) as usize);
    let id = args.id;
    let index = args.index;

    for i in 0..(args.n_parties as usize) {
        let uri = args.hosts[&(i as u32)].clone();

        if i != args.index as usize {
            handles.push(tokio::spawn(async move {
                // Attempt to establish a channel, sleeping a couple of seconds until we succesfully are able to connect.
                let channel: Channel;

                loop {
                    match Channel::builder(uri.clone())
                        .timeout(Duration::from_secs(RECV_TIMEOUT_SECS))
                        .connect()
                        .await
                    {
                        Ok(c) => {
                            info!("Party {} connected with Party {}", index, i);
                            channel = c;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Party {} could not finish with Party {}, with error: {}",
                                index, i, e
                            );
                            tokio::time::sleep(Duration::from_secs(CLIENT_RETRY_TIMEOUT_SECS))
                                .await;
                        }
                    }
                }

                let mut client = AbftClient::new(channel);

                loop {
                    match client
                        .finished(FinishedMessage {
                            protocol_id: id,
                            send_id: index,
                            recv_id: i as u32,
                        })
                        .await
                    {
                        Ok(_) => {
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Party {} got non-ok status code when sending finish to {}: {}",
                                index, i, e
                            );
                        }
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

    info!(
        "Party {} gracefully exit, having received num finished messages: {}",
        args.index,
        finished.len()
    );

    info!("\n");
}

fn spawn_client_managers(args: &ABFTCliArgs) -> (Arc<ChannelSender>, Receiver<u32>) {
    let (client_ready_send, client_ready_receive) = mpsc::channel(args.n_parties as usize);

    let mut channels: Vec<_> = (0..args.n_parties)
        .map(|_| {
            let (tx, rx) = mpsc::channel::<ProtocolMessage>(
                (args.n_parties * args.n_parties * 50 + 100) as usize,
            );
            (tx, Some(rx))
        })
        .collect();

    let own_index = args.index;

    for i in 0..(args.n_parties as usize) {
        let uri = args.hosts[&(i as u32)].clone();

        if i != own_index as usize {
            let mut recv = channels[i].1.take().unwrap();

            let client_send = client_ready_send.clone();

            tokio::spawn(async move {
                // Attempt to establish a channel, sleeping a couple of seconds until we succesfully are able to connect.
                let channel: Channel;

                loop {
                    match Channel::builder(uri.clone())
                        .timeout(Duration::from_secs(RECV_TIMEOUT_SECS))
                        .connect()
                        .await
                    {
                        Ok(c) => {
                            info!("Party {} connected with Party {}", own_index, i);
                            channel = c;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Party {} could not connect with Party {}, with error: {}",
                                own_index, i, e
                            );
                            tokio::time::sleep(Duration::from_secs(CLIENT_RETRY_TIMEOUT_SECS))
                                .await;
                        }
                    }
                }

                let mut client = AbftClient::new(channel);

                // Signify that the client is connected to setup manager

                match client_send.send(i as u32).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Got error when sending to setup_manager: {}", e);
                    }
                }

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

    (Arc::new(ChannelSender { senders }), client_ready_receive)
}

fn spawn_buffer_manager(
    protocol: Arc<ABFT<ChannelSender, ABFTBufferManager, TransactionSet>>,
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

fn enable_unstable_network(args: &ABFTCliArgs) -> bool {
    let ABFTCliArgs {
        id,
        index,
        n_parties,
        m_parties,
        delay,
        packet_loss,
        ..
    } = args;

    // calculate which nodes are to be affected by unstable network

    let seed = hash_sha256(format!("{}-{}-{}", id, n_parties, m_parties).as_bytes());

    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let mut indexes: Vec<u32> = (0..*n_parties).collect();

    indexes.shuffle(&mut rng);

    let indexes: Vec<u32> = indexes.into_iter().take(*m_parties as usize).collect();

    info!(
        "Chose the following parties for unstable network {:?}",
        indexes
    );

    if indexes.contains(index) {
        info!("Invoking Netem with ");
        let output = Command::new("sudo")
            .args(&["tc", "qdisc", "add", "dev", "eth0", "root"])
            .args(&[
                "netem",
                "delay",
                format!("{}ms", delay).as_str(),
                "loss",
                format!("{}%", packet_loss).as_str(),
            ])
            .output()
            .expect("Failed to execute command");

        if !output.status.success() {
            error!(
                "Failed to invoke Netem with parameters: Delay : {}ms, Packet loss: {}%",
                delay, packet_loss
            );
            panic!("Could not invoke Netem, when passing in non-zero value for m_parties");
        }

        return true;
    }
    false
}

fn disable_unstable_network() {
    info!("Deleting rules invoked with Netem ");
    let output = Command::new("sudo")
        .args(&["tc", "qdisc", "del", "dev", "eth0", "root"])
        .output()
        .expect("Failed to execute command");

    if !output.status.success() {
        error!(
            "Failed to delete rules invoked for Netem, with status: {}",
            output.status
        );
        panic!("Could not invoke Netem, when passing in non-zero value for m_parties");
    }
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
            Arg::with_name("Fault tolerance")
                .short("f")
                .value_name("INTEGER")
                .help("Number of possibly faulty nodes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Batch size")
                .short("b")
                .value_name("INTEGER")
                .help("Total number of transaction provided as input to protocol")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Iterations")
                .long("iterations")
                .value_name("INTEGER")
                .help("Total number of rounds the protocol should run")
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
            Arg::with_name("Endpoint")
                .short("e")
                .value_name("SocketAddr")
                .help("Endpoint for server to listen to")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Hosts")
                .short("h")
                .value_name("PATH")
                .help("Custom path to list of host ips")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Number of parties affected by unstable network")
                .short("m")
                .value_name("INTEGER")
                .help("Number of unique parties in the configuration which are affected by an unstable network (delay and packet loss). Less than n.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Packet delay for unstable network")
                .short("d")
                .value_name("INTEGER")
                .help("Additional packet delay put on outgoing packets for nodes affected by unstable network. In ms.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("Packet loss rate for unstable network")
                .short("l")
                .value_name("INTEGER")
                .help("Additional packet loss rate put on outgoing packets for nodes affected by unstable network. In percentage, between 0 to 100.")
                .takes_value(true),
        )
        .get_matches();

    let id = matches
        .value_of("Protocol ID")
        .unwrap()
        .parse::<u32>()
        .unwrap_or(0);

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

    let f_tolerance = matches
        .value_of("Fault tolerance")
        .unwrap()
        .parse::<u32>()
        .unwrap_or(n_parties / 4);

    let batch_size = matches
        .value_of("Batch size")
        .unwrap()
        .parse::<u64>()
        .unwrap_or(n_parties as u64);

    let iterations = matches
        .value_of("Iterations")
        .unwrap_or("1")
        .parse::<usize>()
        .unwrap();

    let m_parties = matches
        .value_of("Number of parties affected by unstable network")
        .unwrap_or("0")
        .parse::<u32>()
        .unwrap();

    let delay = matches
        .value_of("Packet delay for unstable network")
        .unwrap_or("0")
        .parse::<u32>()
        .unwrap();

    let packet_loss = matches
        .value_of("Packet loss rate for unstable network")
        .unwrap_or("0")
        .parse::<u32>()
        .unwrap();

    let crypto = String::from(matches.value_of("Crypto").unwrap_or("abft/crypto"));

    let server_endpoint = String::from(matches.value_of("Endpoint").unwrap_or("[::1]"));

    info!("Invoked with endpoint: {}", server_endpoint);

    let server_endpoint = format!("{}:{}", server_endpoint, SERVER_PORT_NUMBER)
        .parse::<SocketAddr>()
        .unwrap();

    info!("Evaluated endpoint to: {}", server_endpoint);

    // Read hosts

    let hosts_path = String::from(matches.value_of("Hosts").unwrap_or("hosts"));

    let mut hosts = HashMap::with_capacity(n_parties as usize);

    let file = std::fs::File::open(hosts_path).unwrap();

    let lines = std::io::BufReader::new(file).lines();

    for (i, line) in lines.enumerate() {
        let line = line.unwrap();
        hosts.insert(
            i as u32,
            format!("http://{}:{}", line, SERVER_PORT_NUMBER)
                .parse()
                .unwrap(),
        );
    }

    ABFTCliArgs {
        id,
        index,
        f_tolerance,
        n_parties,
        batch_size,
        iterations,
        crypto,
        server_endpoint,
        hosts,
        m_parties,
        delay,
        packet_loss,
    }
}

fn init_protocol(
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    crypto: String,
    send_handle: Arc<ChannelSender>,
    recv_handle: Arc<ABFTBufferManager>,
) -> Arc<ABFT<ChannelSender, ABFTBufferManager, TransactionSet>> {
    let bytes = std::fs::read(format!("{}/key_material{}", crypto, index)).unwrap();

    let keyset: KeySet = deserialize(&bytes).unwrap();

    let abft = Arc::new(ABFT::init(
        id,
        index,
        f_tolerance,
        n_parties,
        send_handle,
        recv_handle,
        Arc::new(keyset.signer_prbc.into()),
        keyset.signer_mvba.into(),
        keyset.coin.into(),
        keyset.encrypter.into(),
    ));

    abft
}

fn init_logger() {
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();
}

#[derive(Debug, Clone)]
pub struct ABFTCliArgs {
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    batch_size: u64,
    iterations: usize,
    crypto: String,
    server_endpoint: SocketAddr,
    hosts: HashMap<u32, Uri>,

    // Network unstability
    m_parties: u32,
    delay: u32,
    packet_loss: u32,
}

pub struct ABFTService {
    index: u32,
    protocol: Arc<ABFT<ChannelSender, ABFTBufferManager, TransactionSet>>,
    buff_send: Sender<ABFTBufferCommand>,
    setup_send: Sender<u32>,
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

    async fn setup_ack(
        &self,
        request: Request<abft::proto::SetupAck>,
    ) -> Result<Response<abft::proto::SetupAckResponse>, tonic::Status> {
        let message = request.into_inner();

        match self.setup_send.send(message.send_id).await {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Party {} got error when handling protocol message: {}",
                    message.recv_id, e
                )
            }
        }

        Ok(Response::new(SetupAckResponse {}))
    }
}
