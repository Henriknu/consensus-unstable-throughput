use async_stream::try_stream;
use clap::{App, Arg, SubCommand};
use futures_core::Stream;
use futures_util::{stream, StreamExt};
use log::{error, info};
use rpc::abft_client::AbftClient;
use rpc::abft_server::{Abft, AbftServer};
use std::pin::Pin;
use tonic::{Request, Response};

use std::sync::Arc;

pub mod rpc {
    tonic::include_proto!("abft");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use env_logger::{Builder, Target};

    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();

    // client

    let mut client = AbftClient::connect("http://[::1]:10000").await.unwrap();

    let message = rpc::ProtocolMessage::default();

    info!("Sending array of messages: {:?}", message);

    let request = stream::iter(vec![message.clone(); 10]);

    Ok(())
}
