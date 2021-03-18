use async_trait::async_trait;

use consensus_core::data::message_buffer::MessageBuffer;

use crate::{
    proto::ProtocolMessage,
    protocols::acs::buffer::{ACSBuffer, ACSBufferCommand},
    ABFTResult,
};

pub struct ABFTBuffer {
    acs: ACSBuffer,
    decryption: MessageBuffer<ProtocolMessage>,
}

impl ABFTBuffer {
    pub fn new() -> Self {
        Self {
            acs: ACSBuffer::new(),
            decryption: Default::default(),
        }
    }

    pub fn execute(&mut self, command: ABFTBufferCommand) -> Vec<ProtocolMessage> {
        match command {
            ABFTBufferCommand::ACS { inner } => self.acs.execute(inner),
            ABFTBufferCommand::ABFTDecryptionShare => self
                .decryption
                .epochs
                .entry(0)
                .or_default()
                .drain(..)
                .collect(),

            ABFTBufferCommand::Store { message } => {
                // only store decryption shares. Sub-protocols go via ACS buffer.
                self.decryption.epochs.entry(0).or_default().push(message);
                vec![]
            }
        }
    }
}

#[derive(Debug)]
pub enum ABFTBufferCommand {
    ACS { inner: ACSBufferCommand },
    ABFTDecryptionShare,
    Store { message: ProtocolMessage },
}

#[async_trait]
pub trait ABFTReceiver {
    async fn drain_decryption_shares(&self) -> ABFTResult<()>;
}
