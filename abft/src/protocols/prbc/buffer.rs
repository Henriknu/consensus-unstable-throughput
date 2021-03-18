use consensus_core::data::message_buffer::MessageBuffer;

use async_trait::async_trait;

use crate::proto::{ProtocolMessage, ProtocolMessageType};

use super::{messages::PRBCMessageType, PRBCResult};

#[derive(Debug, Default)]
pub struct PRBCBuffer {
    inner: MessageBuffer<ProtocolMessage>,
}

impl PRBCBuffer {
    pub fn new() -> Self {
        Self {
            inner: MessageBuffer::new(),
        }
    }

    pub fn execute(&mut self, command: PRBCBufferCommand) -> Vec<ProtocolMessage> {
        match command {
            PRBCBufferCommand::RBC => self.inner.epochs.entry(0).or_default().drain(..).collect(),

            PRBCBufferCommand::Store { message } => {
                self.store(message);
                vec![]
            }
            PRBCBufferCommand::PRBC => self.inner.epochs.entry(1).or_default().drain(..).collect(),
        }
    }

    pub fn store(&mut self, message: ProtocolMessage) {
        match message.message_type() {
            ProtocolMessageType::RbcEcho
            | ProtocolMessageType::RbcValue
            | ProtocolMessageType::RbcReady => {
                self.inner.epochs.entry(0).or_default().push(message);
            }
            ProtocolMessageType::PrbcDone => {
                self.inner.epochs.entry(1).or_default().push(message);
            }
            _ => {
                //ignore
            }
        }
    }
}

#[derive(Debug)]
pub enum PRBCBufferCommand {
    RBC,

    PRBC,

    Store { message: ProtocolMessage },
}

#[async_trait]
pub trait PRBCReceiver {
    async fn drain_rbc(&self, send_id: u32) -> PRBCResult<()>;

    async fn drain_prbc_done(&self, send_id: u32) -> PRBCResult<()>;
}
