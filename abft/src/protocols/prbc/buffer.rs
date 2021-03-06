use consensus_core::data::message_buffer::MessageBuffer;

use crate::messaging::{ProtocolMessage, ProtocolMessageType};

use super::messages::PRBCMessageType;

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
        if let ProtocolMessageType::PRBC(prbc_message_type) = &message.message_type {
            match prbc_message_type {
                PRBCMessageType::RBCEcho
                | PRBCMessageType::RBCValue
                | PRBCMessageType::RBCReady => {
                    self.inner.epochs.entry(0).or_default().push(message);
                }
                PRBCMessageType::PRBCDone => {
                    self.inner.epochs.entry(1).or_default().push(message);
                }
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