use std::collections::HashMap;

use consensus_core::data::message_buffer::MessageBuffer;
use log::error;

use super::messages::{ProtocolMessage, ProtocolMessageType};

pub struct MVBABuffer {
    pp_recv: HashMap<usize, MessageBuffer<ProtocolMessage>>,
    elect: MessageBuffer<ProtocolMessage>,
    view_change: MessageBuffer<ProtocolMessage>,
}

impl MVBABuffer {
    pub fn new() -> Self {
        Self {
            pp_recv: HashMap::new(),
            elect: MessageBuffer::new(),
            view_change: MessageBuffer::new(),
        }
    }

    pub fn execute(&mut self, command: MVBABufferCommand) -> Vec<ProtocolMessage> {
        match command {
            MVBABufferCommand::PPReceive { view, send_id } => self
                .pp_recv
                .entry(send_id)
                .or_default()
                .epochs
                .entry(view)
                .or_default()
                .drain(..)
                .collect(),
            MVBABufferCommand::ElectCoinShare { view } => self
                .elect
                .epochs
                .entry(view)
                .or_default()
                .drain(..)
                .collect(),

            MVBABufferCommand::ViewChange { view } => self
                .view_change
                .epochs
                .entry(view)
                .or_default()
                .drain(..)
                .collect(),
            MVBABufferCommand::Store { message } => {
                self.store(message);
                vec![]
            }
        }
    }

    pub fn store(&mut self, message: ProtocolMessage) {
        match message.message_type {
            ProtocolMessageType::PBSend => {
                self.pp_recv
                    .entry(message.header.send_id)
                    .or_default()
                    .epochs
                    .entry(message.header.view)
                    .or_default()
                    .push(message);
            }
            ProtocolMessageType::ElectCoinShare => {
                self.elect
                    .epochs
                    .entry(message.header.view)
                    .or_default()
                    .push(message);
            }
            ProtocolMessageType::ViewChange => {
                self.view_change
                    .epochs
                    .entry(message.header.view)
                    .or_default()
                    .push(message);
            }

            ProtocolMessageType::MVBADone
            | ProtocolMessageType::MVBASkipShare
            | ProtocolMessageType::MVBASkip
            | ProtocolMessageType::Unknown
            | ProtocolMessageType::PBShareAck => {}
        }
    }
}

#[derive(Debug)]
pub enum MVBABufferCommand {
    PPReceive { view: usize, send_id: usize },
    ElectCoinShare { view: usize },

    ViewChange { view: usize },

    Store { message: ProtocolMessage },
}
