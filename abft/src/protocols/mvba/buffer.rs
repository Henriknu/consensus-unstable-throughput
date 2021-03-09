use std::collections::HashMap;

use async_trait::async_trait;

use consensus_core::data::message_buffer::MessageBuffer;

use crate::messaging::{ProtocolMessage, ProtocolMessageType};

use super::{error::MVBAResult, messages::MVBAMessageType, proposal_promotion::PPResult};

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
        if let ProtocolMessageType::MVBA(mvba_message_type) = &message.message_type {
            match mvba_message_type {
                MVBAMessageType::PBSend => {
                    self.pp_recv
                        .entry(message.header.send_id)
                        .or_default()
                        .epochs
                        .entry(message.header.view)
                        .or_default()
                        .push(message);
                }
                MVBAMessageType::ElectCoinShare => {
                    self.elect
                        .epochs
                        .entry(message.header.view)
                        .or_default()
                        .push(message);
                }
                MVBAMessageType::ViewChange => {
                    self.view_change
                        .epochs
                        .entry(message.header.view)
                        .or_default()
                        .push(message);
                }

                MVBAMessageType::MVBADone
                | MVBAMessageType::MVBASkipShare
                | MVBAMessageType::MVBASkip
                | MVBAMessageType::PBShareAck => {}
            }
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

#[async_trait]
pub trait MVBAReceiver {
    async fn drain_pp_receive(&self, view: usize, send_id: usize) -> PPResult<()>;

    async fn drain_elect(&self, view: usize) -> MVBAResult<()>;

    async fn drain_view_change(&self, view: usize) -> MVBAResult<()>;
}
