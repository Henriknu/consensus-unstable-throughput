use std::collections::HashMap;

use async_trait::async_trait;

use consensus_core::data::message_buffer::MessageBuffer;

use crate::proto::{ProtocolMessage, ProtocolMessageType};

use super::{error::MVBAResult, proposal_promotion::PPResult};

pub struct MVBABuffer {
    pp_recv: HashMap<u32, MessageBuffer<ProtocolMessage>>,
    done: MessageBuffer<ProtocolMessage>,
    skip_share: MessageBuffer<ProtocolMessage>,
    skip: MessageBuffer<ProtocolMessage>,
    elect: MessageBuffer<ProtocolMessage>,
    view_change: MessageBuffer<ProtocolMessage>,
}

impl MVBABuffer {
    pub fn new() -> Self {
        Self {
            pp_recv: HashMap::new(),
            done: MessageBuffer::new(),
            skip_share: MessageBuffer::new(),
            skip: MessageBuffer::new(),
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
                .entry(view as usize)
                .or_default()
                .drain(..)
                .collect(),

            MVBABufferCommand::Skip { view } => {
                let buffers = vec![&mut self.done, &mut self.skip, &mut self.skip_share];

                buffers
                    .into_iter()
                    .map(|buff| buff.epochs.entry(view as usize).or_default().drain(..))
                    .flatten()
                    .collect()
            }

            MVBABufferCommand::ElectCoinShare { view } => self
                .elect
                .epochs
                .entry(view as usize)
                .or_default()
                .drain(..)
                .collect(),

            MVBABufferCommand::ViewChange { view } => self
                .view_change
                .epochs
                .entry(view as usize)
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
        match message.message_type() {
            ProtocolMessageType::PbSend => {
                self.pp_recv
                    .entry(message.send_id)
                    .or_default()
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }
            ProtocolMessageType::ElectCoinShare => {
                self.elect
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }
            ProtocolMessageType::ViewChange => {
                self.view_change
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }

            ProtocolMessageType::MvbaDone => {
                self.done
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }

            ProtocolMessageType::MvbaSkipShare => {
                self.skip_share
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }

            ProtocolMessageType::MvbaSkip => {
                self.skip
                    .epochs
                    .entry(message.view as usize)
                    .or_default()
                    .push(message);
            }

            _ => {
                // ignore
            }
        }
    }
}

#[derive(Debug)]
pub enum MVBABufferCommand {
    PPReceive { view: u32, send_id: u32 },

    Skip { view: u32 },

    ElectCoinShare { view: u32 },

    ViewChange { view: u32 },

    Store { message: ProtocolMessage },
}

#[async_trait]
pub trait MVBAReceiver {
    async fn drain_pp_receive(&self, view: u32, send_id: u32) -> PPResult<()>;

    async fn drain_skip(&self, view: u32) -> PPResult<()>;

    async fn drain_elect(&self, view: u32) -> MVBAResult<()>;

    async fn drain_view_change(&self, view: u32) -> MVBAResult<()>;
}
