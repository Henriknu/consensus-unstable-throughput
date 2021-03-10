use async_trait::async_trait;

use bincode::serialize;
use consensus_core::crypto::commoncoin::EncodedCoinShare;

use serde::{Deserialize, Serialize};

use crate::protocols::{
    mvba::{messages::MVBAMessageType, proposal_promotion::PPProposal},
    prbc::messages::PRBCMessageType,
};

use crate::protocols::mvba::provable_broadcast::{PBSigShare, PBID};
use crate::protocols::mvba::{SkipShare, SkipSig, MVBAID};

#[async_trait]
pub trait ProtocolMessageSender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
        message: M,
    );
    async fn broadcast<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        n_parties: usize,
        view: usize,
        prbc_index: usize,
        message: M,
    );
}

// Wrappers

#[derive(Debug, Clone)]
pub struct ProtocolMessage {
    pub header: ProtocolMessageHeader,
    pub message_type: ProtocolMessageType,
    pub message_data: Vec<u8>,
}

impl Default for ProtocolMessage {
    fn default() -> Self {
        Self {
            header: Default::default(),
            message_data: Default::default(),
            message_type: ProtocolMessageType::Default,
        }
    }
}

impl ProtocolMessage {
    pub fn new(
        protocol_id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
        message_type: ProtocolMessageType,
        message_data: Vec<u8>,
    ) -> Self {
        Self {
            header: ProtocolMessageHeader::new(protocol_id, send_id, recv_id, view, prbc_index),
            message_type,
            message_data,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtocolMessageHeader {
    pub protocol_id: usize,
    pub send_id: usize,
    pub recv_id: usize,
    pub view: usize,
    pub prbc_index: usize,
}

impl ProtocolMessageHeader {
    pub fn new(
        protocol_id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
    ) -> Self {
        Self {
            protocol_id,
            recv_id,
            send_id,
            view,
            prbc_index,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProtocolMessageType {
    MVBA(MVBAMessageType),
    PRBC(PRBCMessageType),
    Default,
}

pub trait ToProtocolMessage
where
    Self: Serialize,
{
    const MESSAGE_TYPE: ProtocolMessageType;

    fn to_protocol_message(
        &self,
        protocol_id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        prbc_index: usize,
    ) -> ProtocolMessage {
        let message_data = serialize(self).expect("Could not serialize inner of Protocol message");

        ProtocolMessage::new(
            protocol_id,
            send_id,
            recv_id,
            view,
            prbc_index,
            Self::MESSAGE_TYPE,
            message_data,
        )
    }
}
