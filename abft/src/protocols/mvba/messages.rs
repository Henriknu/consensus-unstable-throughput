use bincode::serialize;
use consensus_core::crypto::commoncoin::EncodedCoinShare;
use serde::{Deserialize, Serialize};

use super::{
    proposal_promotion::PPProposal,
    provable_broadcast::{PBSigShare, PBID},
    Value,
};

// Wrappers

pub struct ProtocolMessage {
    pub header: ProtocolMessageHeader,
    pub message_type: ProtocolMessageType,
    pub message_data: Vec<u8>,
}

impl ProtocolMessage {
    pub fn new(
        protocol_id: usize,
        send_id: usize,
        recv_id: usize,
        message_type: ProtocolMessageType,
        message_data: Vec<u8>,
    ) -> Self {
        Self {
            header: ProtocolMessageHeader::new(protocol_id, send_id, recv_id),
            message_type,
            message_data,
        }
    }
}

pub struct ProtocolMessageHeader {
    pub protocol_id: usize,
    pub send_id: usize,
    pub recv_id: usize,
}

impl ProtocolMessageHeader {
    pub fn new(protocol_id: usize, send_id: usize, recv_id: usize) -> Self {
        Self {
            protocol_id,
            recv_id,
            send_id,
        }
    }
}

pub enum ProtocolMessageType {
    //MVBA
    MVBADone,
    MVBASkipShare,
    MVBASkip,

    // Provable Broadcast
    PBSend,
    PBShareAck,

    // Elect
    ElectCoinShare,

    // ViewChange
    ViewChange,
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
    ) -> ProtocolMessage {
        let message_data = serialize(self).expect("Could not serialize inner of Protocol message");

        ProtocolMessage::new(
            protocol_id,
            send_id,
            recv_id,
            Self::MESSAGE_TYPE,
            message_data,
        )
    }
}

// Concrete Messages
#[derive(Serialize, Deserialize)]
pub struct PBSendMessage {
    pub id: PBID,
    pub proposal: PPProposal,
}

impl PBSendMessage {
    pub fn new(id: PBID, proposal: PPProposal) -> Self {
        Self { id, proposal }
    }
}

impl ToProtocolMessage for PBSendMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PBSend;
}

#[derive(Serialize, Deserialize)]
pub struct PBShareAckMessage {
    pub id: PBID,
    pub share: PBSigShare,
}

impl PBShareAckMessage {
    pub fn new(id: PBID, share: PBSigShare) -> Self {
        Self { id, share }
    }
}

impl ToProtocolMessage for PBShareAckMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PBShareAck;
}

#[derive(Serialize, Deserialize)]
pub struct ElectCoinShareMessage {
    pub share: EncodedCoinShare,
}

impl ElectCoinShareMessage {
    pub fn new(share: EncodedCoinShare) -> Self {
        Self { share }
    }
}

impl ToProtocolMessage for ElectCoinShareMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::ElectCoinShare;
}

#[derive(Serialize, Deserialize)]
pub struct ViewChangeMessage {
    pub id: usize,
    pub index: usize,
    pub view: usize,
    pub leader_key: Option<PPProposal>,
    pub leader_lock: Option<PPProposal>,
    pub leader_commit: Option<PPProposal>,
}

impl ViewChangeMessage {
    pub fn new(
        id: usize,
        index: usize,
        view: usize,
        leader_key: Option<PPProposal>,
        leader_lock: Option<PPProposal>,
        leader_commit: Option<PPProposal>,
    ) -> Self {
        Self {
            id,
            index,
            view,
            leader_key,
            leader_lock,
            leader_commit,
        }
    }
}

impl ToProtocolMessage for ViewChangeMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::ViewChange;
}
