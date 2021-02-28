use async_trait::async_trait;

use bincode::serialize;
use consensus_core::crypto::commoncoin::EncodedCoinShare;

use serde::{Deserialize, Serialize};

use super::{
    proposal_promotion::PPProposal,
    provable_broadcast::{PBSigShare, PBID},
    SkipShare, SkipSig, MVBAID,
};

// Wrappers

#[async_trait]
pub trait MVBASender {
    async fn send<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        message: M,
    );
    async fn broadcast<M: ToProtocolMessage + Send + Sync>(
        &self,
        id: usize,
        send_id: usize,
        n_parties: usize,
        view: usize,
        message: M,
    );
}

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
            message_type: ProtocolMessageType::Unknown,
        }
    }
}

impl ProtocolMessage {
    pub fn new(
        protocol_id: usize,
        send_id: usize,
        recv_id: usize,
        view: usize,
        message_type: ProtocolMessageType,
        message_data: Vec<u8>,
    ) -> Self {
        Self {
            header: ProtocolMessageHeader::new(protocol_id, send_id, recv_id, view),
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
}

impl ProtocolMessageHeader {
    pub fn new(protocol_id: usize, send_id: usize, recv_id: usize, view: usize) -> Self {
        Self {
            protocol_id,
            recv_id,
            send_id,
            view,
        }
    }
}

#[derive(Debug, Clone)]
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

    // Default
    Unknown,
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
    ) -> ProtocolMessage {
        let message_data = serialize(self).expect("Could not serialize inner of Protocol message");

        ProtocolMessage::new(
            protocol_id,
            send_id,
            recv_id,
            view,
            Self::MESSAGE_TYPE,
            message_data,
        )
    }
}

// Concrete Messages
#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct MVBADoneMessage {
    pub id: MVBAID,
    pub proposal: PPProposal,
}

impl MVBADoneMessage {
    pub fn new(id: MVBAID, proposal: PPProposal) -> Self {
        Self { id, proposal }
    }
}

impl ToProtocolMessage for MVBADoneMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBADone;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MVBASkipShareMessage {
    pub id: MVBAID,
    pub share: SkipShare,
}

impl MVBASkipShareMessage {
    pub fn new(id: MVBAID, share: SkipShare) -> Self {
        Self { id, share }
    }
}

impl ToProtocolMessage for MVBASkipShareMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBASkipShare;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MVBASkipMessage {
    pub id: MVBAID,
    pub sig: SkipSig,
}

impl MVBASkipMessage {
    pub fn new(id: MVBAID, sig: SkipSig) -> Self {
        Self { id, sig }
    }
}

impl ToProtocolMessage for MVBASkipMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBASkip;
}
