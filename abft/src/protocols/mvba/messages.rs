use consensus_core::crypto::commoncoin::EncodedCoinShare;

use serde::{Deserialize, Serialize};

use crate::{
    messaging::{ProtocolMessageType, ToProtocolMessage},
    protocols::mvba::proposal_promotion::PPProposal,
};

use crate::protocols::mvba::provable_broadcast::{PBSigShare, PBID};
use crate::protocols::mvba::{SkipShare, SkipSig, MVBAID};

#[derive(Debug, Clone)]
pub enum MVBAMessageType {
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBA(MVBAMessageType::PBSend);
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
    const MESSAGE_TYPE: ProtocolMessageType =
        ProtocolMessageType::MVBA(MVBAMessageType::PBShareAck);
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
    const MESSAGE_TYPE: ProtocolMessageType =
        ProtocolMessageType::MVBA(MVBAMessageType::ElectCoinShare);
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
    const MESSAGE_TYPE: ProtocolMessageType =
        ProtocolMessageType::MVBA(MVBAMessageType::ViewChange);
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBA(MVBAMessageType::MVBADone);
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
    const MESSAGE_TYPE: ProtocolMessageType =
        ProtocolMessageType::MVBA(MVBAMessageType::MVBASkipShare);
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MVBA(MVBAMessageType::MVBASkip);
}
