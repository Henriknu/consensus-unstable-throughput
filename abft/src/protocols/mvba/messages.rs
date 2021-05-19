use consensus_core::crypto::commoncoin::EncodedCoinShare;

use serde::{Deserialize, Serialize};

use crate::{
    messaging::ToProtocolMessage, proto::ProtocolMessageType,
    protocols::mvba::proposal_promotion::PPProposal, ABFTValue,
};

use crate::protocols::mvba::provable_broadcast::{PBSigShare, PBID};
use crate::protocols::mvba::{SkipShare, SkipSig, MVBAID};

// Concrete Messages
#[derive(Debug, Serialize, Deserialize)]
pub struct PBSendMessage<V: ABFTValue> {
    pub id: PBID,
    #[serde(bound = "")]
    pub proposal: PPProposal<V>,
}

impl<V: ABFTValue> PBSendMessage<V> {
    pub fn new(id: PBID, proposal: PPProposal<V>) -> Self {
        Self { id, proposal }
    }
}

impl<V: ABFTValue> ToProtocolMessage for PBSendMessage<V> {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PbSend;
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PbShareAck;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewChangeMessage<V: ABFTValue> {
    pub id: u32,
    pub index: u32,
    pub view: u32,
    #[serde(bound = "")]
    pub leader_key: Option<PPProposal<V>>,
    #[serde(bound = "")]
    pub leader_lock: Option<PPProposal<V>>,
    #[serde(bound = "")]
    pub leader_commit: Option<PPProposal<V>>,
}

impl<V: ABFTValue> ViewChangeMessage<V> {
    pub fn new(
        id: u32,
        index: u32,
        view: u32,
        leader_key: Option<PPProposal<V>>,
        leader_lock: Option<PPProposal<V>>,
        leader_commit: Option<PPProposal<V>>,
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

impl<V: ABFTValue> ToProtocolMessage for ViewChangeMessage<V> {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::ViewChange;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MVBADoneMessage<V: ABFTValue> {
    pub id: MVBAID,
    #[serde(bound = "")]
    pub proposal: PPProposal<V>,
}

impl<V: ABFTValue> MVBADoneMessage<V> {
    pub fn new(id: MVBAID, proposal: PPProposal<V>) -> Self {
        Self { id, proposal }
    }
}

impl<V: ABFTValue> ToProtocolMessage for MVBADoneMessage<V> {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MvbaDone;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MvbaSkipShare;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::MvbaSkip;
}
