use consensus_core::crypto::{hash::H256, merkle::MerkleBranch};
use serde::{Deserialize, Serialize};

use crate::messaging::{ProtocolMessageType, ToProtocolMessage};

use super::rbc::RBCBlock;

#[derive(Debug, Clone)]
pub enum PRBCMessageType {
    //RBC
    RBCEcho,
    RBCValue,
    RBCReady,
}

// Concrete Messages
#[derive(Debug, Serialize, Deserialize)]
pub struct RBCValueMessage {
    pub(crate) root: H256,
    pub(crate) block: RBCBlock,
    pub(crate) branch: MerkleBranch,
}

impl RBCValueMessage {
    pub fn new(root: H256, block: RBCBlock, branch: MerkleBranch) -> Self {
        Self {
            root,
            block,
            branch,
        }
    }
}

impl ToProtocolMessage for RBCValueMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PRBC(PRBCMessageType::RBCValue);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RBCReadyMessage {
    pub(crate) root: H256,
}

impl RBCReadyMessage {
    pub fn new(root: H256) -> Self {
        Self { root }
    }
}

impl ToProtocolMessage for RBCReadyMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PRBC(PRBCMessageType::RBCReady);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RBCEchoMessage {
    pub(crate) index: usize,
    pub(crate) root: H256,
    pub(crate) block: RBCBlock,
    pub(crate) branch: MerkleBranch,
}

impl RBCEchoMessage {
    pub fn new(index: usize, root: H256, block: RBCBlock, branch: MerkleBranch) -> Self {
        Self {
            index,
            root,
            block,
            branch,
        }
    }
}

impl ToProtocolMessage for RBCEchoMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PRBC(PRBCMessageType::RBCEcho);
}
