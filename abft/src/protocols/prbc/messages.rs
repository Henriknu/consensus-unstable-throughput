use consensus_core::crypto::{hash::H256, merkle::MerkleBranch, sign::SignatureShare};
use serde::{Deserialize, Serialize};

use crate::messaging::ToProtocolMessage;

use crate::proto::{ProtocolMessage, ProtocolMessageType};

#[derive(Debug, Clone)]
pub enum PRBCMessageType {
    //PRBC
    PRBCDone,

    //RBC
    RBCEcho,
    RBCValue,
    RBCReady,
}

// Concrete Messages

#[derive(Debug, Serialize, Deserialize)]
pub struct PRBCDoneMessage {
    pub(crate) share: SignatureShare,
}

impl PRBCDoneMessage {
    pub fn new(share: SignatureShare) -> Self {
        Self { share }
    }
}

impl ToProtocolMessage for PRBCDoneMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::PrbcDone;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RBCValueMessage {
    pub(crate) root: H256,
    pub(crate) fragment: Vec<u8>,
    pub(crate) branch: MerkleBranch,
}

impl RBCValueMessage {
    pub fn new(root: H256, fragment: Vec<u8>, branch: MerkleBranch) -> Self {
        Self {
            root,
            fragment,
            branch,
        }
    }
}

impl ToProtocolMessage for RBCValueMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::RbcValue;
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
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::RbcReady;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RBCEchoMessage {
    pub(crate) index: u32,
    pub(crate) root: H256,
    pub(crate) fragment: Vec<u8>,
    pub(crate) branch: MerkleBranch,
}

impl RBCEchoMessage {
    pub fn new(index: u32, root: H256, fragment: Vec<u8>, branch: MerkleBranch) -> Self {
        Self {
            index,
            root,
            fragment,
            branch,
        }
    }
}

impl ToProtocolMessage for RBCEchoMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::RbcEcho;
}
