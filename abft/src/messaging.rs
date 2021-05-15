use async_trait::async_trait;

use bincode::serialize;
use consensus_core::crypto::encrypt::EncodedDecryptionShare;

use serde::{Deserialize, Serialize};

use crate::proto::{ProtocolMessage, ProtocolMessageType};

#[async_trait]
pub trait ProtocolMessageSender {
    async fn send<M: ToProtocolMessage + Send + Sync + 'static>(
        &self,
        id: u32,
        send_id: u32,
        recv_id: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    );
    async fn broadcast<M: ToProtocolMessage + Send + Sync + 'static>(
        &self,
        id: u32,
        send_id: u32,
        n_parties: u32,
        view: u32,
        prbc_index: u32,
        message: M,
    );
}

pub trait ToProtocolMessage
where
    Self: Serialize,
{
    const MESSAGE_TYPE: ProtocolMessageType;

    fn to_protocol_message(
        &self,
        protocol_id: u32,
        send_id: u32,
        recv_id: u32,
        view: u32,
        prbc_index: u32,
    ) -> ProtocolMessage {
        let message_data = serialize(self).expect("Could not serialize inner of Protocol message");

        ProtocolMessage {
            protocol_id,
            send_id,
            recv_id,
            view,
            prbc_index,
            message_type: Self::MESSAGE_TYPE.into(),
            message_data,
        }
    }
}

// Concrete Messages
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ABFTDecryptionShareMessage {
    pub index: u32,
    pub key: EncodedDecryptionShare,
    pub nonce: EncodedDecryptionShare,
}

impl ABFTDecryptionShareMessage {
    pub fn new(index: u32, key: EncodedDecryptionShare, nonce: EncodedDecryptionShare) -> Self {
        Self { index, key, nonce }
    }
}

impl ToProtocolMessage for ABFTDecryptionShareMessage {
    const MESSAGE_TYPE: ProtocolMessageType = ProtocolMessageType::AbftDecryptionShare;
}
