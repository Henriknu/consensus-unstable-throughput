use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use byteorder::{self, ByteOrder};
use log::{debug, warn};
use tokio::sync::{mpsc::error::SendError, Notify, RwLock};

use self::{
    buffer::{PRBCBufferCommand, PRBCReceiver},
    messages::{PRBCDoneMessage, RBCEchoMessage, RBCReadyMessage, RBCValueMessage},
    rbc::{RBCError, RBC},
};
use crate::{
    messaging::ProtocolMessageSender,
    proto::{ProtocolMessage, ProtocolMessageType},
    ABFTValue,
};
use bincode::{deserialize, Error as BincodeError};
use consensus_core::crypto::{
    sign::{Signature, SignatureShare, Signer},
    SignatureIdentifier,
};
use thiserror::Error;

pub mod buffer;
pub mod messages;
pub mod rbc;

pub type PRBCResult<T> = Result<T, PRBCError>;

pub struct PRBC {
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    batch_size: u32,
    pub(crate) send_id: u32,
    value_identifier: [u8; 8],
    shares: RwLock<BTreeMap<usize, SignatureShare>>,
    notify_shares: Arc<Notify>,
    has_signature: AtomicBool,

    // Sub-protocol instances
    rbc: RwLock<Option<RBC>>,
}

impl PRBC {
    pub fn init(
        id: u32,
        index: u32,
        f_tolerance: u32,
        n_parties: u32,
        batch_size: u32,
        send_id: u32,
    ) -> Self {
        let mut value_identifier = [0u8; 8];

        byteorder::NativeEndian::write_u32_into(&[id, send_id], &mut value_identifier);

        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            batch_size,
            send_id,
            value_identifier,
            shares: Default::default(),
            notify_shares: Default::default(),
            has_signature: AtomicBool::new(false),
            rbc: RwLock::new(None),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender + Sync + Send, R: PRBCReceiver, V: ABFTValue>(
        &self,
        value: Option<V>,
        recv_handle: &R,
        send_handle: &F,
        signer: &Signer,
    ) -> PRBCResult<PRBCSignature<V>> {
        self.init_rbc().await?;

        let lock = self.rbc.read().await;
        let rbc = lock.as_ref().expect("RBC should be initialized");

        recv_handle.drain_rbc(self.send_id).await?;

        let value = rbc.invoke(value, send_handle).await?;

        let identifier = SignatureIdentifier::new(0, self.send_id as usize);

        let share = signer.sign(&self.value_identifier, &identifier);

        recv_handle.drain_prbc_done(self.send_id).await?;

        let done_message = PRBCDoneMessage::new(share);

        send_handle
            .broadcast(
                self.id,
                self.index,
                self.n_parties,
                0,
                self.send_id,
                done_message,
            )
            .await;

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        let lock = self.shares.write().await;

        let signature = signer.combine_signatures(&lock, &identifier);

        if !signer.verify_signature(&signature, &self.value_identifier) {
            warn!(
                "Party {} got invalid signature. Shares: {:?}, ValueID: {:?}",
                self.index, *lock, self.value_identifier
            );

            panic!(
                "Party {} got invalid signature for Party {}. Abort and investigate.",
                self.index, self.send_id
            );
        }

        self.has_signature.store(true, Ordering::Relaxed);

        Ok(PRBCSignature {
            value,
            inner: signature,
        })
    }

    pub async fn handle_protocol_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: ProtocolMessage,
        send_handle: &F,
        _signer: &Signer,
    ) -> PRBCResult<()> {
        let ProtocolMessage {
            send_id,
            recv_id,
            prbc_index,
            protocol_id,
            view,
            message_data,
            message_type,
        } = message;

        match ProtocolMessageType::from_i32(message_type).unwrap() {
            ProtocolMessageType::PrbcDone => {
                // If we have already returned a signature, we can safely ignore any new protocol messages sent.
                if self.has_signature.load(Ordering::Relaxed) {
                    return Ok(());
                }

                let inner: PRBCDoneMessage = deserialize(&message_data)?;

                match self.on_done_message(send_id, inner).await {
                    Ok(_) => {}
                    Err(PRBCError::NotReadyForDoneMessage) => {
                        return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                            send_id,
                            recv_id,
                            prbc_index,
                            protocol_id,
                            view,
                            message_data,
                            message_type,
                        }));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            ProtocolMessageType::RbcEcho => {
                let rbc = self.rbc.read().await;

                if let Some(rbc) = &*rbc {
                    let inner: RBCEchoMessage = deserialize(&message_data)?;

                    rbc.on_echo_message(inner, send_handle).await?;
                } else {
                    return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                        send_id,
                        recv_id,
                        prbc_index,
                        protocol_id,
                        view,
                        message_data,
                        message_type,
                    }));
                }
            }
            ProtocolMessageType::RbcValue => {
                let rbc = self.rbc.read().await;

                if let Some(rbc) = &*rbc {
                    let inner: RBCValueMessage = deserialize(&message_data)?;

                    rbc.on_value_message(inner, send_handle).await?;
                } else {
                    return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                        send_id,
                        recv_id,
                        prbc_index,
                        protocol_id,
                        view,
                        message_data,
                        message_type,
                    }));
                }
            }
            ProtocolMessageType::RbcReady => {
                let rbc = self.rbc.read().await;

                if let Some(rbc) = &*rbc {
                    let inner: RBCReadyMessage = deserialize(&message_data)?;

                    rbc.on_ready_message(send_id, inner, send_handle).await?;
                } else {
                    return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                        send_id,
                        recv_id,
                        prbc_index,
                        protocol_id,
                        view,
                        message_data,
                        message_type,
                    }));
                }
            }
            _ => {
                warn!(
                    "Message with other ProtocolMessageType: {:?} than PRBC was passed to PRBC.",
                    message_type
                )
            }
        }

        Ok(())
    }

    pub async fn on_done_message(&self, index: u32, message: PRBCDoneMessage) -> PRBCResult<()> {
        // Need to ensure we have received value

        debug!("Party {} went into on done prbc message. ", self.index);

        {
            let mut lock = self.shares.write().await;
            if !lock.contains_key(&(index as usize)) {
                lock.insert(index as usize, message.share);

                if lock.len() >= (self.f_tolerance + 1) as usize {
                    self.notify_shares.notify_one();
                }
            }
        }

        debug!("Party {} went out of on done prbc message. ", self.index);

        Ok(())
    }

    async fn init_rbc(&self) -> PRBCResult<()> {
        let rbc = RBC::try_init(
            self.id,
            self.index,
            self.f_tolerance,
            self.n_parties,
            self.batch_size,
            self.send_id,
        )?;

        let mut lock = self.rbc.write().await;

        lock.replace(rbc);

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PRBCSignature<V: ABFTValue> {
    pub(crate) value: V,
    pub(crate) inner: Signature,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct PRBCID {
    epoch: u32,
    send_id: u32,
}

#[derive(Error, Debug)]
pub enum PRBCError {
    #[error(transparent)]
    RBC(#[from] RBCError),
    #[error("Not ready for DoneMessage, because RBC instance has not returned yet.")]
    NotReadyForDoneMessage,
    #[error(transparent)]
    FailedToSerialize(#[from] BincodeError),
    #[error("Produced/Received invalid signature for {0}")]
    InvalidSignature(String),
    #[error("Not ready to handle message")]
    NotReadyForMessage(ProtocolMessage),
    #[error("Failed to send PRBCBufferCommand from MVBA instance")]
    BufferSender(#[from] SendError<PRBCBufferCommand>),
}
