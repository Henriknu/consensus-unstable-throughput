use std::{collections::BTreeMap, sync::Arc};

use log::{info, warn};
use tokio::sync::{mpsc::error::SendError, Notify, RwLock};

use self::{
    buffer::{PRBCBufferCommand, PRBCReceiver},
    messages::{
        PRBCDoneMessage, PRBCMessageType, RBCEchoMessage, RBCReadyMessage, RBCValueMessage,
    },
    rbc::{RBCError, RBC},
};
use crate::{
    messaging::{
        ProtocolMessage, ProtocolMessageHeader, ProtocolMessageSender, ProtocolMessageType,
    },
    ABFTValue, Value,
};
use bincode::{deserialize, serialize, Error as BincodeError};
use consensus_core::crypto::sign::{Signature, SignatureShare, Signer};
use thiserror::Error;

pub mod buffer;
pub mod messages;
pub mod rbc;

pub type PRBCResult<T> = Result<T, PRBCError>;

pub struct PRBC<V: ABFTValue> {
    id: usize,
    index: usize,
    n_parties: usize,
    pub(crate) send_id: usize,
    value: RwLock<Option<V>>,
    shares: RwLock<BTreeMap<usize, SignatureShare>>,
    notify_shares: Arc<Notify>,

    // Sub-protocol instances
    rbc: RwLock<Option<RBC>>,
}

impl<V: ABFTValue> PRBC<V> {
    pub fn init(id: usize, index: usize, n_parties: usize, send_id: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            send_id,
            value: RwLock::new(None),
            shares: Default::default(),
            notify_shares: Default::default(),
            rbc: RwLock::new(None),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender + Sync + Send, R: PRBCReceiver>(
        &self,
        value: Option<V>,
        recv_handle: &R,
        send_handle: &F,
        signer: &Signer,
    ) -> PRBCResult<PRBCSignature<V>> {
        self.init_rbc().await?;

        let lock = self.rbc.read().await;
        let rbc = lock.as_ref().expect("RBC should be initialized");

        info!(
            "Party {} draining rbc messages from buffer, for PRBC {}",
            self.index, self.send_id
        );
        recv_handle.drain_rbc(self.send_id).await?;

        let value = rbc.invoke(value, send_handle).await?;

        {
            let mut lock = self.value.write().await;

            lock.replace(value.clone());
        }

        recv_handle.drain_prbc_done(self.send_id).await?;

        let share = signer.sign(&serialize(&value)?);

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

        let signature = signer
            .combine_signatures(&lock)
            .map_err(|_| PRBCError::InvalidSignature("PRBC Invoke".to_string()))?;

        info!(
            "Party {} succesfully completed PRBC with signature: {:?}",
            self.index, signature
        );

        Ok(PRBCSignature {
            value,
            inner: signature,
        })
    }

    pub async fn handle_protocol_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: ProtocolMessage,
        send_handle: &F,
        signer: &Signer,
    ) -> PRBCResult<()> {
        let ProtocolMessage {
            header,
            message_data,
            message_type,
        } = message;
        let ProtocolMessageHeader {
            send_id,
            recv_id,
            prbc_index,
            ..
        } = header;

        info!(
            "Handling PRBC message from {} to {}, in PRBC instance {}, with message_type {:?}",
            send_id, recv_id, prbc_index, message_type
        );

        if let ProtocolMessageType::PRBC(prbc_message_type) = &message_type {
            match prbc_message_type {
                PRBCMessageType::PRBCDone => {
                    let inner: PRBCDoneMessage = deserialize(&message_data)?;

                    match self.on_done_message(send_id, inner, signer).await {
                        Ok(_) => {}
                        Err(PRBCError::NotReadyForDoneMessage) => {
                            return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                                header,
                                message_data,
                                message_type,
                            }));
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                PRBCMessageType::RBCEcho => {
                    let rbc = self.rbc.read().await;

                    if let Some(rbc) = &*rbc {
                        let inner: RBCEchoMessage = deserialize(&message_data)?;

                        rbc.on_echo_message(inner, send_handle).await?;
                    } else {
                        warn!("Did not find RBC for Party {}!", recv_id);
                        return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
                PRBCMessageType::RBCValue => {
                    let rbc = self.rbc.read().await;

                    if let Some(rbc) = &*rbc {
                        let inner: RBCValueMessage = deserialize(&message_data)?;

                        rbc.on_value_message(inner, send_handle).await?;
                    } else {
                        warn!("Did not find RBC for Party {}!", recv_id);
                        return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
                PRBCMessageType::RBCReady => {
                    let rbc = self.rbc.read().await;

                    if let Some(rbc) = &*rbc {
                        let inner: RBCReadyMessage = deserialize(&message_data)?;

                        rbc.on_ready_message(send_id, inner, send_handle).await?;
                    } else {
                        warn!("Did not find RBC for Party {}!", recv_id);
                        return Err(PRBCError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
            }
        } else {
            warn!(
                "Message with other ProtocolMessageType: {:?} than PRBC was passed to PRBC.",
                message_type
            )
        }

        Ok(())
    }

    pub async fn on_done_message(
        &self,
        index: usize,
        message: PRBCDoneMessage,
        signer: &Signer,
    ) -> PRBCResult<()> {
        // Need to ensure we have received value

        let lock = self.value.read().await;

        let value = lock
            .as_ref()
            .ok_or_else(|| PRBCError::NotReadyForDoneMessage)?;

        if !signer.verify_share(index, &message.share, &serialize(&value)?) {
            warn!(
                "Party {} got invalid signature share from {} on PRBC value.",
                self.index, index
            );
            return Ok(());
        }

        {
            let mut lock = self.shares.write().await;
            if !lock.contains_key(&index) {
                lock.insert(index, message.share);

                if lock.len() >= (self.n_parties / 3 + 1) {
                    self.notify_shares.notify_one();
                }
            }
        }

        Ok(())
    }

    async fn init_rbc(&self) -> PRBCResult<()> {
        let rbc = RBC::init(self.id, self.index, self.n_parties, self.send_id)?;

        let mut lock = self.rbc.write().await;

        lock.replace(rbc);

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct PRBCSignature<V: ABFTValue> {
    pub(crate) value: V,
    pub(crate) inner: Signature,
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
