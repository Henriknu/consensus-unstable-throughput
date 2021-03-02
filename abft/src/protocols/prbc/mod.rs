use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use log::warn;
use tokio::sync::{Notify, RwLock};

use self::{
    messages::PRBCDoneMessage,
    rbc::{RBCError, RBC},
};
use crate::{messaging::ProtocolMessageSender, Value};
use bincode::{serialize, Error as BincodeError};
use consensus_core::crypto::sign::{Signature, SignatureShare, Signer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod messages;
pub mod rbc;

pub type PRBCResult<T> = Result<T, PRBCError>;

pub struct PRBC {
    id: usize,
    index: usize,
    n_parties: usize,
    value: RwLock<Option<Value>>,
    shares: RwLock<BTreeMap<usize, SignatureShare>>,
    notify_shares: Arc<Notify>,
}

impl PRBC {
    pub fn init(id: usize, index: usize, n_parties: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            value: RwLock::new(None),
            shares: Default::default(),
            notify_shares: Default::default(),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender>(
        &self,
        value: Option<Value>,
        signer: &Signer,
        send_handle: &F,
    ) -> PRBCResult<PRBCSignature> {
        let rbc = RBC::init(self.id, self.index, self.n_parties)?;

        let value = rbc.invoke(value, send_handle).await?;

        {
            let mut lock = self.value.write().await;

            lock.replace(value);
        }

        let share = signer.sign(&serialize(&value)?);

        let done_message = PRBCDoneMessage::new(share);

        send_handle
            .broadcast(self.id, self.index, self.n_parties, 0, done_message)
            .await;

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        let lock = self.shares.write().await;

        let signature = signer
            .combine_signatures(&lock)
            .map_err(|_| PRBCError::InvalidSignature("PRBC Invoke".to_string()))?;

        Ok(PRBCSignature { inner: signature })
    }

    pub async fn on_done_message(
        &self,
        index: usize,
        message: PRBCDoneMessage,
        signer: &Signer,
    ) -> PRBCResult<()> {
        // Need to ensure we have received value

        let lock = self.value.read().await;

        let value = lock.ok_or_else(|| PRBCError::NotReadyForDoneMessage)?;

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
}

#[derive(Debug, Clone)]
pub struct PRBCSignature {
    inner: Signature,
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
}
