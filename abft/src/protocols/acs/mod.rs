use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{mpsc::channel, Arc},
};
use thiserror::Error;

use consensus_core::crypto::{
    commoncoin::Coin,
    sign::{Signature, Signer},
};
use log::{error, info};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Notify, RwLock,
};

use crate::{
    messaging::{
        ProtocolMessage, ProtocolMessageHeader, ProtocolMessageSender, ProtocolMessageType,
    },
    ABFTValue, Value,
};

use super::{
    mvba::{buffer::MVBAReceiver, error::MVBAError, MVBA},
    prbc::{buffer::PRBCReceiver, PRBCError, PRBCSignature, PRBC},
};

pub type ACSResult<T> = Result<T, ACSError>;

pub mod buffer;

pub struct ACS<V: ABFTValue> {
    id: usize,
    index: usize,
    n_parties: usize,
    value: V,

    // sub-protocols
    prbcs: RwLock<Option<HashMap<usize, Arc<PRBC<V>>>>>,
    mvba: RwLock<Option<MVBA<SignatureVector>>>,
}

impl<V: ABFTValue> ACS<V> {
    pub fn init(id: usize, index: usize, n_parties: usize, value: V) -> Self {
        Self {
            id,
            index,
            n_parties,
            value,

            prbcs: RwLock::const_new(None),
            mvba: RwLock::const_new(None),
        }
    }

    pub async fn invoke<
        F: ProtocolMessageSender + Sync + Send + 'static,
        R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
    >(
        &self,
        recv_handle: Arc<R>,
        send_handle: Arc<F>,
        signer_prbc: Arc<Signer>,
        signer_mvba: &Signer,
        coin: &Coin,
    ) -> ACSResult<ValueVector<V>> {
        // Spin up n-1 PRBC instances, receiving values from other parties

        // broadcast value using PRBC

        // receive signatures from PRBC instances

        self.init_prbc().await;

        let (sig_send, mut sig_recv) = tokio::sync::mpsc::channel(self.n_parties);
        {
            let prbc_lock = self.prbcs.read().await;

            let prbcs = prbc_lock.as_ref().expect("PRBC should be initialized");

            for (index, prbc) in prbcs {
                let prbc_clone = prbc.clone();
                let recv_clone = recv_handle.clone();
                let send_clone = send_handle.clone();
                let sig_send_clone = sig_send.clone();
                let signer_clone = signer_prbc.clone();
                let index_copy = self.index;

                let value = {
                    if *index == self.index {
                        Some(self.value.clone())
                    } else {
                        None
                    }
                };

                tokio::spawn(async move {
                    match prbc_clone
                        .invoke(value, &*recv_clone, &*send_clone, &*signer_clone)
                        .await
                    {
                        Ok(signature) => {
                            let _ = sig_send_clone.send((prbc_clone.send_id, signature)).await;
                        }
                        Err(e) => {
                            error!(
                                "Party {} received error on invoking pp_recv: {}",
                                index_copy, e
                            );
                        }
                    }
                });
            }
        }

        // when received n - f signatures, we have enough values to propose for MVBA

        let mut signatures = BTreeMap::new();

        while let Some((index, signature)) = sig_recv.recv().await {
            if !signatures.contains_key(&index) {
                signatures.insert(index, signature);
            }

            if signatures.len() >= (self.n_parties * 2 / 3 + 1) {
                break;
            }
        }

        // Propose W = set ( (value, sig)) to MVBA

        let vector = self.to_signature_vector(&signatures).await;

        self.init_mvba(vector).await;

        // Wait for mvba to return some W*, proposed by one of the parties.

        let elected_vector = {
            let mvba_lock = self.mvba.read().await;

            let mvba = mvba_lock.as_ref().expect("MVBA should be init");

            mvba.invoke(recv_handle, &*send_handle, signer_mvba, coin)
                .await?
        };

        // Wait to receive values from each and every party contained in the W vector.

        let result = self
            .retrieve_values(elected_vector, signatures, sig_recv)
            .await;

        // Return the combined values of all the parties in the W vector.

        Ok(result)
    }

    pub async fn handle_protocol_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: ProtocolMessage,
        send_handle: &F,
        signer_prbc: &Signer,
        signer_mvba: &Signer,
        coin: &Coin,
    ) -> ACSResult<()> {
        info!(
            "Handling message from {} to {} with message_type {:?}",
            message.header.send_id, message.header.recv_id, message.message_type
        );

        match message.message_type {
            ProtocolMessageType::PRBC(_) => {
                // pass to correct PRBC instance

                let prbcs = self.prbcs.read().await;

                if let Some(prbcs) = &*prbcs {
                    if let Some(prbc) = prbcs.get(&message.header.prbc_index) {
                        match prbc
                            .handle_protocol_message(message, send_handle, signer_prbc)
                            .await
                        {
                            Ok(_) => {}
                            Err(PRBCError::NotReadyForMessage(message)) => {
                                return Err(ACSError::NotReadyForPRBCMessage(message));
                            }
                            Err(e) => return Err(ACSError::PRBCError(e)),
                        }
                    } else {
                        return Err(ACSError::NotReadyForPRBCMessage(message));
                    }
                } else {
                    return Err(ACSError::NotReadyForPRBCMessage(message));
                }
            }
            ProtocolMessageType::MVBA(_) => {
                // pass to MVBA instance
                let mvba = self.mvba.read().await;

                if let Some(mvba) = &*mvba {
                    match mvba
                        .handle_protocol_message(message, send_handle, signer_mvba, coin)
                        .await
                    {
                        Ok(_) => {}
                        Err(MVBAError::NotReadyForMessage(message)) => {
                            return Err(ACSError::NotReadyForMVBAMessage(message));
                        }
                        Err(e) => return Err(ACSError::MVBAError(e)),
                    }
                } else {
                    return Err(ACSError::NotReadyForMVBAMessage(message));
                }
            }
            ProtocolMessageType::Default => {

                // ignore
            }
        }

        Ok(())
    }

    async fn to_signature_vector(
        &self,
        signatures: &BTreeMap<usize, PRBCSignature<V>>,
    ) -> SignatureVector {
        let inner = signatures
            .iter()
            .map(|(k, v)| (*k, v.inner.clone()))
            .collect();

        SignatureVector { inner }
    }

    async fn retrieve_values(
        &self,
        vector: SignatureVector,
        signatures: BTreeMap<usize, PRBCSignature<V>>,
        mut sig_recv: Receiver<(usize, PRBCSignature<V>)>,
    ) -> ValueVector<V> {
        let mut result: BTreeMap<usize, V> = BTreeMap::new();

        // Add all values we currently have
        {
            for index in vector.inner.keys() {
                if signatures.contains_key(index) {
                    result.insert(*index, signatures.get(index).unwrap().value.clone());
                }
            }
        }

        if result.len() == vector.inner.len() {
            return ValueVector { inner: result };
        }

        // Need to get outstainding values

        let mut remaining = Vec::with_capacity(vector.inner.len());

        for index in vector.inner.keys() {
            if !result.contains_key(index) {
                remaining.push(*index);
            }
        }

        while let Some((index, signature)) = sig_recv.recv().await {
            if !result.contains_key(&index) && remaining.contains(&index) {
                result.insert(index, signature.value);
                remaining.retain(|i| *i != index);
            }
            if result.len() == vector.inner.len() {
                break;
            }
        }

        ValueVector { inner: result }
    }

    async fn init_prbc(&self) {
        let prbcs = (0..self.n_parties)
            .map(|i| {
                (
                    i,
                    Arc::new(PRBC::init(self.id, self.index, self.n_parties, i)),
                )
            })
            .collect();

        let mut lock = self.prbcs.write().await;
        lock.replace(prbcs);
    }

    async fn init_mvba(&self, value: SignatureVector) {
        let mvba = MVBA::init(self.id, self.index, self.n_parties, value);

        let mut lock = self.mvba.write().await;

        lock.replace(mvba);
    }
}

#[derive(Error, Debug)]
pub enum ACSError {
    #[error("Not ready to handle PRBC message")]
    NotReadyForPRBCMessage(ProtocolMessage),
    #[error("Not ready to handle PRBC message")]
    NotReadyForMVBAMessage(ProtocolMessage),
    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    MVBAError(#[from] MVBAError),
    #[error(transparent)]
    PRBCError(#[from] PRBCError),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SignatureVector {
    pub inner: BTreeMap<usize, Signature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValueVector<V: ABFTValue> {
    inner: BTreeMap<usize, V>,
}
