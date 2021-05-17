use byteorder::{self, ByteOrder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use thiserror::Error;

use consensus_core::crypto::{
    commoncoin::Coin,
    sign::{Signature, Signer},
};
use log::{debug, error, info, warn};
use tokio::sync::{mpsc::Receiver, RwLock};

use crate::{
    messaging::ProtocolMessageSender,
    proto::{ProtocolMessage, ProtocolMessageType},
    ABFTValue,
};

use super::{
    mvba::{buffer::MVBAReceiver, error::MVBAError, MvbaValue, MVBA},
    prbc::{buffer::PRBCReceiver, PRBCError, PRBCSignature, PRBC},
};

pub type ACSResult<T> = Result<T, ACSError>;

pub mod buffer;

pub struct ACS {
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    batch_size: u32,

    // sub-protocols
    prbcs: RwLock<Option<HashMap<u32, Arc<PRBC>>>>,
    mvba: RwLock<Option<MVBA<SignatureVector>>>,
}

impl ACS {
    pub fn init(id: u32, index: u32, f_tolerance: u32, n_parties: u32, batch_size: u32) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            batch_size,

            prbcs: RwLock::const_new(None),
            mvba: RwLock::const_new(None),
        }
    }

    pub async fn invoke<
        V: ABFTValue,
        F: ProtocolMessageSender + Sync + Send + 'static,
        R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
    >(
        &self,
        value: V,
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

        info!("Party {} starting prbc instances", self.index);

        let (sig_send, mut sig_recv) = tokio::sync::mpsc::channel(self.n_parties as usize);
        {
            let prbc_lock = self.prbcs.read().await;

            let prbcs = prbc_lock.as_ref().expect("PRBC should be initialized");

            let mut inputs = vec![None; prbcs.len()];

            inputs[self.index as usize].replace(value);

            for (index, prbc) in prbcs {
                let prbc_clone = prbc.clone();
                let recv_clone = recv_handle.clone();
                let send_clone = send_handle.clone();
                let sig_send_clone = sig_send.clone();
                let signer_clone = signer_prbc.clone();
                let index_copy = self.index;

                let value = inputs[*index as usize].take();

                tokio::spawn(async move {
                    match prbc_clone
                        .invoke(value, &*recv_clone, &*send_clone, &*signer_clone)
                        .await
                    {
                        Ok(signature) => {
                            debug!("Sending signature for PRBC {}.", index_copy);
                            let _ = sig_send_clone
                                .send((prbc_clone.send_id, signature))
                                .await
                                .map_err(|e| {
                                    warn!(
                                        "Could not send signature for PRBC {}, got error {}",
                                        index_copy, e
                                    );
                                });

                            debug!("Sending signature for PRBC {} went through.", index_copy);
                        }
                        Err(e) => {
                            error!(
                                "Party {} received error on invoking prbc: {}",
                                index_copy, e
                            );
                        }
                    }
                });
            }
        }

        info!("Party {} done starting prbc instances", self.index);

        // when received n - f signatures, we have enough values to propose for MVBA

        let mut signatures = BTreeMap::new();

        while let Some((index, signature)) = sig_recv.recv().await {
            if !signatures.contains_key(&index) {
                signatures.insert(index, signature);
            }

            if signatures.len() >= (self.n_parties - self.f_tolerance) as usize {
                break;
            }
        }

        // Propose W = set ( (value, sig)) to MVBA

        let (signature_vector, value_vector) = self.split_signatures(signatures).await;

        self.init_mvba(signature_vector).await;

        // Wait for mvba to return some W*, proposed by one of the parties.

        let elected_vector = {
            let mvba_lock = self.mvba.read().await;

            let mvba = mvba_lock.as_ref().expect("MVBA should be init");

            mvba.invoke(recv_handle, &*send_handle, signer_mvba, coin)
                .await?
        };
        // Wait to receive values from each and every party contained in the W vector.

        let result = self
            .retrieve_values(elected_vector, value_vector, sig_recv)
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
        match message.message_type() {
            ProtocolMessageType::PrbcDone
            | ProtocolMessageType::RbcEcho
            | ProtocolMessageType::RbcValue
            | ProtocolMessageType::RbcReady => {
                // pass to correct PRBC instance

                let prbcs = self.prbcs.read().await;

                if let Some(prbcs) = &*prbcs {
                    if let Some(prbc) = prbcs.get(&message.prbc_index) {
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
            ProtocolMessageType::MvbaDone
            | ProtocolMessageType::MvbaSkipShare
            | ProtocolMessageType::MvbaSkip
            | ProtocolMessageType::PbSend
            | ProtocolMessageType::PbShareAck
            | ProtocolMessageType::ElectCoinShare
            | ProtocolMessageType::ViewChange => {
                // pass to MVBA instance
                let mvba = self.mvba.read().await;

                if let Some(mvba) = &*mvba {
                    match mvba
                        .handle_protocol_message(
                            message,
                            send_handle,
                            signer_mvba,
                            signer_prbc,
                            coin,
                        )
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
            ProtocolMessageType::AbftDecryptionShare | ProtocolMessageType::Default => {

                // ignore
            }
        }

        Ok(())
    }

    async fn split_signatures<V: ABFTValue>(
        &self,
        prbc_signatures: BTreeMap<u32, PRBCSignature<V>>,
    ) -> (SignatureVector, ValueVector<V>) {
        let (values, signatures): (BTreeMap<u32, _>, BTreeMap<u32, _>) = prbc_signatures
            .into_iter()
            .map(|(k, v)| {
                let PRBCSignature { value, inner } = v;

                ((k, value), (k, inner))
            })
            .unzip();

        (
            SignatureVector { inner: signatures },
            ValueVector { inner: values },
        )
    }

    async fn retrieve_values<V: ABFTValue>(
        &self,
        signature_vector: SignatureVector,
        value_vector: ValueVector<V>,
        mut sig_recv: Receiver<(u32, PRBCSignature<V>)>,
    ) -> ValueVector<V> {
        let ValueVector { inner } = value_vector;

        let mut inner: BTreeMap<u32, V> = inner
            .into_iter()
            .filter(|(k, _)| signature_vector.inner.contains_key(k))
            .collect();

        if inner.len() == signature_vector.inner.len() {
            return ValueVector { inner };
        }

        // Need to get outstainding values

        let mut remaining = Vec::with_capacity(signature_vector.inner.len());

        for index in signature_vector.inner.keys() {
            if !inner.contains_key(index) {
                remaining.push(*index);
            }
        }

        while let Some((index, signature)) = sig_recv.recv().await {
            if !inner.contains_key(&index) && remaining.contains(&index) {
                inner.insert(index, signature.value);
                remaining.retain(|i| *i != index);
            }
            if inner.len() == signature_vector.inner.len() {
                break;
            }
        }

        ValueVector { inner }
    }

    async fn init_prbc(&self) {
        let prbcs = (0..self.n_parties)
            .map(|i| {
                (
                    i,
                    Arc::new(PRBC::init(
                        self.id,
                        self.index,
                        self.f_tolerance,
                        self.n_parties,
                        self.batch_size,
                        i,
                    )),
                )
            })
            .collect();

        let mut lock = self.prbcs.write().await;
        lock.replace(prbcs);
    }

    async fn init_mvba(&self, value: SignatureVector) {
        let mvba = MVBA::init(self.id, self.index, self.f_tolerance, self.n_parties, value);

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
    #[error("Not able to send prbc signature to receiver")]
    FailedSignatureSend,

    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    MVBAError(#[from] MVBAError),
    #[error(transparent)]
    PRBCError(#[from] PRBCError),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SignatureVector {
    pub inner: BTreeMap<u32, Signature>,
}

impl MvbaValue for SignatureVector {
    fn eval_mvba(&self, id: u32, f_tolerance: u32, n_parties: u32, signer: &Signer) -> bool {
        if self.inner.len() < (n_parties - f_tolerance) as usize {
            error!("Not enough signatures");
            return false;
        }

        let mut data = [0u8; 8];

        for (index, signature) in &self.inner {
            byteorder::NativeEndian::write_u32_into(&[id, *index], &mut data);

            if !signer.verify_signature(&signature, &data) {
                error!("invalid signature");
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValueVector<V: ABFTValue> {
    pub(crate) inner: BTreeMap<u32, V>,
}
