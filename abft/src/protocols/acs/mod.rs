use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};
use log::{error, info};
use tokio::sync::{mpsc::Sender, Notify, RwLock};

use crate::{
    messaging::{
        ProtocolMessage, ProtocolMessageHeader, ProtocolMessageSender, ProtocolMessageType,
    },
    ABFTValue, Value,
};

use self::buffer::ACSBufferCommand;

use super::{
    mvba::{buffer::MVBAReceiver, MVBA},
    prbc::{buffer::PRBCReceiver, PRBCSignature, PRBC},
};

pub type ACSResult<T> = Result<T, ACSError>;

pub mod buffer;

pub struct ACS<V: ABFTValue> {
    id: usize,
    index: usize,
    n_parties: usize,
    value: V,
    prbc_signatures: RwLock<HashMap<usize, PRBCSignature<V>>>,
    notify_new_signature: Arc<Notify>,
    notify_enough_signatures: Arc<Notify>,

    // sub-protocols
    prbcs: RwLock<Option<HashMap<usize, Arc<PRBC<V>>>>>,
    mvba: RwLock<Option<MVBA<V>>>,
}

impl<V: ABFTValue> ACS<V> {
    pub fn new(id: usize, index: usize, n_parties: usize, value: V) -> Self {
        Self {
            id,
            index,
            n_parties,
            value,
            prbc_signatures: Default::default(),
            notify_new_signature: Default::default(),
            notify_enough_signatures: Default::default(),
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
    ) -> ACSResult<()> {
        // Spin up n-1 PRBC instances, receiving values from other parties

        // broadcast value using PRBC

        // receive signatures from PRBC instances

        self.init_prbc().await;

        {
            let prbc_lock = self.prbcs.read().await;

            let prbcs = prbc_lock.as_ref().expect("PRBC should be initialized");

            for (index, prbc) in prbcs {
                let prbc_clone = prbc.clone();
                let recv_clone = recv_handle.clone();
                let send_clone = send_handle.clone();
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
                        Ok(_) => {}
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

        let notify_signatures = self.notify_enough_signatures.clone();

        notify_signatures.notified().await;

        // Propose W = set ( (value, sig)) to MVBA

        //self.init_mvba().await;

        // Wait for mvba to return some W*, proposed by one of the parties.

        {
            let mvba_lock = self.mvba.read().await;

            let mvba = mvba_lock.as_ref().expect("MVBA should be init");

            let result = mvba
                .invoke(recv_handle, &*send_handle, signer_mvba, coin)
                .await;
        }

        // Wait to receive values from each and every party contained in the W vector.

        //let result = self.retrieve_values().await;

        // Return the combined values of all the parties in the W vector.

        Ok(())
    }

    pub async fn handle_protocol_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: ProtocolMessage,
        send_handle: &F,
        signer_prbc: &Signer,
        signer_mvba: &Signer,
        coin: &Coin,
    ) {
        let ProtocolMessage {
            header,
            message_data,
            message_type,
        } = message;
        let ProtocolMessageHeader {
            send_id, recv_id, ..
        } = header;

        info!(
            "Handling message from {} to {} with message_type {:?}",
            send_id, recv_id, message_type
        );

        match message_type {
            ProtocolMessageType::PRBC(_) => {

                // pass to correct PRBC instance
            }
            ProtocolMessageType::MVBA(_) => {

                // pass to MVBA instance
            }
            ProtocolMessageType::Default => {

                // ignore
            }
        }
    }

    async fn retrieve_values(&self, vector: Vec<usize>) -> HashMap<usize, V> {
        let mut result: HashMap<usize, V> = HashMap::new();

        // Add all values we currently have
        {
            let signatures = self.prbc_signatures.read().await;
            for index in &vector {
                if signatures.contains_key(index) {
                    result.insert(*index, signatures.get(index).clone().unwrap().value.clone());
                }
            }
        }

        let mut remaining = Vec::with_capacity(vector.len());

        // If we have outstanding values, add indices to remaining list.

        if result.len() != vector.len() {
            for index in &vector {
                if !result.contains_key(index) {
                    remaining.push(*index);
                }
            }
        }

        loop {
            // If we have all the values needed, break and return.
            if result.len() == vector.len() {
                break;
            }

            // If not, we wait for a new value to arrive.

            let notify_new_signature = self.notify_new_signature.clone();

            notify_new_signature.notified().await;

            let signatures = self.prbc_signatures.read().await;
            let mut i = 0;

            let remaining2 = remaining.clone();

            for index in &remaining2 {
                if signatures.contains_key(index) {
                    result.insert(*index, signatures.get(index).clone().unwrap().value.clone());
                    remaining.remove(i);
                }
                i += 1;
            }
        }

        result
    }

    async fn on_prbc_finished(&self) -> ACSResult<()> {
        Ok(())
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

    async fn init_mvba(&self, value: V) {
        let mvba = MVBA::init(self.id, self.index, self.n_parties, value);

        let mut lock = self.mvba.write().await;

        lock.replace(mvba);
    }
}

#[derive(Error, Debug)]
pub enum ACSError {}
