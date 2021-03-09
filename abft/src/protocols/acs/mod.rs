use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};
use log::info;
use tokio::sync::{mpsc::Sender, RwLock};

use crate::{
    messaging::{
        ProtocolMessage, ProtocolMessageHeader, ProtocolMessageSender, ProtocolMessageType,
    },
    Value,
};

use self::buffer::ACSBufferCommand;

use super::{
    mvba::MVBA,
    prbc::{PRBCSignature, PRBC},
};

pub type ACSResult<T> = Result<T, ACSError>;

pub mod buffer;

pub struct ACS {
    id: usize,
    index: usize,
    n_parties: usize,
    value: Value,
    prbc_signatures: RwLock<HashMap<usize, PRBCSignature>>,

    // sub-protocols
    prbcs: RwLock<Option<HashMap<usize, Arc<PRBC>>>>,
    mvba: RwLock<Option<MVBA>>,
}

impl ACS {
    pub fn new(id: usize, index: usize, n_parties: usize, value: Value) -> Self {
        Self {
            id,
            index,
            n_parties,
            value,
            prbc_signatures: Default::default(),
            prbcs: RwLock::const_new(None),
            mvba: RwLock::const_new(None),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender + Sync + Send>(
        &self,
        buff_handle: Sender<ACSBufferCommand>,
        send_handle: &F,
        signer_prbc: &Signer,
        signer_mvba: &Signer,
        coin: &Coin,
    ) {
        // Spin up n-1 PRBC instances, receiving values from other parties

        // broadcast value using PRBC

        // receive signatures from PRBC instances

        self.init_prbc().await;

        {
            let prbc_lock = self.prbcs.read().await;

            let prbcs = prbc_lock.as_ref().expect("PRBC should be initialized");

            for (index, prbc) in prbcs {
                let prbc_clone = prbc.clone();
                let buff_clone = buff_handle.clone();
                let send_clone = send_handle.clone();
                let signer_clone = signer_prbc.clone();

                let value = {
                    if *index == self.index {
                        Some(self.value)
                    } else {
                        None
                    }
                };

                tokio::spawn(async move {
                    prbc_clone
                        .invoke(value, buff_clone, send_clone, signer_clone)
                        .await;
                });
            }
        }

        // when received n - f signatures, we have enough values to propose for MVBA

        // Propose W = set ( (value, sig)) to MVBA

        // Wait for mvba to return some W*, proposed by one of the parties.

        // Wait to receive values from each and every party contained in the W vector.

        // Return the combined values of all the parties in the W vector.
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

    async fn on_prbc_finished(&self) -> ACSResult<()> {}

    async fn init_prbc(&self) -> ACSResult<()> {
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ACSError {}
