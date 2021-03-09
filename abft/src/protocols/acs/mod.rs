use std::{collections::HashMap, sync::Arc};

use consensus_core::crypto::{commoncoin::Coin, sign::Signer};
use tokio::sync::RwLock;

use crate::{messaging::ProtocolMessageSender, Value};

use super::{mvba::MVBA, prbc::PRBC};

pub struct ACS<F: ProtocolMessageSender + Sync + Send> {
    id: usize,
    index: usize,
    n_parties: usize,
    value: Value,

    // sub-protocols
    prbcs: RwLock<Option<HashMap<usize, Arc<PRBC<F>>>>>,
    mvba: RwLock<Option<MVBA>>,

    // Infrastructure
    send_handle: F,
    coin: Coin,
    signer: Signer,
}

impl<F: ProtocolMessageSender + Sync + Send> ACS<F> {
    pub fn new(
        id: usize,
        index: usize,
        n_parties: usize,
        value: Value,
        send_handle: F,
        signer: Signer,
        coin: Coin,
    ) -> Self {
        Self {
            id,
            index,
            n_parties,
            value,
            prbcs: RwLock::const_new(None),
            mvba: RwLock::const_new(None),
            coin,
            signer,
            send_handle,
        }
    }

    pub async fn invoke() {

        // Spin up n-1 PRBC instances, receiving values from other parties

        // broadcast value using PRBC

        // receive signatures from PRBC instances

        // when received n - f signatures, we have enough values to propose for MVBA

        // Propose W = set ( (value, sig)) to MVBA

        // Wait for mvba to return some W*, proposed by one of the parties.

        // Wait to receive values from each and every party contained in the W vector.

        // Return the combined values of all the parties in the W vector.
    }
}

pub enum ACSError {}
