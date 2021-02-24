use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use tokio::sync::RwLock;

use super::{
    messages::{MVBASender, PBSendMessage, PBShareAckMessage, ProtocolMessage},
    provable_broadcast::*,
    Key, Value, MVBA, MVBAID,
};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

pub struct PPSender {
    id: PPID,
    index: usize,
    n_parties: usize,
    proof: Option<PBSig>,
    inner_pb: RwLock<Option<PBSender>>,
    status: PPStatus,
}

impl PPSender {
    pub fn init(id: PPID, index: usize, n_parties: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            proof: None,
            inner_pb: RwLock::new(None),
            status: PPStatus::Init,
        }
    }

    pub async fn promote<F: MVBASender>(
        &self,
        value: Value,
        key: PBKey,
        signer: &Signer,
        send_handle: &F,
    ) -> Option<PBSig> {
        // proof_prev = null
        let mut proof_prev: Option<PBSig> = None;

        // for step 1 to 4: Execute PB. Store return value in proof_prev

        for step in 1u8..5 {
            let proposal = PPProposal {
                value,
                proof: PBProof {
                    key: key.clone(),
                    proof_prev: proof_prev.clone(),
                },
            };

            self.init_pb(step, proposal).await;

            let lock = self.inner_pb.read().await;

            let pb = lock.as_ref().unwrap();

            proof_prev.replace(pb.broadcast(signer, send_handle).await);
        }

        proof_prev
    }

    pub async fn on_share_ack(&self, index: usize, message: PBShareAckMessage, signer: &Signer) {
        let inner_pb = self.inner_pb.read().await;
        if let Some(pb) = &*inner_pb {
            pb.on_share_ack_message(index, message, signer).await;
        }
    }

    async fn init_pb(&self, step: u8, proposal: PPProposal) {
        let pb = PBSender::init(
            PBID {
                id: self.id,
                step: FromPrimitive::from_u8(step).expect("Step 1-4 correspond to range (1..5)"),
            },
            self.index,
            self.n_parties,
            proposal,
        );

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(pb);
    }
}

#[derive(Default)]
pub struct PPReceiver {
    id: PPID,
    index: usize,
    key: Option<PPProposal>,
    lock: Option<PPProposal>,
    commit: Option<PPProposal>,
    inner_pb: RwLock<Option<PBReceiver>>,
}

impl PPReceiver {
    pub fn init(id: PPID, index: usize) -> Self {
        Self {
            id,
            index,
            key: None,
            lock: None,
            commit: None,
            inner_pb: RwLock::new(None),
        }
    }

    pub async fn invoke(&mut self) {
        // Step 1: Sender broadcasts value and mvba key
        self.init_pb(1).await;
        let pb_lock = self.inner_pb.read().await;
        let pb = pb_lock.as_ref().unwrap();
        let _ = pb.invoke().await;

        // Step 2: Sender broadcasts key proposal
        self.init_pb(2).await;
        let pb_lock = self.inner_pb.read().await;
        let pb = pb_lock.as_ref().unwrap();
        let key = pb.invoke().await;
        self.key.replace(key);

        // Step 3: Sender broadcasts lock proposal
        self.init_pb(3).await;
        let pb_lock = self.inner_pb.read().await;
        let pb = pb_lock.as_ref().unwrap();
        let lock = pb.invoke().await;
        self.lock.replace(lock);

        // Step 4: Sender broadcasts commit proposal
        self.init_pb(4).await;
        let pb_lock = self.inner_pb.read().await;
        let pb = pb_lock.as_ref().unwrap();
        let commit = pb.invoke().await;
        self.commit.replace(commit);
    }

    pub async fn on_value_send_message<F: MVBASender>(
        &self,
        index: usize,
        message: PBSendMessage,
        id: &MVBAID,
        leader_index: usize,
        lock: usize,
        signer: &Signer,
        send_handle: &F,
    ) {
        let inner_pb = self.inner_pb.read().await;

        if let Some(pb) = &*inner_pb {
            pb.on_value_send_message(index, message, id, leader_index, lock, signer, send_handle)
                .await;
        }
    }

    pub async fn abandon(&self) {
        let mut inner_pb = self.inner_pb.write().await;

        if let Some(pb) = &mut *inner_pb {
            *inner_pb = None;
        }
    }

    async fn init_pb(&self, step: u8) {
        let id = PBID {
            id: self.id,
            step: FromPrimitive::from_u8(step as u8 + 1).expect("Expect step < 4"),
        };

        let new_pb = PBReceiver::init(id, self.index);

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(new_pb);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct PPID {
    pub(crate) inner: MVBAID,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PPProposal {
    pub(crate) value: Value,
    pub(crate) proof: PBProof,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, PartialOrd, FromPrimitive)]
pub enum PPStatus {
    Init,
    Step1,
    Step2,
    Step3,
    Step4,
    Finished,
}
