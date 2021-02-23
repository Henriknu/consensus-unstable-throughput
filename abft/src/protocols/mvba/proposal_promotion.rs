use std::{marker::PhantomData, sync::Arc};

use super::{
    messages::{MVBASender, PBSendMessage, PBShareAckMessage, ProtocolMessage},
    provable_broadcast::*,
    Key, Value, MVBA, MVBAID,
};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

pub struct PPSender<F: MVBASender> {
    id: PPID,
    index: usize,
    n_parties: usize,
    proof: Option<PBSig>,
    inner_pb: Option<PBSender<F>>,
    status: PPStatus,
    _phantom: PhantomData<F>,
}

impl<F: MVBASender> PPSender<F> {
    pub fn init(id: PPID, index: usize, n_parties: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            proof: None,
            inner_pb: None,
            status: PPStatus::Init,
            _phantom: PhantomData,
        }
    }

    pub async fn promote(
        &mut self,
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

            let pb = self.init_pb(step, proposal);

            proof_prev.replace(pb.broadcast(signer, send_handle).await);
        }

        proof_prev
    }

    pub async fn on_share_ack(
        &mut self,
        index: usize,
        message: PBShareAckMessage,
        signer: &Signer,
    ) {
        if let Some(pb) = &mut self.inner_pb {
            pb.on_share_ack_message(index, message, signer).await;
        }
    }

    fn init_pb(&mut self, step: u8, proposal: PPProposal) -> &PBSender<F> {
        let pb = PBSender::init(
            PBID {
                id: self.id,
                step: FromPrimitive::from_u8(step).expect("Step 1-4 correspond to range (1..5)"),
            },
            self.index,
            self.n_parties,
            proposal,
        );

        self.inner_pb.replace(pb);

        &self
            .inner_pb
            .as_ref()
            .expect("PB instance should be initialized")
    }
}

#[derive(Clone, Default)]
pub struct PPReceiver<F: MVBASender> {
    id: PPID,
    index: usize,
    key: Option<PPProposal>,
    lock: Option<PPProposal>,
    commit: Option<PPProposal>,
    inner_pb: Option<PBReceiver<F>>,
    _phantom: PhantomData<F>,
}

impl<F: MVBASender> PPReceiver<F> {
    pub fn init(id: PPID, index: usize) -> Self {
        Self {
            id,
            index,
            key: None,
            lock: None,
            commit: None,
            inner_pb: None,
            _phantom: PhantomData,
        }
    }

    pub async fn invoke(&mut self) {
        // Step 1: Sender broadcasts value and mvba key
        let pb = self.init_pb(1);
        let _ = pb.invoke().await;

        // Step 2: Sender broadcasts key proposal
        let pb = self.init_pb(2);
        let key = pb.invoke().await;
        self.key.replace(key);

        // Step 3: Sender broadcasts lock proposal
        let pb = self.init_pb(3);
        let lock = pb.invoke().await;
        self.lock.replace(lock);

        // Step 4: Sender broadcasts commit proposal
        let pb = self.init_pb(4);
        let commit = pb.invoke().await;
        self.commit.replace(commit);
    }

    pub async fn on_value_send_message(
        &mut self,
        index: usize,
        message: PBSendMessage,
        id: &MVBAID,
        leader_index: usize,
        lock: usize,
        signer: &Signer,
        send_handle: &F,
    ) {
        if let Some(pb) = &mut self.inner_pb {
            pb.on_value_send_message(index, message, id, leader_index, lock, signer, send_handle)
                .await;
        }
    }

    pub fn abandon(&mut self) {
        if let Some(pb) = &mut self.inner_pb {
            pb.abandon();
        }
    }

    fn init_pb(&mut self, step: u8) -> &PBReceiver<F> {
        let id = PBID {
            id: self.id,
            step: FromPrimitive::from_u8(step as u8 + 1).expect("Expect step < 4"),
        };

        let new_pb = PBReceiver::init(id, self.index);

        self.inner_pb.replace(new_pb);

        //TODO: Remove reference, take it in caller instead

        self.inner_pb
            .as_ref()
            .expect("PB instance should be initialized")
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
