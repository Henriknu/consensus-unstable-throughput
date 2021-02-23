use std::sync::Arc;

use super::{
    messages::{PBSendMessage, PBShareAckMessage, ProtocolMessage},
    provable_broadcast::*,
    Key, Value, MVBA, MVBAID,
};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

pub struct PPSender<'s, F: Fn(usize, ProtocolMessage)> {
    id: PPID,
    index: usize,
    n_parties: usize,
    proof: Option<PBSig>,
    inner_pb: Option<PBSender<'s, F>>,
    status: PPStatus,
    signer: &'s Signer,
    send_handle: &'s F,
}

impl<'s, F: Fn(usize, ProtocolMessage)> PPSender<'s, F> {
    pub fn init(
        id: PPID,
        index: usize,
        n_parties: usize,
        signer: &'s Signer,
        send_handle: &'s F,
    ) -> Self {
        Self {
            id,
            index,
            n_parties,
            proof: None,
            signer,
            inner_pb: None,
            status: PPStatus::Init,
            send_handle,
        }
    }

    pub async fn promote(&mut self, value: Value, key: PBKey) -> Option<PBSig> {
        // proof_prev = null
        let mut proof_prev: Option<PBSig> = None;

        // for step 1 to 4: Execute PB. Store return value in proof_prev

        for step in 1..5 {
            let proposal = PPProposal {
                value,
                proof: PBProof {
                    key: key.clone(),
                    proof_prev: proof_prev.clone(),
                },
            };

            let pb = self.init_pb(step, proposal);

            proof_prev.replace(pb.broadcast().await);
        }

        proof_prev
    }

    pub fn on_share_ack(&self, message: &PBShareAckMessage) {}

    fn init_pb(&mut self, step: u8, proposal: PPProposal) -> &PBSender<'s, F> {
        let pb = PBSender::init(
            PBID {
                id: self.id,
                step: FromPrimitive::from_u8(step).expect("Step 1-4 correspond to range (1..5)"),
            },
            self.index,
            self.n_parties,
            self.signer,
            proposal,
            self.send_handle,
        );

        self.inner_pb.replace(pb);

        &self
            .inner_pb
            .as_ref()
            .expect("PB instance should be initialized")
    }
}

#[derive(Clone)]
pub struct PPReceiver<'s, F: Fn(usize, ProtocolMessage)> {
    id: PPID,
    index: usize,
    key: Option<PPProposal>,
    lock: Option<PPProposal>,
    commit: Option<PPProposal>,
    signer: &'s Signer,
    send_handle: &'s F,
    inner_pb: Option<PBReceiver<'s, F>>,
}

impl<'s, F: Fn(usize, ProtocolMessage)> PPReceiver<'s, F> {
    pub fn init(id: PPID, index: usize, signer: &'s Signer, send_handle: &'s F) -> Self {
        Self {
            id,
            index,
            key: None,
            lock: None,
            commit: None,
            signer,
            inner_pb: None,
            send_handle,
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

    pub fn on_value_send_message(&self, message: &PBSendMessage) {}

    pub fn abandon(&mut self) {
        if let Some(pb) = &mut self.inner_pb {
            pb.abandon();
        }
    }

    fn init_pb(&mut self, step: u8) -> &PBReceiver<'s, F> {
        let id = PBID {
            id: self.id,
            step: FromPrimitive::from_u8(step as u8 + 1).expect("Expect step < 4"),
        };

        let new_pb = PBReceiver::init(id, self.index, self.signer, self.send_handle);

        self.inner_pb.replace(new_pb);

        //TODO: Remove reference, take it in caller instead

        self.inner_pb
            .as_ref()
            .expect("PB instance should be initialized")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
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
