use super::{messages::ProtocolMessage, provable_broadcast::*, Value, MVBA, MVBAID};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

pub struct PPSender<'s, F: Fn(usize, &ProtocolMessage)> {
    id: PPID,
    index: usize,
    n_parties: usize,
    proposal: &'s PPProposal,
    proof: Option<PBSig>,
    status: PPStatus,
    signer: &'s Signer,
    send_handle: &'s F,
}

impl<'s, F: Fn(usize, &ProtocolMessage)> PPSender<'s, F> {
    pub fn init(
        id: PPID,
        index: usize,
        n_parties: usize,
        proposal: &'s PPProposal,
        signer: &'s Signer,
        send_handle: &'s F,
    ) -> Self {
        Self {
            id,
            index,
            n_parties,
            proposal,
            proof: None,
            signer,
            status: PPStatus::Init,
            send_handle,
        }
    }

    pub async fn promote(&self) -> Option<PBSig> {
        // proof_prev = null
        let mut proof_prev: Option<PBSig> = None;

        // for step 1 to 4: Execute PB. Store return value in proof_prev

        for step in 1..5 {
            let mut pb = PBSender::init(
                PBID {
                    id: self.id,
                    step: FromPrimitive::from_u8(step)
                        .expect("Step 1-4 correspond to range (1..5)"),
                },
                self.index,
                self.n_parties,
                self.signer,
                &self.proposal,
                self.send_handle,
            );

            proof_prev.replace(pb.broadcast().await);
        }

        proof_prev
    }
}

pub struct PPReceiver<'s, F: Fn(usize, &ProtocolMessage)> {
    id: PPID,
    index: usize,
    key: Option<PPProposal>,
    lock: Option<PPProposal>,
    commit: Option<PPProposal>,
    signer: &'s Signer,
    send_handle: &'s F,
    inner_pb: PBReceiver<'s, F>,
    mvba: &'s MVBA<'s, F>,
}

impl<'s, F: Fn(usize, &ProtocolMessage)> PPReceiver<'s, F> {
    pub fn init(
        id: PPID,
        index: usize,
        signer: &'s Signer,
        send_handle: &'s F,
        mvba: &'s MVBA<'s, F>,
    ) -> Self {
        Self {
            id,
            index,
            key: None,
            lock: None,
            commit: None,
            signer,
            inner_pb: PBReceiver::init(
                PBID {
                    id,
                    step: PPStatus::Step1,
                },
                index,
                &signer,
                send_handle,
                mvba,
            ),
            mvba,
            send_handle,
        }
    }

    pub async fn invoke(&mut self) {
        // Step 1: Sender broadcasts value and mvba key

        let _ = self.inner_pb.invoke().await;
        self.increment_pb();

        // Step 2: Sender broadcasts key proposal

        let key = self.inner_pb.invoke().await;
        self.key.replace(key);
        self.increment_pb();

        // Step 3: Sender broadcasts lock proposal

        let lock = self.inner_pb.invoke().await;
        self.lock.replace(lock);
        self.increment_pb();

        // Step 4: Sender broadcasts lock proposal

        let commit = self.inner_pb.invoke().await;
        self.commit.replace(commit);
    }

    pub fn abandon(&mut self) {
        self.inner_pb.abandon()
    }

    fn increment_pb(&mut self) {
        let PBID { id, step } = self.inner_pb.id;

        let new_id = PBID {
            id,
            step: FromPrimitive::from_u8(step as u8 + 1).expect("Expect step < 4"),
        };

        let new_pb = PBReceiver::init(
            new_id,
            self.index,
            self.signer,
            self.send_handle,
            &self.mvba,
        );

        self.inner_pb = new_pb;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PPID {
    pub(crate) inner: MVBAID,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
