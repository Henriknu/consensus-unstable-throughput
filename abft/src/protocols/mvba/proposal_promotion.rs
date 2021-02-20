use super::{messages::ProtocolMessage, provable_broadcast::*, Value, MVBAID};
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

pub struct PPReceiver {
    key: Option<PPProposal>,
    lock: Option<PPProposal>,
    commit: Option<PPProposal>,
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
