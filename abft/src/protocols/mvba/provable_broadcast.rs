use consensus_core::crypto::sign::{Signature, SignatureShare, Signer};

use std::sync::Arc;
use tokio::sync::Notify;

use bincode::serialize;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use super::{
    proposal_promotion::{PPProposal, PPStatus, PPID},
    Value, MVBA, MVBAID,
};

type PBMessage = PPProposal;

pub struct PBSender<'s, F: Fn(usize, &PBMessage)> {
    id: PBID,
    n_parties: usize,
    notify_shares: Arc<Notify>,
    signer: &'s Signer,
    message: &'s PBMessage,
    shares: Vec<PBSigShare>,
    send_handle: &'s F,
}

impl<'s, F: Fn(usize, &PBMessage)> PBSender<'s, F> {
    pub fn init(
        id: PBID,
        n_parties: usize,
        signer: &'s Signer,
        message: &'s PPProposal,
        send_handle: &'s F,
    ) -> Self {
        Self {
            id,
            n_parties,
            notify_shares: Arc::new(Notify::new()),
            signer,
            message,
            shares: Default::default(),
            send_handle,
        }
    }

    pub async fn broadcast(&mut self) -> PBSig {
        //send <ID, SEND, value, proof> to all parties

        for i in 0..self.n_parties {
            (self.send_handle)(i, &self.message);
        }

        // wait for n - f shares

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        // deliver proof of value being broadcasted

        self.deliver()
    }

    pub fn on_share_ack(&mut self, index: usize, share: PBSigShare) {
        if self.signer.verify_share(
            index,
            &share.inner,
            &serialize(&self.message).expect("Could not serialize PB message for ack"),
        ) {
            self.shares.push(share);
        }

        if self.shares.len() == (self.n_parties * 2 / 3) + 1 {
            self.notify_shares.notify_one();
        }
    }

    pub fn deliver(&mut self) -> PBSig {
        let shares = self
            .shares
            .iter()
            .enumerate()
            .map(|(index, share)| (index, share.inner.clone()))
            .collect();

        let signature = self.signer.combine_signatures(&shares).unwrap();

        PBSig { inner: signature }
    }
}

#[derive(Clone)]
pub struct PBReceiver<'s, F: Fn(usize, &PBMessage)> {
    id: PBID,
    signer: &'s Signer,
    should_stop: bool,
    message: Option<PBMessage>,
    mvba: &'s MVBA<F>,
}

impl<'s, F: Fn(usize, &PBMessage)> PBReceiver<'s, F> {
    pub fn init(id: PBID, signer: &'s Signer, mvba: &'s MVBA<F>) -> Self {
        Self {
            id,
            signer,
            should_stop: false,
            message: None,
            mvba,
        }
    }

    pub fn on_value_send(&mut self, message: PBMessage, send_handle: &dyn Fn(PBID, PBSigShare)) {
        if !self.should_stop && self.evaluate_pb_val(&message) {
            self.abandon();
            let response = PBResponse {
                id: self.id,
                value: message.value,
            };

            let inner = self.signer.sign(
                &serialize(&response).expect("Could not serialize message for on_value_send"),
            );
            send_handle(self.id, PBSigShare { inner });
            self.message.replace(message);
        }
    }

    fn evaluate_pb_val(&self, message: &PBMessage) -> bool {
        let PBID { id, step } = self.id;
        let PBProof { key, proof_prev } = &message.proof;

        // If first step, verify that the key provided is valid
        if step == PPStatus::Step1 && self.check_key(&message.value, key) {
            return true;
        }

        let response_prev = PBResponse {
            id: PBID {
                id,
                step: FromPrimitive::from_u8(step as u8 - 1).expect("Expect step > 1"),
            },
            value: message.value,
        };

        // If later step, verify that the proof provided is valid for the previous step.
        if step > PPStatus::Step1
            && proof_prev.is_some()
            && self.signer.verify_signature(
                &proof_prev.as_ref().unwrap().inner,
                &serialize(&response_prev)
                    .expect("Could not serialize response_prev for evaluate_pb_val"),
            )
        {
            return true;
        }

        false
    }

    fn check_key(&self, value: &Value, key: &PBKey) -> bool {
        // Check that value is valid high-level application
        if !eval_mvba_val(value) {
            return false;
        }

        let PBKey {
            view,
            view_key_proof,
        } = key;

        let view_key = PBResponse {
            id: PBID {
                id: PPID {
                    inner: MVBAID {
                        id: self.mvba.id.id,
                        index: self.mvba.leaders[*view].unwrap(),
                        view: *view,
                    },
                },
                step: PPStatus::Step1,
            },
            value: *value,
        };

        // Verify the validity of the key provided
        if *view != 1
            && (view_key_proof.is_none()
                || !self.signer.verify_signature(
                    &view_key_proof.as_ref().unwrap().inner,
                    &serialize(&view_key).expect("Could not serialize view_key for check_key"),
                ))
        {
            return false;
        }

        // Verify that the key was not obtained in an earlier view than what is currently locked
        if view < &self.mvba.LOCK {
            return false;
        }

        true
    }
    pub fn abandon(&mut self) {
        self.should_stop = true;
    }
}

fn eval_mvba_val(value: &Value) -> bool {
    todo!()
}

pub struct PBSigShare {
    inner: SignatureShare,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PBID {
    pub(crate) id: PPID,
    pub(crate) step: PPStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBResponse {
    pub(crate) id: PBID,
    pub(crate) value: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBSig {
    pub(crate) inner: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBProof {
    pub(crate) key: PBKey,
    pub(crate) proof_prev: Option<PBSig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBKey {
    pub(crate) view: usize,
    pub(crate) view_key_proof: Option<PBSig>,
}
