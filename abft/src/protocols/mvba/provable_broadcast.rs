use consensus_core::crypto::sign::{Signature, SignatureShare, Signer};
use log::warn;

use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, Notify};

use bincode::serialize;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::messaging::ProtocolMessageSender;

use super::{
    messages::{PBSendMessage, PBShareAckMessage},
    proposal_promotion::{PPProposal, PPStatus, PPID},
    Value, MVBAID,
};

type PBResult<T> = Result<T, PBError>;

#[derive(Error, Debug)]
pub enum PBError {
    #[error("Got invalid signature for ShareAck Message")]
    InvalidShareAckSignature,
    #[error("Got invalid value proposed")]
    InvalidValueProposed,
    #[error("Key provided with proposal was invalid")]
    InvalidKeyIncluded,
    #[error("Key provided with proposal was older than current lock")]
    ExpiredKeyIncluded,
    #[error("Value failed external validation checked")]
    FailedExternalValidation,
    #[error(
        "Invariant broken when combining signatures (too few shares or invalid index supplied)"
    )]
    CryptoError,
}

pub struct PBSender {
    id: PBID,
    index: usize,
    n_parties: usize,
    notify_shares: Arc<Notify>,
    proposal: PPProposal,
    shares: Mutex<BTreeMap<usize, PBSigShare>>,
}

impl PBSender {
    pub fn init(id: PBID, index: usize, n_parties: usize, proposal: PPProposal) -> Self {
        Self {
            id,
            index,
            n_parties,
            notify_shares: Arc::new(Notify::new()),
            proposal,
            shares: Default::default(),
        }
    }

    pub async fn broadcast<F: ProtocolMessageSender>(
        &self,
        signer: &Signer,
        send_handle: &F,
    ) -> PBResult<PBSig> {
        //send <ID, SEND, value, proof> to all parties

        let pb_send = PBSendMessage::new(self.id, self.proposal.clone());

        send_handle
            .broadcast(
                self.id.id.inner.id,
                self.index,
                self.n_parties,
                self.id.id.inner.view,
                pb_send,
            )
            .await;

        // wait for n - f shares

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        // deliver proof of value being broadcasted

        let lock = self.shares.lock().await;

        let shares = lock
            .iter()
            .map(|(index, share)| (*index, share.inner.clone()))
            .collect();

        drop(lock);

        let signature = signer
            .combine_signatures(&shares)
            .map_err(|_| PBError::CryptoError)?;

        Ok(PBSig { inner: signature })
    }

    pub async fn on_share_ack_message(
        &self,
        index: usize,
        message: PBShareAckMessage,
        signer: &Signer,
    ) -> PBResult<()> {
        let share = message.share;

        let response = PBResponse {
            id: self.id,
            value: self.proposal.value,
        };

        let mut shares = self.shares.lock().await;

        if signer.verify_share(
            index,
            &share.inner,
            &serialize(&response).expect("Could not serialize PB message for ack"),
        ) {
            shares.insert(index, share);
        } else {
            return Err(PBError::InvalidShareAckSignature);
        }

        if shares.len() >= (self.n_parties * 2 / 3) + 1 {
            self.notify_shares.notify_one();
        }

        Ok(())
    }
}

pub struct PBReceiver {
    pub id: PBID,
    index: usize,
    should_stop: Mutex<bool>,
    proposal: Mutex<Option<PPProposal>>,
    notify_proposal: Arc<Notify>,
}

impl PBReceiver {
    pub fn init(id: PBID, index: usize) -> Self {
        Self {
            id,
            index,
            should_stop: Mutex::new(false),
            proposal: Mutex::new(None),
            notify_proposal: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke(&self) -> PPProposal {
        // wait for a valid proposal to arrive

        let notify_proposal = self.notify_proposal.clone();

        notify_proposal.notified().await;

        // deliver proposal received

        let mut proposal = self.proposal.lock().await;

        proposal
            .take()
            .expect("Proposal has been validated on arrival")
    }

    pub async fn on_value_send_message<F: ProtocolMessageSender>(
        &self,
        index: usize,
        message: PBSendMessage,
        mvba_id: &MVBAID,
        leader_index: usize,
        lock: usize,
        signer: &Signer,
        send_handle: &F,
    ) -> PBResult<()> {
        let proposal = message.proposal;

        let mut should_stop = self.should_stop.lock().await;

        if !*should_stop
            && self.evaluate_pb_val(&proposal, message.id, mvba_id, leader_index, lock, signer)?
        {
            *should_stop = true;
            drop(should_stop);
            let response = PBResponse {
                id: message.id,
                value: proposal.value,
            };

            let inner = signer.sign(
                &serialize(&response).expect("Could not serialize message for on_value_send"),
            );

            let pb_ack = PBShareAckMessage::new(self.id, PBSigShare { inner });

            send_handle
                .send(
                    self.id.id.inner.id,
                    self.index,
                    index,
                    self.id.id.inner.view,
                    pb_ack,
                )
                .await;

            let mut prev_proposal = self.proposal.lock().await;

            prev_proposal.replace(proposal);

            self.notify_proposal.notify_one();
        }
        Ok(())
    }

    fn evaluate_pb_val(
        &self,
        proposal: &PPProposal,
        message_id: PBID,
        mvba_id: &MVBAID,
        leader_index: usize,
        lock: usize,
        signer: &Signer,
    ) -> PBResult<bool> {
        let step = message_id.step;
        let PBProof { key, proof_prev } = &proposal.proof;

        // If first step, verify that the key provided is valid
        if step == PPStatus::Step1
            && self.check_key(&proposal.value, key, mvba_id, leader_index, lock, signer)?
        {
            return Ok(true);
        }

        let response_prev = PBResponse {
            id: PBID {
                id: message_id.id,
                step: FromPrimitive::from_u8(message_id.step as u8 - 1).expect("Expect step > 1"),
            },
            value: proposal.value,
        };

        // If later step, verify that the proof provided is valid for the previous step.
        if step > PPStatus::Step1
            && proof_prev.is_some()
            && signer.verify_signature(
                &proof_prev.as_ref().unwrap().inner,
                &serialize(&response_prev)
                    .expect("Could not serialize response_prev for evaluate_pb_val"),
            )
        {
            return Ok(true);
        }

        Err(PBError::InvalidValueProposed)
    }

    fn check_key(
        &self,
        value: &Value,
        key: &PBKey,
        id: &MVBAID,
        leader_index: usize,
        lock: usize,
        signer: &Signer,
    ) -> PBResult<bool> {
        // Check that value is valid high-level application
        if !eval_mvba_val(value) {
            return Err(PBError::FailedExternalValidation);
        }

        let PBKey {
            view,
            view_key_proof,
        } = key;

        let view_key = PBResponse {
            id: PBID {
                id: PPID {
                    inner: MVBAID {
                        id: id.id,
                        index: leader_index,
                        view: *view,
                    },
                },
                step: PPStatus::Step1,
            },
            value: *value,
        };

        // Verify the validity of the key provided
        if *view != 0
            && (view_key_proof.is_none()
                || !signer.verify_signature(
                    &view_key_proof.as_ref().unwrap().inner,
                    &serialize(&view_key).expect("Could not serialize view_key for check_key"),
                ))
        {
            warn!("Returning false for PBReceiver::check_key for Party {} because view: {} != 1 and key was not valid", self.index,view);
            return Err(PBError::InvalidKeyIncluded);
        }

        // Verify that the key was not obtained in an earlier view than what is currently locked
        if view < &lock {
            warn!("Returning false for PBReceiver::check_key for Party {} because key was gotten in earlier view: {} than lock: {}", self.index, view, lock);
            return Err(PBError::ExpiredKeyIncluded);
        }

        Ok(true)
    }
}

fn eval_mvba_val(_value: &Value) -> bool {
    //TODO
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PBProof {
    pub(crate) key: PBKey,
    pub(crate) proof_prev: Option<PBSig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PBKey {
    pub(crate) view: usize,
    pub(crate) view_key_proof: Option<PBSig>,
}
