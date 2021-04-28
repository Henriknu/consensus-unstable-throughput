use consensus_core::crypto::{
    sign::{Signature, SignatureShare, Signer},
    SignatureIdentifier,
};
use log::{error, warn};

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, Notify};

use bincode::serialize;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{messaging::ProtocolMessageSender, ABFTValue};

use super::{
    messages::{PBSendMessage, PBShareAckMessage},
    proposal_promotion::{PPProposal, PPStatus, PPID},
    MvbaValue, MVBAID,
};

type PBResult<T> = Result<T, PBError>;

#[derive(Error, Debug)]
pub enum PBError {
    #[error("Got invalid signature for ShareAck Message")]
    InvalidShareAckSignature,
    #[error("Got invalid value proposed, for step: {0}")]
    InvalidValueProposed(usize),
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
    pub id: PBID,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    notify_shares: Arc<Notify>,
    shares: Mutex<BTreeMap<usize, PBSigShare>>,
}

impl PBSender {
    pub fn init(id: PBID, index: u32, f_tolerance: u32, n_parties: u32) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            notify_shares: Arc::new(Notify::new()),

            shares: Default::default(),
        }
    }

    pub async fn broadcast<F: ProtocolMessageSender, V: ABFTValue>(
        &self,
        proposal: PPProposal<V>,
        signer: &Signer,
        send_handle: &F,
    ) -> PBResult<PBSig> {
        //send <ID, SEND, value, proof> to all parties

        let pb_send = PBSendMessage::new(self.id, proposal.clone());

        send_handle
            .broadcast(
                self.id.id.inner.id,
                self.index,
                self.n_parties,
                self.id.id.inner.view,
                0,
                pb_send,
            )
            .await;

        // wait for n - f shares

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        // deliver proof of value being broadcasted

        let mut lock = self.shares.lock().await;

        let shares = std::mem::take(&mut *lock)
            .into_iter()
            .map(|(index, share)| (index, share.inner))
            .collect();

        drop(lock);

        let identifier = SignatureIdentifier::new(self.id.step as usize + 1, self.index as usize);

        let signature = signer.combine_signatures(&shares, &identifier);

        let response = PBResponse {
            id: self.id,
            value: proposal.value.clone(),
        };

        if !signer.verify_signature(&signature, &serialize(&response).unwrap()) {
            error!("Party {} got invalid when promoting proposal.", self.index,);

            panic!()
        }

        Ok(PBSig { inner: signature })
    }

    pub async fn on_share_ack_message(
        &self,
        index: u32,
        message: PBShareAckMessage,
    ) -> PBResult<()> {
        let share = message.share;

        let mut shares = self.shares.lock().await;

        shares.insert(index as usize, share);

        if shares.len() >= (self.n_parties - self.f_tolerance) as usize {
            self.notify_shares.notify_one();
        }

        Ok(())
    }
}

pub struct PBReceiver<V: ABFTValue + MvbaValue> {
    pub id: PBID,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    should_stop: AtomicBool,
    proposal: Mutex<Option<PPProposal<V>>>,
    notify_proposal: Arc<Notify>,
}

impl<V: ABFTValue + MvbaValue> PBReceiver<V> {
    pub fn init(id: PBID, index: u32, f_tolerance: u32, n_parties: u32) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            should_stop: AtomicBool::new(false),
            proposal: Mutex::new(None),
            notify_proposal: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke(&self) -> PPProposal<V> {
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
        index: u32,
        message: PBSendMessage<V>,
        mvba_id: &MVBAID,
        leader_index: u32,
        lock: u32,
        signer_mvba: &Signer,
        signer_prbc: &Signer,
        send_handle: &F,
    ) -> PBResult<()> {
        let proposal = message.proposal;

        if !self.should_stop.load(Ordering::Relaxed)
            && self.evaluate_pb_val(
                &proposal,
                message.id,
                mvba_id,
                leader_index,
                lock,
                signer_mvba,
                signer_prbc,
            )?
        {
            self.should_stop.store(true, Ordering::Relaxed);

            let response = PBResponse {
                id: message.id,
                value: proposal.value.clone(),
            };

            let identifier = SignatureIdentifier::new(message.id.step as usize + 1, index as usize);

            let inner = signer_mvba.sign(
                &serialize(&response).expect("Could not serialize message for on_value_send"),
                &identifier,
            );

            let pb_ack = PBShareAckMessage::new(self.id, PBSigShare { inner });

            send_handle
                .send(
                    self.id.id.inner.id,
                    self.index,
                    index,
                    self.id.id.inner.view,
                    0,
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
        proposal: &PPProposal<V>,
        message_id: PBID,
        mvba_id: &MVBAID,
        leader_index: u32,
        lock: u32,
        signer_mvba: &Signer,
        signer_prbc: &Signer,
    ) -> PBResult<bool> {
        let step = message_id.step;
        let PBProof { key, proof_prev } = &proposal.proof;

        // If first step, verify that the key provided is valid
        if step == PPStatus::Step1
            && self.check_key(
                &proposal.value,
                key,
                mvba_id,
                leader_index,
                lock,
                signer_mvba,
                signer_prbc,
            )?
        {
            return Ok(true);
        }

        let response_prev = PBResponse {
            id: PBID {
                id: message_id.id,
                step: FromPrimitive::from_u8(message_id.step as u8 - 1).expect("Expect step > 1"),
            },
            value: proposal.value.clone(),
        };

        // If later step, verify that the proof provided is valid for the previous step.
        if step > PPStatus::Step1
            && proof_prev.is_some()
            && signer_mvba.verify_signature(
                &proof_prev.as_ref().unwrap().inner,
                &serialize(&response_prev)
                    .expect("Could not serialize response_prev for evaluate_pb_val"),
            )
        {
            return Ok(true);
        }

        Err(PBError::InvalidValueProposed(step as usize + 1))
    }

    fn check_key(
        &self,
        value: &V,
        key: &PBKey,
        id: &MVBAID,
        leader_index: u32,
        lock: u32,
        signer_mvba: &Signer,
        signer_prbc: &Signer,
    ) -> PBResult<bool> {
        // Check that value is valid high-level application
        if !value.eval_mvba(id.id, self.f_tolerance, self.n_parties, signer_prbc) {
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
            value: value.clone(),
        };

        // Verify the validity of the key provided
        if *view != 0
            && (view_key_proof.is_none()
                || !signer_mvba.verify_signature(
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
pub struct PBResponse<V: ABFTValue> {
    pub(crate) id: PBID,
    #[serde(deserialize_with = "V::deserialize")]
    pub(crate) value: V,
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
    pub(crate) view: u32,
    pub(crate) view_key_proof: Option<PBSig>,
}
