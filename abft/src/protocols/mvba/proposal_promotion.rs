use std::{cmp::Ordering, fmt, sync::Arc};

use tokio::sync::{mpsc::error::SendError, RwLock};

use tokio::sync::Notify;

use crate::{messaging::ProtocolMessageSender, ABFTValue};

use super::{
    buffer::{MVBABufferCommand, MVBAReceiver},
    messages::{PBSendMessage, PBShareAckMessage},
    provable_broadcast::*,
    MvbaValue, MVBAID,
};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PPError {
    #[error("Not ready to handle PBShareAckMessage")]
    NotReadyForShareAck,
    #[error("Not ready to handle PBShareAckMessage")]
    NotReadyForSend,
    #[error("Received message with an earlier step: {0}, when current step is {1}")]
    ExpiredMessage(PPStatus, PPStatus),
    #[error(transparent)]
    PBError(#[from] PBError),
    #[error("Failed to compare step of message received")]
    FailedCompareStep,
    #[error("Failed to send MVBABufferCommand at PPReceiver")]
    BufferSender(#[from] SendError<MVBABufferCommand>),
    #[error("PPReceiver was abandoned")]
    Abandoned,
}

pub type PPResult<T> = Result<T, PPError>;

pub struct PPSender<V: ABFTValue> {
    id: PPID,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    key: RwLock<Option<PPProposal<V>>>,
    lock: RwLock<Option<PPProposal<V>>>,
    commit: RwLock<Option<PPProposal<V>>>,
    inner_pb: RwLock<Option<PBSender>>,
}

impl<V: ABFTValue> PPSender<V> {
    pub fn init(id: PPID, index: u32, f_tolerance: u32, n_parties: u32) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            key: RwLock::new(None),
            lock: RwLock::new(None),
            commit: RwLock::new(None),
            inner_pb: RwLock::new(None),
        }
    }

    pub async fn promote<F: ProtocolMessageSender>(
        &self,
        value: V,
        key: PBKey,
        signer: &Signer,
        send_handle: &F,
    ) -> PPResult<Option<PBSig>> {
        let mut proof_prev: Option<PBSig> = None;

        let mut proposal = PPProposal {
            value,
            proof: PBProof {
                key,
                proof_prev: None,
            },
        };

        // Step 1
        {
            self.init_pb(PPStatus::Step1).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().expect("PB instance should be initialized");
            proposal
                .proof
                .proof_prev
                .replace(pb.broadcast(proposal.clone(), signer, send_handle).await?);

            let mut _key = self.key.write().await;
            _key.replace(proposal.clone());
        }
        // Step 2
        {
            self.init_pb(PPStatus::Step2).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().expect("PB instance should be initialized");
            proposal
                .proof
                .proof_prev
                .replace(pb.broadcast(proposal.clone(), signer, send_handle).await?);

            let mut _lock = self.lock.write().await;
            _lock.replace(proposal.clone());
        }
        // Step 3
        {
            self.init_pb(PPStatus::Step3).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().expect("PB instance should be initialized");
            proposal
                .proof
                .proof_prev
                .replace(pb.broadcast(proposal.clone(), signer, send_handle).await?);

            let mut _commit = self.commit.write().await;
            _commit.replace(proposal.clone());
        }
        // Step 4
        {
            self.init_pb(PPStatus::Step4).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().expect("PB instance should be initialized");
            proof_prev.replace(pb.broadcast(proposal, signer, send_handle).await?);
        }

        Ok(proof_prev)
    }

    pub async fn on_share_ack(&self, index: u32, message: PBShareAckMessage) -> PPResult<()> {
        let inner_pb = self.inner_pb.read().await;
        if let Some(pb) = &*inner_pb {
            Self::check_step(&message, pb)?;

            pb.on_share_ack_message(index, message).await?;
        } else {
            return Err(PPError::NotReadyForShareAck);
        }
        Ok(())
    }

    fn check_step(message: &PBShareAckMessage, pb: &PBSender) -> PPResult<()> {
        match message.id.step.partial_cmp(&pb.id.step) {
            Some(Ordering::Equal) => Ok(()),
            Some(Ordering::Greater) => Err(PPError::NotReadyForSend),
            Some(Ordering::Less) => Err(PPError::ExpiredMessage(message.id.step, pb.id.step)),
            None => Err(PPError::FailedCompareStep),
        }
    }

    pub async fn result(&self) -> PPLeader<V> {
        let (key, lock, commit);

        {
            let mut _key = self.key.write().await;
            key = _key.take();
        }

        {
            let mut _lock = self.lock.write().await;
            lock = _lock.take();
        }

        {
            let mut _commit = self.commit.write().await;
            commit = _commit.take();
        }

        PPLeader { key, lock, commit }
    }

    async fn init_pb(&self, step: PPStatus) {
        let pb = PBSender::init(
            PBID { id: self.id, step },
            self.index,
            self.f_tolerance,
            self.n_parties,
        );

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(pb);
    }
}

#[derive(Default)]
pub struct PPReceiver<V: ABFTValue + MvbaValue> {
    id: PPID,
    index: u32,
    send_id: u32,
    f_tolerance: u32,
    n_parties: u32,
    key: RwLock<Option<PPProposal<V>>>,
    lock: RwLock<Option<PPProposal<V>>>,
    commit: RwLock<Option<PPProposal<V>>>,
    inner_pb: RwLock<Option<PBReceiver<V>>>,
    notify_abandon: Arc<Notify>,
}

impl<V: ABFTValue + MvbaValue> PPReceiver<V> {
    pub fn init(id: PPID, index: u32, f_tolerance: u32, n_parties: u32, send_id: u32) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,
            send_id,
            key: RwLock::new(None),
            lock: RwLock::new(None),
            commit: RwLock::new(None),
            inner_pb: RwLock::new(None),
            notify_abandon: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke<R: MVBAReceiver>(&self, recv_handle: &R) -> PPResult<()> {
        // Step 1: Sender broadcasts value and mvba key
        {
            self.init_pb(PPStatus::Step1).await;
            recv_handle
                .drain_pp_receive(self.id.inner.view, self.send_id)
                .await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().expect("PB instance should be initialized");
            let _ = self.invoke_or_abandon(pb).await?;
        }

        // Step 2: Sender broadcasts key proposal
        {
            self.init_pb(PPStatus::Step2).await;
            recv_handle
                .drain_pp_receive(self.id.inner.view, self.send_id)
                .await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().expect("PB instance should be initialized");
            let key = self.invoke_or_abandon(pb).await?;
            let mut _key = self.key.write().await;
            _key.replace(key);
        }

        // Step 3: Sender broadcasts lock proposal
        {
            self.init_pb(PPStatus::Step3).await;
            recv_handle
                .drain_pp_receive(self.id.inner.view, self.send_id)
                .await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().expect("PB instance should be initialized");
            let lock = self.invoke_or_abandon(pb).await?;
            let mut _lock = self.lock.write().await;
            _lock.replace(lock);
        }

        // Step 4: Sender broadcasts commit proposal
        {
            self.init_pb(PPStatus::Step4).await;
            recv_handle
                .drain_pp_receive(self.id.inner.view, self.send_id)
                .await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().expect("PB instance should be initialized");
            let commit = self.invoke_or_abandon(pb).await?;
            let mut _commit = self.commit.write().await;
            _commit.replace(commit);
        }
        Ok(())
    }

    pub async fn on_value_send_message<F: ProtocolMessageSender>(
        &self,
        index: u32,
        message: PBSendMessage<V>,
        id: &MVBAID,
        leader_index: u32,
        lock: u32,
        signer_mvba: &Signer,
        signer_prbc: &Signer,
        send_handle: &F,
    ) -> PPResult<()> {
        let inner_pb = self.inner_pb.read().await;

        if let Some(pb) = &*inner_pb {
            Self::check_step(&message, pb)?;

            pb.on_value_send_message(
                index,
                message,
                id,
                leader_index,
                lock,
                signer_mvba,
                signer_prbc,
                send_handle,
            )
            .await?;
        } else {
            return Err(PPError::NotReadyForSend);
        }
        Ok(())
    }

    fn check_step(message: &PBSendMessage<V>, pb: &PBReceiver<V>) -> PPResult<()> {
        match message.id.step.partial_cmp(&pb.id.step) {
            Some(Ordering::Equal) => Ok(()),
            Some(Ordering::Greater) => Err(PPError::NotReadyForSend),
            Some(Ordering::Less) => Err(PPError::ExpiredMessage(message.id.step, pb.id.step)),
            None => Err(PPError::FailedCompareStep),
        }
    }

    pub async fn result(&self) -> PPLeader<V> {
        let (key, lock, commit);

        {
            let mut _key = self.key.write().await;
            key = _key.take();
        }

        {
            let mut _lock = self.lock.write().await;
            lock = _lock.take();
        }

        {
            let mut _commit = self.commit.write().await;
            commit = _commit.take();
        }

        PPLeader { key, lock, commit }
    }

    pub async fn abandon(&self) {
        self.notify_abandon.notify_one();
    }

    pub async fn invoke_or_abandon(&self, pb: &PBReceiver<V>) -> PPResult<PPProposal<V>> {
        let notify_abandon = self.notify_abandon.clone();
        let proposal = tokio::select! {
            proposal = pb.invoke() => Some(proposal),
            _ = notify_abandon.notified() => {
                None
            },
        };

        let proposal = proposal.ok_or_else(|| PPError::Abandoned)?;

        Ok(proposal)
    }

    async fn init_pb(&self, step: PPStatus) {
        let id = PBID { id: self.id, step };

        let new_pb = PBReceiver::init(id, self.index, self.f_tolerance, self.n_parties);

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(new_pb);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct PPID {
    pub(crate) inner: MVBAID,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PPProposal<V: ABFTValue> {
    #[serde(deserialize_with = "V::deserialize")]
    pub(crate) value: V,
    pub(crate) proof: PBProof,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, PartialOrd, FromPrimitive)]
pub enum PPStatus {
    Step1,
    Step2,
    Step3,
    Step4,
}

pub struct PPLeader<V: ABFTValue> {
    pub key: Option<PPProposal<V>>,
    pub lock: Option<PPProposal<V>>,
    pub commit: Option<PPProposal<V>>,
}

impl fmt::Display for PPStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PPStatus::Step1 => {
                write!(f, "Step1")
            }
            PPStatus::Step2 => {
                write!(f, "Step2")
            }
            PPStatus::Step3 => {
                write!(f, "Step3")
            }
            PPStatus::Step4 => {
                write!(f, "Step4")
            }
        }
    }
}
