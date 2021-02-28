use std::{cmp::Ordering, fmt, sync::Arc};

use tokio::sync::{
    mpsc::{error::SendError, Sender},
    RwLock,
};

use tokio::sync::Notify;

use super::{
    buffer::MVBABufferCommand,
    messages::{MVBASender, PBSendMessage, PBShareAckMessage},
    provable_broadcast::*,
    Value, MVBAID,
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

pub struct PPSender {
    id: PPID,
    index: usize,
    n_parties: usize,
    key: RwLock<Option<PPProposal>>,
    lock: RwLock<Option<PPProposal>>,
    commit: RwLock<Option<PPProposal>>,
    inner_pb: RwLock<Option<PBSender>>,
}

impl PPSender {
    pub fn init(id: PPID, index: usize, n_parties: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            key: RwLock::new(None),
            lock: RwLock::new(None),
            commit: RwLock::new(None),
            inner_pb: RwLock::new(None),
        }
    }

    pub async fn promote<F: MVBASender>(
        &self,
        value: Value,
        key: PBKey,
        signer: &Signer,
        send_handle: &F,
    ) -> Option<PBSig> {
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
            self.init_pb(PPStatus::Step1, proposal.clone()).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().unwrap();
            proof_prev.replace(pb.broadcast(signer, send_handle).await);
            proposal.proof.proof_prev = proof_prev.clone();

            let mut _key = self.key.write().await;
            _key.replace(proposal.clone());
        }
        // Step 2
        {
            self.init_pb(PPStatus::Step2, proposal.clone()).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().unwrap();
            proof_prev.replace(pb.broadcast(signer, send_handle).await);
            proposal.proof.proof_prev = proof_prev.clone();

            let mut _lock = self.lock.write().await;
            _lock.replace(proposal.clone());
        }
        // Step 3
        {
            self.init_pb(PPStatus::Step3, proposal.clone()).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().unwrap();
            proof_prev.replace(pb.broadcast(signer, send_handle).await);
            proposal.proof.proof_prev = proof_prev.clone();

            let mut _commit = self.commit.write().await;
            _commit.replace(proposal.clone());
        }
        // Step 4
        {
            self.init_pb(PPStatus::Step4, proposal.clone()).await;
            let lock = self.inner_pb.read().await;
            let pb = lock.as_ref().unwrap();
            proof_prev.replace(pb.broadcast(signer, send_handle).await);
        }

        proof_prev
    }

    pub async fn on_share_ack(
        &self,
        index: usize,
        message: PBShareAckMessage,
        signer: &Signer,
    ) -> PPResult<()> {
        let inner_pb = self.inner_pb.read().await;
        if let Some(pb) = &*inner_pb {
            pb.on_share_ack_message(index, message, signer).await?;
        } else {
            return Err(PPError::NotReadyForShareAck);
        }
        Ok(())
    }

    pub async fn result(&self) -> PPLeader {
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

    async fn init_pb(&self, step: PPStatus, proposal: PPProposal) {
        let pb = PBSender::init(
            PBID { id: self.id, step },
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
    send_id: usize,
    key: RwLock<Option<PPProposal>>,
    lock: RwLock<Option<PPProposal>>,
    commit: RwLock<Option<PPProposal>>,
    inner_pb: RwLock<Option<PBReceiver>>,
    notify_abandon: Arc<Notify>,
}

impl PPReceiver {
    pub fn init(id: PPID, index: usize, send_id: usize) -> Self {
        Self {
            id,
            index,
            send_id,
            key: RwLock::new(None),
            lock: RwLock::new(None),
            commit: RwLock::new(None),
            inner_pb: RwLock::new(None),
            notify_abandon: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke(&self, buff_handle: Sender<MVBABufferCommand>) -> PPResult<()> {
        // Step 1: Sender broadcasts value and mvba key
        {
            self.init_pb(PPStatus::Step1).await;
            self.drain_buffer(&buff_handle).await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let _ = self.invoke_or_abandon(pb).await?;
        }

        // Step 2: Sender broadcasts key proposal
        {
            self.init_pb(PPStatus::Step2).await;
            self.drain_buffer(&buff_handle).await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let key = self.invoke_or_abandon(pb).await?;
            let mut _key = self.key.write().await;
            _key.replace(key);
        }

        // Step 3: Sender broadcasts lock proposal
        {
            self.init_pb(PPStatus::Step3).await;
            self.drain_buffer(&buff_handle).await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let lock = self.invoke_or_abandon(pb).await?;
            let mut _lock = self.lock.write().await;
            _lock.replace(lock);
        }

        // Step 4: Sender broadcasts commit proposal
        {
            self.init_pb(PPStatus::Step4).await;
            self.drain_buffer(&buff_handle).await?;

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let commit = self.invoke_or_abandon(pb).await?;
            let mut _commit = self.commit.write().await;
            _commit.replace(commit);
        }
        Ok(())
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
    ) -> PPResult<()> {
        let inner_pb = self.inner_pb.read().await;

        if let Some(pb) = &*inner_pb {
            Self::check_step(&message, pb)?;

            pb.on_value_send_message(index, message, id, leader_index, lock, signer, send_handle)
                .await?;
        } else {
            return Err(PPError::NotReadyForSend);
        }
        Ok(())
    }

    fn check_step(message: &PBSendMessage, pb: &PBReceiver) -> PPResult<()> {
        match message.id.step.partial_cmp(&pb.id.step) {
            Some(Ordering::Equal) => Ok(()),
            Some(Ordering::Greater) => Err(PPError::NotReadyForSend),
            Some(Ordering::Less) => Err(PPError::ExpiredMessage(message.id.step, pb.id.step)),
            None => Err(PPError::FailedCompareStep),
        }
    }

    pub async fn result(&self) -> PPLeader {
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

    pub async fn invoke_or_abandon(&self, pb: &PBReceiver) -> PPResult<PPProposal> {
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

        let new_pb = PBReceiver::init(id, self.index);

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(new_pb);
    }

    async fn drain_buffer(&self, buff_handle: &Sender<MVBABufferCommand>) -> PPResult<()> {
        buff_handle
            .send(MVBABufferCommand::PPReceive {
                send_id: self.send_id,
                view: self.id.inner.view,
            })
            .await?;

        Ok(())
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
    Step1,
    Step2,
    Step3,
    Step4,
}

pub struct PPLeader {
    pub key: Option<PPProposal>,
    pub lock: Option<PPProposal>,
    pub commit: Option<PPProposal>,
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
