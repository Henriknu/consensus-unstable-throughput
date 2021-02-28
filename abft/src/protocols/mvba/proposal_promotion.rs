use std::{cmp::Ordering, fmt, marker::PhantomData, sync::Arc};

use log::{debug, info};
use tokio::sync::{Mutex, RwLock};

use super::{
    error::{MVBAError, MVBAResult},
    messages::{MVBABuffer, MVBASender, PBSendMessage, PBShareAckMessage, ProtocolMessage},
    provable_broadcast::*,
    Key, Value, MVBA, MVBAID,
};
use consensus_core::crypto::sign::Signer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
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
}

pub type PPResult<T> = Result<T, PPError>;

pub struct PPSender {
    id: PPID,
    index: usize,
    n_parties: usize,
    key: RwLock<Option<PPProposal>>,
    lock: RwLock<Option<PPProposal>>,
    commit: RwLock<Option<PPProposal>>,
    proof: Option<PBSig>,
    inner_pb: RwLock<Option<PBSender>>,
}

impl PPSender {
    pub fn init(id: PPID, index: usize, n_parties: usize) -> Self {
        Self {
            id,
            index,
            n_parties,
            proof: None,
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
        // proof_prev = null
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
        debug!(
            "Calling PPSender::on_share_ack for Party {} on message from Party {}",
            self.index, index
        );
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
        }
    }

    pub async fn invoke<F: MVBASender + Sync + Send>(
        &self,
        buff_handle: Arc<Mutex<MVBABuffer<F>>>,
    ) {
        // Step 1: Sender broadcasts value and mvba key
        {
            self.init_pb(PPStatus::Step1).await;
            self.drain_messages(&buff_handle);

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let _ = pb.invoke().await;
        }

        // Step 2: Sender broadcasts key proposal
        {
            self.init_pb(PPStatus::Step2).await;
            self.drain_messages(&buff_handle);

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let key = pb.invoke().await;
            let mut _key = self.key.write().await;
            _key.replace(key);
        }

        // Step 3: Sender broadcasts lock proposal
        {
            self.init_pb(PPStatus::Step3).await;
            self.drain_messages(&buff_handle);

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let lock = pb.invoke().await;
            let mut _lock = self.lock.write().await;
            _lock.replace(lock);
        }

        // Step 4: Sender broadcasts commit proposal
        {
            self.init_pb(PPStatus::Step4).await;
            self.drain_messages(&buff_handle);

            let pb_lock = self.inner_pb.read().await;
            let pb = pb_lock.as_ref().unwrap();
            let commit = pb.invoke().await;
            let mut _commit = self.commit.write().await;
            _commit.replace(commit);
        }
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
        debug!(
            "Calling PPReceiver::on_value_send_message for Party {} on message from Party {}",
            self.index, index
        );

        debug!(
            "Grabbing lock at PPReceiver::on_value_send_message for Party {}",
            self.index
        );

        let inner_pb = self.inner_pb.read().await;

        if let Some(pb) = &*inner_pb {
            Self::check_step(&message, pb)?;

            pb.on_value_send_message(index, message, id, leader_index, lock, signer, send_handle)
                .await?;
        } else {
            debug!(
                "Did not find PBReceiver instance on PPReceiver::on_value_send_message for Party {} on message from Party {}",
                self.index, index
            );
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
        let mut inner_pb = self.inner_pb.write().await;

        if let Some(_) = &mut *inner_pb {
            *inner_pb = None;
        }
    }

    async fn init_pb(&self, step: PPStatus) {
        debug!(
            "Initializing PBReceiver with step {} for Party {}",
            step, self.index,
        );

        let id = PBID { id: self.id, step };

        let new_pb = PBReceiver::init(id, self.index);

        let mut inner_pb = self.inner_pb.write().await;

        inner_pb.replace(new_pb);

        debug!(
            "Succesfully Initialized PBReceiver with step {} for Party {}",
            step, self.index,
        );
    }

    async fn drain_messages<F: MVBASender + Sync + Send>(
        &self,
        buff_handle: &Arc<Mutex<MVBABuffer<F>>>,
    ) {
        let mut buff_lock = buff_handle.lock().await;
        buff_lock.drain_pp_recv(self.send_id, self.id.inner.view);
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
