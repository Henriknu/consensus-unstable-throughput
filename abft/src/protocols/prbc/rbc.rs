use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bincode::{deserialize, serialize, Error as BincodeError};
use consensus_core::crypto::{
    hash::{Hashable, H256},
    merkle::{get_branch, verify_branch, MerkleTree},
};
use consensus_core::erasure::{ErasureCoder, ErasureCoderError, NonZeroUsize};
use log::{info, warn};
use thiserror::Error;
use tokio::sync::{Notify, RwLock};

use crate::{messaging::ProtocolMessageSender, Value};

use super::messages::{RBCEchoMessage, RBCReadyMessage, RBCValueMessage};

pub type RBCResult<T> = Result<T, RBCError>;

pub struct RBC {
    id: usize,
    index: usize,
    n_parties: usize,
    erasure: RwLock<ErasureCoder>,
    echo_messages: RwLock<BTreeMap<H256, BTreeMap<usize, RBCEchoMessage>>>,
    ready_messages: RwLock<BTreeMap<H256, BTreeMap<usize, RBCReadyMessage>>>,
    notify_echo: Arc<Notify>,
    notify_ready: Arc<Notify>,
    has_sent_ready: AtomicBool,
}

impl RBC {
    pub fn init(id: usize, index: usize, n_parties: usize) -> RBCResult<Self> {
        Ok(Self {
            id,
            index,
            n_parties,
            erasure: RwLock::new(ErasureCoder::new(
                NonZeroUsize::new(n_parties * 2 / 3).ok_or_else(|| RBCError::ZeroUsize)?,
                NonZeroUsize::new(n_parties / 3 + 1).ok_or_else(|| RBCError::ZeroUsize)?,
            )?),
            echo_messages: Default::default(),
            ready_messages: Default::default(),
            notify_echo: Arc::new(Notify::new()),
            notify_ready: Arc::new(Notify::new()),
            has_sent_ready: AtomicBool::new(false),
        })
    }

    pub async fn invoke<F: ProtocolMessageSender>(
        &self,
        value: Option<Value>,
        send_handle: &F,
    ) -> RBCResult<Value> {
        if let Some(value) = value {
            self.broadcast_value(value, send_handle).await?;
        }

        let notify_ready = self.notify_ready.clone();

        notify_ready.notified().await;

        info!(
            "Party {} done waiting on receiving ready messages. ",
            self.index
        );

        let notify_echo = self.notify_echo.clone();

        notify_echo.notified().await;

        info!(
            "Party {} done waiting on receiving echo messages. ",
            self.index
        );

        let value = self.decode_value().await?;

        info!("Party {} decoded the value to be: {:?} ", self.index, value,);

        Ok(value)
    }

    pub async fn on_value_message<F: ProtocolMessageSender>(
        &self,
        message: RBCValueMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        let echo_message =
            RBCEchoMessage::new(self.index, message.root, message.fragment, message.branch);

        send_handle
            .broadcast(self.id, self.index, self.n_parties, 0, echo_message)
            .await;

        Ok(())
    }

    pub async fn on_echo_message<F: ProtocolMessageSender>(
        &self,
        message: RBCEchoMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        if !verify_branch(
            &message.root,
            &message.fragment.hash(),
            message.index,
            self.n_parties,
            &message.branch,
        ) {
            warn!(
                "Party {} received invalid branch on index: {}",
                self.index, message.index
            );
            return Ok(());
        }

        let n_echo_messages;
        let root = message.root;

        {
            let mut lock = self.echo_messages.write().await;

            if !lock
                .entry(message.root)
                .or_default()
                .contains_key(&message.index)
            {
                lock.entry(message.root).and_modify(|map| {
                    map.insert(message.index, message);
                });
            }
            n_echo_messages = lock.entry(root).or_default().len();
        }

        if n_echo_messages >= (self.n_parties / 3 + 1) {
            self.notify_echo.notify_one();
        }

        if n_echo_messages >= (self.n_parties * 2 / 3 + 1)
            && !self.has_sent_ready.load(Ordering::SeqCst)
        {
            let blocks = self.reconstruct_blocks_with_root(root).await?;

            let merkle2 = MerkleTree::new(&blocks);

            {
                if *merkle2.root() != root {
                    return Err(RBCError::InvalidMerkleRootConstructed);
                }
            }

            let ready_message = RBCReadyMessage::new(*merkle2.root());

            send_handle
                .broadcast(self.id, self.index, self.n_parties, 0, ready_message)
                .await;

            self.has_sent_ready.store(true, Ordering::SeqCst);
        }

        Ok(())
    }

    pub async fn on_ready_message<F: ProtocolMessageSender>(
        &self,
        index: usize,
        message: RBCReadyMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        let root = message.root;
        let n_ready_messages;

        {
            let mut lock = self.ready_messages.write().await;

            if !lock.entry(message.root).or_default().contains_key(&index) {
                lock.entry(message.root).or_default().insert(index, message);
            }

            n_ready_messages = lock.entry(root).or_default().len();
        }

        if n_ready_messages >= (self.n_parties / 3 + 1)
            && !self.has_sent_ready.load(Ordering::SeqCst)
        {
            let ready_message = RBCReadyMessage::new(root);

            send_handle
                .broadcast(self.id, self.index, self.n_parties, 0, ready_message)
                .await;

            self.has_sent_ready.store(true, Ordering::SeqCst);
        }

        if n_ready_messages >= (self.n_parties * 2 / 3 + 1) {
            self.notify_ready.notify_one();
        }

        Ok(())
    }

    async fn broadcast_value<F: ProtocolMessageSender>(
        &self,
        value: Value,
        send_handle: &F,
    ) -> RBCResult<()> {
        let erasure = self.erasure.write().await;

        let fragments = erasure.encode(&serialize(&value)?);

        assert_eq!(fragments.len(), self.n_parties);

        let merkle = MerkleTree::new(&fragments);

        let mut fragments = fragments.into_iter();

        info!(
            "Party {} broadcasts value: {:?} in PRBC with root: {}",
            self.index,
            value,
            merkle.root()
        );

        for j in 0..self.n_parties {
            let fragment = fragments
                .next()
                .ok_or_else(|| RBCError::FaultyNumberOfErasureBlocks)?;

            let message = RBCValueMessage::new(*merkle.root(), fragment, get_branch(&merkle, j));
            if j != self.index {
                send_handle.send(self.id, self.index, j, 0, message).await;
            } else {
                self.on_value_message(message, send_handle).await?;
            }
        }

        Ok(())
    }

    async fn reconstruct_blocks_with_root(&self, root: H256) -> RBCResult<Vec<Vec<u8>>> {
        // want to reconstruct whatever blocks sent out which have not been
        let mut lock = self.echo_messages.write().await;
        let erasure = self.erasure.write().await;

        let root_map = lock.entry(root).or_default();

        let mut erasures = Vec::<i32>::with_capacity(self.n_parties);

        for i in 0..self.n_parties {
            if !root_map.contains_key(&i) {
                erasures.push(i as i32);
            }
        }

        let fragments = root_map
            .iter()
            .map(|(_, message)| message.fragment.clone())
            .collect::<Vec<Vec<u8>>>();

        let fragments = erasure.reconstruct(&fragments, erasures)?;

        Ok(fragments)
    }

    async fn decode_value(&self) -> RBCResult<Value> {
        let root = self.get_ready_root().await?;

        let fragments: Vec<Vec<u8>>;
        let mut erasures = Vec::<i32>::with_capacity(self.n_parties);

        {
            let lock = self.echo_messages.read().await;

            let root_map = lock.get(&root).ok_or_else(|| RBCError::NoReadyRootFound)?;

            for i in 0..self.n_parties {
                if !root_map.contains_key(&i) {
                    erasures.push(i as i32);
                }
            }

            fragments = lock
                .get(&root)
                .ok_or_else(|| RBCError::NoReadyRootFound)?
                .values()
                .map(|message| message.fragment.clone())
                .collect();
        }

        let erasure = self.erasure.write().await;

        let bytes = erasure.decode(&fragments, erasures)?;

        let value: Value = deserialize(&bytes)?;

        Ok(value)
    }

    async fn get_ready_root(&self) -> RBCResult<H256> {
        let lock = self.ready_messages.read().await;

        for (root, map) in lock.iter() {
            if map.len() >= (self.n_parties * 2 / 3 + 1) {
                return Ok(*root);
            }
        }

        warn!("Party {} could not find a ready root ", self.index);

        Err(RBCError::NoReadyRootFound)
    }
}

#[derive(Error, Debug)]
pub enum RBCError {
    #[error("Passed non-positive value into constructor of NonZeroUsize")]
    ZeroUsize,
    #[error(transparent)]
    InvalidErasureCoder(#[from] ErasureCoderError),
    #[error(transparent)]
    FailedToSerialize(#[from] BincodeError),
    #[error("Reconstructed merkle root did not match original merkle root received by sender")]
    InvalidMerkleRootConstructed,
    #[error("Reconstructed merkle root did not match original merkle root received by sender")]
    FaultyNumberOfErasureBlocks,
    #[error("Reconstructed merkle root did not match original merkle root received by sender")]
    NoReadyRootFound,
}