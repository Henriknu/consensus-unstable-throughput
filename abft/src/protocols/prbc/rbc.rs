use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
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
use consensus_core::erasure::{ErasureCoder, Error as ErasureCoderError, NonZeroUsize};
use log::warn;
use thiserror::Error;
use tokio::sync::{Notify, RwLock};

use crate::{messaging::ProtocolMessageSender, Value};

use super::messages::{RBCEchoMessage, RBCReadyMessage, RBCValueMessage};

pub type RBCResult<T> = Result<T, RBCError>;

pub struct RBC {
    id: usize,
    index: usize,
    n_parties: usize,
    root: RwLock<H256>,
    echo_messages: RwLock<HashMap<usize, RBCEchoMessage>>,
    ready_messages: RwLock<HashMap<H256, HashMap<usize, RBCReadyMessage>>>,
    notify_echo: Arc<Notify>,
    notify_ready: Arc<Notify>,
    has_seen_root: AtomicBool,
    has_sent_ready: AtomicBool,
}

impl RBC {
    pub fn init(id: usize, index: usize, n_parties: usize) -> RBCResult<Self> {
        Ok(Self {
            id,
            index,
            n_parties,
            root: Default::default(),
            echo_messages: Default::default(),
            ready_messages: Default::default(),
            notify_echo: Arc::new(Notify::new()),
            notify_ready: Arc::new(Notify::new()),
            has_seen_root: AtomicBool::new(false),
            has_sent_ready: AtomicBool::new(false),
        })
    }

    pub async fn invoke<F: ProtocolMessageSender>(
        &self,
        value: Option<Value>,
        send_handle: &F,
    ) -> RBCResult<Value> {
        let mut erasure = self.init_erasure()?;

        if let Some(value) = value {
            self.broadcast_value(value, &mut erasure, send_handle)
                .await?;
        }

        let notify_ready = self.notify_ready.clone();

        notify_ready.notified().await;

        let notify_echo = self.notify_echo.clone();

        notify_echo.notified().await;

        let value = self.decode_value(&mut erasure).await?;

        Ok(value)
    }

    pub async fn on_value_message<F: ProtocolMessageSender>(
        &self,
        message: RBCValueMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        let echo_message =
            RBCEchoMessage::new(self.index, message.root, message.block, message.branch);

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
            &message.block.hash(),
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

        if !self.has_seen_root.load(Ordering::SeqCst) {
            let mut lock = self.root.write().await;
            *lock = message.root;
            self.has_seen_root.store(true, Ordering::SeqCst);
        }

        let n_echo_messages;

        {
            let mut lock = self.echo_messages.write().await;

            if !lock.contains_key(&message.index) {
                lock.insert(message.index, message);
            }

            n_echo_messages = lock.len();
        }

        if n_echo_messages >= (self.n_parties / 3 + 1) {
            self.notify_echo.notify_one();
        }

        if n_echo_messages >= (self.n_parties * 2 / 3 + 1)
            && !self.has_sent_ready.load(Ordering::SeqCst)
        {
            let mut erasure = self.init_erasure()?;

            let blocks = self.reconstruct_blocks(&mut erasure).await?;

            let merkle2 = MerkleTree::new(&blocks);

            {
                let lock = self.root.read().await;

                if *merkle2.root() != *lock {
                    return Err(RBCError::InvalidMerkleRootConstructed);
                }
            }

            let ready_message = RBCReadyMessage::new(*merkle2.root());

            send_handle
                .broadcast(self.id, self.index, self.n_parties, 0, ready_message)
                .await;
        }

        Ok(())
    }

    pub async fn on_ready_message<F: ProtocolMessageSender>(
        &self,
        index: usize,
        message: RBCReadyMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        // validation

        let n_ready_messages;

        {
            let mut lock = self.ready_messages.write().await;

            if !lock.entry(message.root).or_default().contains_key(&index) {
                lock.entry(message.root).or_default().insert(index, message);
            }

            n_ready_messages = lock.len();
        }

        if n_ready_messages >= (self.n_parties / 3 + 1)
            && !self.has_sent_ready.load(Ordering::SeqCst)
        {
            let lock = self.root.read().await;
            let ready_message = RBCReadyMessage::new(*lock);

            send_handle
                .broadcast(self.id, self.index, self.n_parties, 0, ready_message)
                .await;
        }

        if n_ready_messages >= (self.n_parties * 2 / 3 + 1) {
            self.notify_ready.notify_one();
        }

        Ok(())
    }

    async fn broadcast_value<F: ProtocolMessageSender>(
        &self,
        value: Value,
        erasure: &mut ErasureCoder,
        send_handle: &F,
    ) -> RBCResult<()> {
        let blocks = erasure
            .encode(&serialize(&value)?)?
            .into_iter()
            .map(|inner| RBCBlock { inner })
            .collect::<Vec<_>>();

        let merkle = MerkleTree::new(&blocks);

        let mut blocks = blocks.into_iter();

        for j in 0..self.n_parties {
            let block = blocks
                .next()
                .ok_or_else(|| RBCError::FaultyNumberOfErasureBlocks)?;
            if j != self.index {
                let message = RBCValueMessage::new(*merkle.root(), block, get_branch(&merkle, j));

                send_handle.send(self.id, self.index, j, 0, message).await;
            }
        }

        Ok(())
    }

    async fn reconstruct_blocks(&self, erasure: &mut ErasureCoder) -> RBCResult<Vec<RBCBlock>> {
        // want to reconstruct whatever blocks sent out which have not been
        let lock = self.echo_messages.read().await;

        let mut blocks: Vec<RBCBlock> =
            lock.values().map(|message| message.block.clone()).collect();

        for j in 0..self.n_parties {
            if !lock.contains_key(&j) {
                blocks.push(RBCBlock {
                    inner: erasure.reconstruct(j, blocks.iter())?,
                });
            }
        }

        Ok(blocks)
    }

    async fn decode_value(&self, erasure: &mut ErasureCoder) -> RBCResult<Value> {
        let lock = self.echo_messages.read().await;

        let blocks: Vec<RBCBlock> = lock.values().map(|message| message.block.clone()).collect();

        let bytes = erasure.decode(&blocks)?;

        let value: Value = deserialize(&bytes)?;

        Ok(value)
    }

    fn init_erasure(&self) -> RBCResult<ErasureCoder> {
        Ok(ErasureCoder::new(
            NonZeroUsize::new(self.n_parties / 3 + 1).ok_or_else(|| RBCError::ZeroUsize)?,
            NonZeroUsize::new(self.n_parties).ok_or_else(|| RBCError::ZeroUsize)?,
        )?)
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RBCBlock {
    inner: Vec<u8>,
}

impl Hashable for RBCBlock {
    fn hash(&self) -> H256 {
        self.inner.hash()
    }
}

impl AsRef<[u8]> for RBCBlock {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
