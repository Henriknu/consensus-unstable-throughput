use std::{
    collections::btree_map::Entry,
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
use consensus_core::erasure::{
    ErasureCoder, ErasureCoderError, NonZeroUsize, DEFAULT_PACKET_SIZE, DEFAULT_WORD_SIZE,
};
use log::{error, info, warn};
use thiserror::Error;
use tokio::sync::{Notify, RwLock};

use crate::{messaging::ProtocolMessageSender, ABFTValue};

use super::messages::{RBCEchoMessage, RBCReadyMessage, RBCValueMessage};

pub type RBCResult<T> = Result<T, RBCError>;

pub struct RBC {
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,
    send_id: u32,
    erasure: ErasureCoder,
    echo_messages: RwLock<BTreeMap<H256, BTreeMap<u32, RBCEchoMessage>>>,
    ready_messages: RwLock<BTreeMap<H256, BTreeMap<u32, RBCReadyMessage>>>,
    decoded: RwLock<BTreeMap<H256, Vec<Vec<u8>>>>,
    notify_echo: Arc<Notify>,
    notify_ready: Arc<Notify>,
    has_sent_ready: AtomicBool,
}

impl RBC {
    pub fn try_init(
        id: u32,
        index: u32,
        f_tolerance: u32,
        n_parties: u32,
        batch_size: u32,
        send_id: u32,
    ) -> RBCResult<Self> {
        let (word_size, packet_size) =
            get_word_and_packet_size(n_parties as usize, batch_size as usize);

        warn!(
            "For N: {}, B:{}, choose word size: {} and packet size: {} for erasure coding",
            n_parties, batch_size, word_size, packet_size
        );

        let erasure = ErasureCoder::new(
            NonZeroUsize::new((n_parties - 2 * f_tolerance) as usize)
                .ok_or_else(|| RBCError::ZeroUsize)?,
            NonZeroUsize::new((2 * f_tolerance) as usize).ok_or_else(|| RBCError::ZeroUsize)?,
            NonZeroUsize::new(packet_size).ok_or_else(|| RBCError::ZeroUsize)?,
            NonZeroUsize::new(word_size).ok_or_else(|| RBCError::ZeroUsize)?,
        )?;

        warn!("Created erasure encoder");

        Ok(Self {
            id,
            index,
            f_tolerance,
            n_parties,
            send_id,
            erasure,
            echo_messages: Default::default(),
            ready_messages: Default::default(),
            decoded: Default::default(),
            notify_echo: Arc::new(Notify::new()),
            notify_ready: Arc::new(Notify::new()),
            has_sent_ready: AtomicBool::new(false),
        })
    }

    pub async fn invoke<F: ProtocolMessageSender, V: ABFTValue>(
        &self,
        value: Option<V>,
        send_handle: &F,
    ) -> RBCResult<V> {
        if let Some(value) = value {
            self.broadcast_value(value, send_handle).await?;
        }

        let notify_ready = self.notify_ready.clone();

        notify_ready.notified().await;

        let notify_echo = self.notify_echo.clone();

        notify_echo.notified().await;

        let value = self.decode_value().await?;

        Ok(value)
    }

    pub async fn on_value_message<F: ProtocolMessageSender>(
        &self,
        message: RBCValueMessage,
        send_handle: &F,
    ) {
        let echo_message =
            RBCEchoMessage::new(self.index, message.root, message.fragment, message.branch);

        send_handle
            .broadcast(
                self.id,
                self.index,
                self.n_parties,
                0,
                self.send_id,
                echo_message,
            )
            .await;
    }

    pub async fn on_echo_message<F: ProtocolMessageSender>(
        &self,
        message: RBCEchoMessage,
        send_handle: &F,
    ) -> RBCResult<()> {
        if !verify_branch(
            &message.root,
            &message.fragment.hash(),
            message.index as usize,
            self.n_parties as usize,
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

        if n_echo_messages >= (self.n_parties - 2 * self.f_tolerance) as usize {
            self.notify_echo.notify_one();
        }

        if n_echo_messages >= (self.n_parties - self.f_tolerance) as usize
            && self
                .has_sent_ready
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.reconstruct_blocks_with_root_and_validate(root).await?;

            let ready_message = RBCReadyMessage::new(root);

            send_handle
                .broadcast(
                    self.id,
                    self.index,
                    self.n_parties,
                    0,
                    self.send_id,
                    ready_message,
                )
                .await;
        }

        Ok(())
    }

    pub async fn on_ready_message<F: ProtocolMessageSender>(
        &self,
        index: u32,
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

        if n_ready_messages >= (self.f_tolerance + 1) as usize
            && self
                .has_sent_ready
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let ready_message = RBCReadyMessage::new(root);

            send_handle
                .broadcast(
                    self.id,
                    self.index,
                    self.n_parties,
                    0,
                    self.send_id,
                    ready_message,
                )
                .await;
        }

        if n_ready_messages >= (self.f_tolerance * 2 + 1) as usize {
            self.notify_ready.notify_one();
        }

        Ok(())
    }

    async fn broadcast_value<F: ProtocolMessageSender, V: ABFTValue>(
        &self,
        value: V,
        send_handle: &F,
    ) -> RBCResult<()> {
        info!(
            "Party {} encoding blocks for RBC {}",
            self.index, self.send_id
        );
        let fragments = self.erasure.encode(&serialize(&value)?);

        info!(
            "Party {} done encoding blocks for RBC {}",
            self.index, self.send_id
        );

        let merkle = MerkleTree::new(&fragments);

        let mut fragments = fragments.into_iter();

        let mut own_value_message = None;

        for j in 0..self.n_parties {
            let fragment = fragments
                .next()
                .ok_or_else(|| RBCError::FaultyNumberOfErasureBlocks)?;

            let message =
                RBCValueMessage::new(*merkle.root(), fragment, get_branch(&merkle, j as usize));
            if j != self.index {
                send_handle
                    .send(self.id, self.index, j, 0, self.send_id, message)
                    .await;
            } else {
                own_value_message.replace(message);
            }
        }

        self.on_value_message(own_value_message.unwrap(), send_handle)
            .await;

        Ok(())
    }

    async fn reconstruct_blocks_with_root_and_validate(&self, root: H256) -> RBCResult<()> {
        // want to reconstruct whatever blocks sent out which have not been

        let mut lock = self.echo_messages.write().await;

        let root_map = lock.entry(root).or_default();

        let mut erasures = Vec::<i32>::with_capacity(self.n_parties as usize);

        for i in 0..self.n_parties {
            if !root_map.contains_key(&i) {
                erasures.push(i as i32);
            }
        }

        // We can take the values. If the merkle root corresponding the fragments do not match "root", then we panic and "investigate".

        let fragments = std::mem::take(root_map)
            .into_iter()
            .map(|(_, message)| message.fragment)
            .collect::<Vec<Vec<u8>>>();

        info!(
            "Party {} Reconstructing blocks for RBC {}",
            self.index, self.send_id
        );

        let fragments = self.erasure.reconstruct(&fragments, erasures)?;

        info!(
            "Party {} done Reconstructing blocks for RBC {}",
            self.index, self.send_id
        );

        let merkle2 = MerkleTree::new(&fragments);

        if *merkle2.root() != root {
            error!("Party {} reconstructed value in RBC instance {} and got invalid root. Investigate.", self.index, self.send_id);
            panic!("Invalid root after reconstructing");
        }

        {
            let mut decoded_lock = self.decoded.write().await;

            decoded_lock.insert(root, fragments);
        }

        Ok(())
    }

    async fn decode_value<V: ABFTValue>(&self) -> RBCResult<V> {
        let root = self.get_ready_root().await?;

        let mut lock = self.echo_messages.write().await;

        // Check if we already reconstructed fragments. Can then use "cached" value, instead of decoding anew

        {
            let mut decoded_lock = self.decoded.write().await;

            if let Entry::Occupied(decoded) = decoded_lock.entry(root) {
                let mut fragments = decoded.remove();

                let bytes: Vec<_> = fragments
                    .drain(0..(self.n_parties - 2 * self.f_tolerance) as usize)
                    .flatten()
                    .collect();

                let value: V = deserialize(&bytes)?;

                return Ok(value);
            }
        }

        let root_map = lock.get(&root).ok_or_else(|| RBCError::NoReadyRootFound)?;

        let mut erasures = Vec::with_capacity(self.n_parties as usize);

        for i in 0..self.n_parties {
            if !root_map.contains_key(&i) {
                erasures.push(i as i32);
            }
        }

        // Don't need messages after this, can simply take the contents

        let fragments = std::mem::take(
            lock.get_mut(&root)
                .ok_or_else(|| RBCError::NoReadyRootFound)?,
        )
        .into_iter()
        .map(|(_, message)| message.fragment)
        .collect();

        info!(
            "Party {} decoding blocks for RBC {}",
            self.index, self.send_id
        );

        let bytes = self.erasure.decode(&fragments, erasures)?;

        info!(
            "Party {} done decoding blocks for RBC {}",
            self.index, self.send_id
        );

        let value: V = deserialize(&bytes)?;

        Ok(value)
    }

    async fn get_ready_root(&self) -> RBCResult<H256> {
        let lock = self.ready_messages.read().await;

        for (root, map) in lock.iter() {
            if map.len() >= (self.f_tolerance * 2 + 1) as usize {
                return Ok(*root);
            }
        }

        warn!("Party {} could not find a ready root ", self.index);

        Err(RBCError::NoReadyRootFound)
    }
}

/// Pre-calculated word and packet sizes for different values of N and B. Calculated for 3rd gen i7, 4 cores, 8 threads, Ivybridge, may differ for other architectures.
fn get_word_and_packet_size(n_parties: usize, batch_size: usize) -> (usize, usize) {
    match n_parties {
        n_parties if n_parties == 4 => match batch_size {
            batch_size if batch_size == 4 => (2, 8),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },

        n_parties if n_parties == 8 => match batch_size {
            batch_size if batch_size == 8 => (3, 8),
            batch_size if batch_size == 100 => (3, 256),
            batch_size if batch_size == 1000 => (3, 4096),
            batch_size if batch_size == 10_000 => (4, 2048),
            batch_size if batch_size == 100_000 => (3, 16384),
            batch_size if batch_size == 1_000_000 => (5, 8192),
            batch_size if batch_size == 2_000_000 => (3, 16384),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },

        n_parties if n_parties == 16 => match batch_size {
            batch_size if batch_size == 16 => (4, 4),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        n_parties if n_parties == 32 => match batch_size {
            batch_size if batch_size == 32 => (5, 4),
            batch_size if batch_size == 100 => (5, 8),
            batch_size if batch_size == 1000 => (5, 64),
            batch_size if batch_size == 10_000 => (5, 512),
            batch_size if batch_size == 100_000 => (5, 2048),
            batch_size if batch_size == 1_000_000 => (5, 4096),
            batch_size if batch_size == 2_000_000 => (5, 8192),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        n_parties if n_parties == 48 => match batch_size {
            batch_size if batch_size == 48 => (6, 2),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        n_parties if n_parties == 64 => match batch_size {
            batch_size if batch_size == 64 => (6, 2),
            batch_size if batch_size == 100 => (6, 2),
            batch_size if batch_size == 1000 => (6, 8),
            batch_size if batch_size == 10_000 => (6, 256),
            batch_size if batch_size == 100_000 => (6, 2048),
            batch_size if batch_size == 1_000_000 => (6, 4096),
            batch_size if batch_size == 2_000_000 => (6, 8192),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        n_parties if n_parties == 80 => match batch_size {
            batch_size if batch_size == 80 => (7, 1),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        n_parties if n_parties == 100 => match batch_size {
            batch_size if batch_size == 100 => (7, 1),
            batch_size if batch_size == 1000 => (7, 8),
            batch_size if batch_size == 10_000 => (7, 128),
            batch_size if batch_size == 100_000 => (7, 1024),
            batch_size if batch_size == 1_000_000 => (7, 8192),
            batch_size if batch_size == 2_000_000 => (7, 8192),
            _ => {
                warn!("Non-precalced N or B provided");
                (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
            }
        },
        _ => {
            warn!("Non-precalced N or B provided");
            (DEFAULT_WORD_SIZE, DEFAULT_PACKET_SIZE)
        }
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
    #[error("Faulty number of erasure blocks")]
    FaultyNumberOfErasureBlocks,
    #[error("No ready root found, despite calling decode")]
    NoReadyRootFound,
}
