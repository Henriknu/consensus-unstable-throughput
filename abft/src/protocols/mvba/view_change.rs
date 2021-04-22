use crate::{messaging::ProtocolMessageSender, ABFTValue};

use super::{
    messages::ViewChangeMessage,
    proposal_promotion::{PPProposal, PPStatus, PPID},
    provable_broadcast::{PBResponse, PBSig, PBID},
    Key, MVBAID,
};
use bincode::serialize;
use consensus_core::crypto::sign::Signer;
use log::warn;

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, Mutex,
};
use thiserror::Error;
use tokio::sync::Notify;

pub type ViewChangeResult<T> = Result<T, ViewChangeError>;

pub struct ViewChange<V: ABFTValue> {
    id: MVBAID,
    index: u32,
    view: u32,
    f_tolerance: u32,
    n_parties: u32,
    current_key_view: u32,
    current_lock: u32,
    result: Mutex<Option<Changes<V>>>,
    done: AtomicBool,
    num_messages: AtomicU32,
    notify_messages: Arc<Notify>,
}

impl<V: ABFTValue> ViewChange<V> {
    pub fn init(
        id: MVBAID,
        index: u32,
        view: u32,
        f_tolerance: u32,
        n_parties: u32,
        current_key_view: u32,
        current_lock: u32,
    ) -> Self {
        Self {
            id,
            index,
            view,
            f_tolerance,
            n_parties,
            current_key_view,
            current_lock,
            result: Mutex::new(Some(Changes::default())),
            done: AtomicBool::new(false),
            num_messages: AtomicU32::new(0),
            notify_messages: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender>(
        &self,
        leader_key: Option<PPProposal<V>>,
        leader_lock: Option<PPProposal<V>>,
        leader_commit: Option<PPProposal<V>>,
        send_handle: &F,
    ) -> ViewChangeResult<Changes<V>> {
        let vc_message = ViewChangeMessage::new(
            self.id.id,
            self.id.index,
            self.id.view,
            leader_key,
            leader_lock,
            leader_commit,
        );

        send_handle
            .broadcast(
                self.id.id,
                self.index,
                self.n_parties,
                self.view,
                0,
                vc_message,
            )
            .await;

        // wait for n - f distinct view change messages, or view change message with valid commit (can decide early then)

        let notify_messages = self.notify_messages.clone();

        notify_messages.notified().await;

        let mut result = self
            .result
            .lock()
            .map_err(|_| ViewChangeError::PoisonedMutex)?;

        self.done.store(true, Ordering::Relaxed);

        Ok(result
            .take()
            .expect("Only the invoking task should be able to take the result"))
    }

    pub fn on_view_change_message(
        &self,
        message: &ViewChangeMessage<V>,
        signer: &Signer,
    ) -> ViewChangeResult<()> {
        // Check if result already taken
        if self.done.load(Ordering::Relaxed) {
            return Ok(());
        }

        let mut new_result = Changes::default();

        if self.has_valid_commit(&message, signer) {
            new_result.value.replace(
                message
                    .leader_commit
                    .as_ref()
                    .expect("Asserted that message had valid commit")
                    .value
                    .clone(),
            );
            self.update(new_result)?;
            self.notify_messages.notify_one();
            return Ok(());
        }

        if message.view > self.current_lock && self.has_valid_lock(&message, signer) {
            new_result.lock.replace(message.view);
        }

        if message.view > self.current_key_view {
            if let Some((value, sig)) = self.get_valid_key(&message, signer) {
                new_result.key.replace(Key {
                    view: message.view,
                    value,
                    proof: Some(sig),
                });
            }
        }

        self.update(new_result)?;

        let num_messages = self.num_messages.fetch_add(1, Ordering::Relaxed);

        if num_messages >= (self.n_parties - self.f_tolerance) {
            self.notify_messages.notify_one();
        }

        Ok(())
    }

    fn update(&self, new_result: Changes<V>) -> ViewChangeResult<()> {
        let mut result_lock = self
            .result
            .lock()
            .map_err(|_| ViewChangeError::PoisonedMutex)?;

        let result = result_lock
            .as_mut()
            .ok_or_else(|| ViewChangeError::ResultAlreadyTaken)?;

        if let Some(key) = new_result.key {
            result.key.replace(key);
        }
        if let Some(lock) = new_result.lock {
            result.lock.replace(lock);
        }
        if let Some(value) = new_result.value {
            result.value.replace(value);
        }
        Ok(())
    }

    fn has_valid_commit(&self, message: &ViewChangeMessage<V>, signer: &Signer) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_commit) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step3,
                },
                value,
            };
            if signer.verify_signature(
                &sig.inner,
                &serialize(&response)
                    .expect("Could not serialize reconstructed PB response on_view_change_message"),
            ) {
                return true;
            }
            warn!(
                "Party {} received ViewChange message with invalid signature for commit",
                self.index
            );
        }
        false
    }

    fn has_valid_lock(&self, message: &ViewChangeMessage<V>, signer: &Signer) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_lock) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step2,
                },
                value,
            };

            if signer.verify_signature(
                &sig.inner,
                &serialize(&response)
                    .expect("Could not serialize reconstructed PB response on_view_change_message"),
            ) {
                return true;
            }
            warn!(
                "Party {} received ViewChange message with invalid signature for lock",
                self.index
            );
        }
        false
    }

    fn get_valid_key(&self, message: &ViewChangeMessage<V>, signer: &Signer) -> Option<(V, PBSig)> {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_key) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step1,
                },
                value: value.clone(),
            };

            if signer.verify_signature(
                &sig.inner,
                &serialize(&response)
                    .expect("Could not serialize reconstructed PB response on_view_change_message"),
            ) {
                return Some((value, sig));
            }
            warn!(
                "Party {} received ViewChange message with invalid signature for key",
                self.index
            );
        }
        None
    }
}

/// Utility function to unpack value and view_key_proof from proposal, if proposal and proofs are Some.
fn try_unpack_value_and_sig<V: ABFTValue>(proposal: &Option<PPProposal<V>>) -> Option<(V, PBSig)> {
    if let Some(PPProposal { value, proof }) = proposal {
        if let Some(sig) = &proof.proof_prev {
            return Some((value.clone(), sig.clone()));
        }
    }
    warn!("Could not unpack value and proof from ViewChange Message");
    None
}

#[derive(Debug, Default)]
pub struct Changes<V: ABFTValue> {
    pub(crate) value: Option<V>,
    pub(crate) lock: Option<u32>,
    pub(crate) key: Option<Key<V>>,
}

#[derive(Error, Debug)]
pub enum ViewChangeError {
    #[error("Acquired a poisoned mutex during viewchange")]
    PoisonedMutex,
    #[error("Changes was already taken from ViewChange instance")]
    ResultAlreadyTaken,
}
