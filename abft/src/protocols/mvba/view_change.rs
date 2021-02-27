use super::{
    messages::{MVBASender, ProtocolMessage, ToProtocolMessage, ViewChangeMessage},
    proposal_promotion::{PPProposal, PPStatus, PPID},
    provable_broadcast::{PBKey, PBProof, PBResponse, PBSig, PBID},
    Key, Value, MVBAID,
};
use bincode::serialize;
use consensus_core::crypto::sign::Signer;
use log::{debug, info, warn};
use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use thiserror::Error;
use tokio::sync::Notify;

pub type ViewChangeResult<T> = Result<T, ViewChangeError>;

pub struct ViewChange {
    id: MVBAID,
    index: usize,
    view: usize,
    n_parties: usize,
    current_key_view: usize,
    current_lock: usize,
    result: Mutex<Option<Changes>>,
    done: AtomicBool,
    num_messages: AtomicUsize,
    notify_messages: Arc<Notify>,
}

impl ViewChange {
    pub fn init(
        id: MVBAID,
        index: usize,
        view: usize,
        n_parties: usize,
        current_key_view: usize,
        current_lock: usize,
    ) -> Self {
        Self {
            id,
            index,
            view,
            current_key_view,
            current_lock,
            result: Mutex::new(Some(Changes::default())),
            done: AtomicBool::new(false),
            num_messages: AtomicUsize::new(0),
            notify_messages: Arc::new(Notify::new()),
            n_parties,
        }
    }

    pub async fn invoke<F: MVBASender>(
        &self,
        leader_key: Option<PPProposal>,
        leader_lock: Option<PPProposal>,
        leader_commit: Option<PPProposal>,
        send_handle: &F,
    ) -> ViewChangeResult<Changes> {
        let vc_message = ViewChangeMessage::new(
            self.id.id,
            self.id.index,
            self.id.view,
            leader_key,
            leader_lock,
            leader_commit,
        );

        for i in 0..self.n_parties {
            send_handle
                .send(i, vc_message.to_protocol_message(self.id.id, self.index, i))
                .await;
        }

        // wait for n - f distinct view change messages, or view change message with valid commit (can decide early then)

        let notify_messages = self.notify_messages.clone();

        notify_messages.notified().await;

        let mut result = self
            .result
            .lock()
            .map_err(|_| ViewChangeError::PoisonedMutex)?;

        self.done.store(true, Ordering::SeqCst);

        Ok(result
            .take()
            .expect("Only the invoking task should be able to take the result"))
    }

    pub fn on_view_change_message(
        &self,
        message: &ViewChangeMessage,
        signer: &Signer,
    ) -> ViewChangeResult<()> {
        // Check if result already taken
        if self.done.load(Ordering::SeqCst) {
            return Ok(());
        }

        let mut new_result = Changes::default();

        if self.has_valid_commit(&message, signer) {
            new_result.value.replace(
                message
                    .leader_commit
                    .as_ref()
                    .expect("Asserted that message had valid commit")
                    .value,
            );
            self.update(new_result)?;
            self.notify_messages.notify_one();
            return Ok(());
        }

        if message.view > self.current_lock && self.has_valid_lock(&message, signer) {
            new_result.lock.replace(message.view);
        }

        if message.view > self.current_key_view && self.has_valid_key(&message, signer) {
            let (value, sig) = try_unpack_value_and_sig(&message.leader_key)
                .expect("Asserted that message had valid key");
            new_result.key.replace(Key {
                view: message.view,
                value,
                proof: Some(sig),
            });
        }

        self.update(new_result)?;

        let num_messages = self.num_messages.fetch_add(1, Ordering::SeqCst);

        if num_messages >= (self.n_parties * 2 / 3) {
            self.notify_messages.notify_one();
        }

        Ok(())
    }

    fn update(&self, new_result: Changes) -> ViewChangeResult<()> {
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

    fn has_valid_commit(&self, message: &ViewChangeMessage, signer: &Signer) -> bool {
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

    fn has_valid_lock(&self, message: &ViewChangeMessage, signer: &Signer) -> bool {
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

    fn has_valid_key(&self, message: &ViewChangeMessage, signer: &Signer) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_key) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step1,
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
                "Party {} received ViewChange message with invalid signature for key",
                self.index
            );
        }
        false
    }
}

/// Utility function to unpack value and view_key_proof from proposal, if proposal and proofs are Some.
fn try_unpack_value_and_sig(proposal: &Option<PPProposal>) -> Option<(Value, PBSig)> {
    if let Some(PPProposal { value, proof }) = proposal {
        if let Some(sig) = &proof.proof_prev {
            return Some((*value, sig.clone()));
        }
    }
    warn!("Could not unpack value and proof from ViewChange Message");
    None
}

#[derive(Debug, Default)]
pub struct Changes {
    pub(crate) value: Option<Value>,
    pub(crate) lock: Option<usize>,
    pub(crate) key: Option<Key>,
}

#[derive(Error, Debug)]
pub enum ViewChangeError {
    #[error("Acquired a poisoned mutex during viewchange")]
    PoisonedMutex,
    #[error("Changes was already taken from ViewChange instance")]
    ResultAlreadyTaken,
}
