use super::{
    messages::{MVBASender, ProtocolMessage, ToProtocolMessage, ViewChangeMessage},
    proposal_promotion::{PPProposal, PPStatus, PPID},
    provable_broadcast::{PBKey, PBProof, PBResponse, PBSig, PBID},
    Key, Value, MVBAID,
};
use bincode::serialize;
use consensus_core::crypto::sign::Signer;
use std::{marker::PhantomData, sync::Arc};
use tokio::sync::Notify;

pub struct ViewChange<F: MVBASender> {
    id: MVBAID,
    n_parties: usize,
    current_key_view: usize,
    current_lock: usize,
    leader_key: Option<PPProposal>,
    leader_lock: Option<PPProposal>,
    leader_commit: Option<PPProposal>,
    result: Option<ViewChangeResult>,
    messages: Vec<u8>,
    notify_messages: Arc<Notify>,
    _phantom: PhantomData<F>,
}

impl<F: MVBASender> ViewChange<F> {
    pub fn init(
        id: MVBAID,
        n_parties: usize,
        current_key_view: usize,
        current_lock: usize,
        key: Option<PPProposal>,
        lock: Option<PPProposal>,
        commit: Option<PPProposal>,
    ) -> Self {
        Self {
            id,
            current_key_view: current_key_view,
            current_lock,
            leader_commit: commit,
            leader_key: key,
            leader_lock: lock,
            result: Default::default(),

            messages: Default::default(),
            notify_messages: Arc::new(Notify::new()),
            n_parties,
            _phantom: PhantomData,
        }
    }

    pub async fn invoke(&mut self, send_handle: &F) -> ViewChangeResult {
        let vc_message = ViewChangeMessage::new(
            self.id.id,
            self.id.index,
            self.id.view,
            self.leader_key.take(),
            self.leader_lock.take(),
            self.leader_commit.take(),
        );

        for i in 0..self.n_parties {
            send_handle
                .send(
                    i,
                    vc_message.to_protocol_message(self.id.id, self.id.index, i),
                )
                .await;
        }

        // wait for n - f distinct view change messages, or view change message with valid commit (can decide early then)

        let notify_messages = self.notify_messages.clone();

        notify_messages.notified().await;

        self.result.take().expect("Viewchange result should")
    }

    pub fn on_view_change_message(&mut self, message: &ViewChangeMessage, signer: &Signer) {
        let mut result = self
            .result
            .take()
            .expect("ViewChange result should be initialized");

        if self.has_valid_commit(&message, signer) {
            result.value.replace(
                message
                    .leader_commit
                    .as_ref()
                    .expect("Asserted that message had valid commit")
                    .value,
            );
            self.notify_messages.notify_one();
            return;
        }

        if message.view > self.current_lock && self.has_valid_lock(&message, signer) {
            result.lock.replace(message.view);
        }

        if message.view > self.current_key_view && self.has_valid_key(&message, signer) {
            let (value, sig) = try_unpack_value_and_sig(&message.leader_key)
                .expect("Asserted that message had valid key");
            result.key.replace(Key {
                view: message.view,
                value: value,
                proof: Some(sig),
            });
        }

        self.result.replace(result);
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
        }
        false
    }
}

/// Utility function to unpack value and view_key_proof from proposal, if proposal and proofs are Some.
fn try_unpack_value_and_sig(proposal: &Option<PPProposal>) -> Option<(Value, PBSig)> {
    if let Some(PPProposal { value, proof }) = proposal {
        if let Some(sig) = &proof.key.view_key_proof {
            return Some((*value, sig.clone()));
        }
    }
    None
}

#[derive(Default)]
pub struct ViewChangeResult {
    pub(crate) value: Option<Value>,
    pub(crate) lock: Option<usize>,
    pub(crate) key: Option<Key>,
}
