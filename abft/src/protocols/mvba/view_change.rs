use super::{
    messages::{ProtocolMessage, ToProtocolMessage, ViewChangeMessage},
    proposal_promotion::{PPProposal, PPStatus, PPID},
    provable_broadcast::{PBKey, PBProof, PBResponse, PBSig, PBID},
    Key, Value, MVBAID,
};
use bincode::serialize;
use consensus_core::crypto::sign::Signer;
use std::sync::Arc;
use tokio::sync::Notify;

pub struct ViewChange<'s, F: Fn(usize, &ProtocolMessage)> {
    id: MVBAID,
    n_parties: usize,
    current_key: &'s Key,
    current_lock: usize,
    leader_key: Option<PPProposal>,
    leader_lock: Option<PPProposal>,
    leader_commit: Option<PPProposal>,
    result: ViewChangeResult,
    signer: &'s Signer,
    messages: Vec<u8>,
    notify_messages: Arc<Notify>,
    send_handle: &'s F,
}

impl<'s, F: Fn(usize, &ProtocolMessage)> ViewChange<'s, F> {
    pub fn init(
        id: MVBAID,
        n_parties: usize,
        current_key: &'s Key,
        current_lock: usize,
        signer: &'s Signer,
        key: Option<PPProposal>,
        lock: Option<PPProposal>,
        commit: Option<PPProposal>,
        send_handle: &'s F,
    ) -> Self {
        Self {
            id,
            current_key,
            current_lock,
            leader_commit: commit,
            leader_key: key,
            leader_lock: lock,
            result: Default::default(),
            signer,
            messages: Default::default(),
            notify_messages: Arc::new(Notify::new()),
            n_parties,
            send_handle,
        }
    }

    pub async fn invoke(self) -> ViewChangeResult {
        let vc_message = ViewChangeMessage::new(
            self.id.id,
            self.id.index,
            self.id.view,
            self.leader_key,
            self.leader_lock,
            self.leader_commit,
        );

        for i in 0..self.n_parties {
            (self.send_handle)(
                i,
                &vc_message.to_protocol_message(self.id.id, self.id.index, i),
            );
        }

        // wait for n - f distinct view change messages, or view change message with valid commit (can decide early then)

        let notify_messages = self.notify_messages.clone();

        notify_messages.notified().await;

        self.result
    }

    pub fn on_view_change_message(&mut self, message: &ViewChangeMessage) {
        if self.has_valid_commit(&message) {
            self.result.value.replace(
                message
                    .leader_commit
                    .as_ref()
                    .expect("Asserted that message had valid commit")
                    .value,
            );
            self.notify_messages.notify_one();
            return;
        }

        if message.view > self.current_lock && self.has_valid_lock(&message) {
            self.result.lock.replace(message.view);
        }

        if message.view > self.current_key.view && self.has_valid_key(&message) {
            let (value, sig) = try_unpack_value_and_sig(&message.leader_key)
                .expect("Asserted that message had valid key");
            self.result.key.replace(Key {
                view: message.view,
                value: value,
                proof: Some(sig),
            });
        }
    }
    fn has_valid_commit(&self, message: &ViewChangeMessage) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_commit) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step3,
                },
                value,
            };
            if self.signer.verify_signature(
                &sig.inner,
                &serialize(&response)
                    .expect("Could not serialize reconstructed PB response on_view_change_message"),
            ) {
                return true;
            }
        }
        false
    }

    fn has_valid_lock(&self, message: &ViewChangeMessage) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_lock) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step2,
                },
                value,
            };

            if self.signer.verify_signature(
                &sig.inner,
                &serialize(&response)
                    .expect("Could not serialize reconstructed PB response on_view_change_message"),
            ) {
                return true;
            }
        }
        false
    }

    fn has_valid_key(&self, message: &ViewChangeMessage) -> bool {
        if let Some((value, sig)) = try_unpack_value_and_sig(&message.leader_key) {
            let response = PBResponse {
                id: PBID {
                    id: PPID { inner: self.id },
                    step: PPStatus::Step1,
                },
                value,
            };

            if self.signer.verify_signature(
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
