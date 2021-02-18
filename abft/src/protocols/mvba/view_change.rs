use super::{
    proposal_promotion::{PPProposal, PPStatus, PPID},
    provable_broadcast::{PBKey, PBProof, PBResponse, PBID},
    Key, Value, MVBAID,
};
use bincode::serialize;
use consensus_core::crypto::sign::Signer;
use std::sync::Arc;
use tokio::sync::Notify;

pub struct ViewChange<'s> {
    id: MVBAID,
    n_parties: usize,
    leader_key: Option<PPProposal>,
    leader_lock: Option<PPProposal>,
    leader_commit: Option<PPProposal>,
    result: ViewChangeResult,
    signer: &'s Signer,
    messages: Vec<u8>,
    notify_messages: Arc<Notify>,
}

impl<'s> ViewChange<'s> {
    pub fn init(
        id: MVBAID,
        n_parties: usize,
        signer: &'s Signer,
        key: Option<PPProposal>,
        lock: Option<PPProposal>,
        commit: Option<PPProposal>,
    ) -> Self {
        Self {
            id,
            leader_commit: commit,
            leader_key: key,
            leader_lock: lock,
            result: Default::default(),
            signer,
            messages: Default::default(),
            notify_messages: Arc::new(Notify::new()),
            n_parties,
        }
    }

    pub async fn invoke(&self) -> ViewChangeResult {
        // for index in (0..self.n_parties) { send_view_change(index, view, getKey(id_leader), getLock(id_leader), getCommit(id_leader));} }

        for index in 0..self.n_parties {
            //send_view_change(index, view, getKey(id_leader), getLock(id_leader), getCommit(id_leader));
        }

        // wait for n - f distinct view change messages, or view change message with valid commit (can decide early then)

        let notify_messages = self.notify_messages.clone();

        notify_messages.notified().await;

        todo!()
    }

    pub fn on_view_change_message(&mut self, message: &ViewChangeMessage) {
        if let Some(PPProposal { value, proof }) = message.leader_commit {
            if let Some(sig) = proof.key.view_key_proof {
                let response = PBResponse {
                    id: PBID {
                        id: PPID { inner: self.id },
                        step: PPStatus::Step3,
                    },
                    value,
                };
                if self.signer.verify_signature(
                    &sig.inner,
                    &serialize(&response).expect(
                        "Could not serialize reconstructed PB response on_view_change_message",
                    ),
                ) {
                    self.result.value.replace(value);
                    self.notify_messages.notify_one();
                    return;
                }
            }
        }

        if let Some(PPProposal { value, proof }) = message.leader_lock {
            if let Some(sig) = proof.key.view_key_proof {
                let response = PBResponse {
                    id: PBID {
                        id: PPID { inner: self.id },
                        step: PPStatus::Step2,
                    },
                    value,
                };

                if message.view > self.leader_lock
                    && self.signer.verify_signature(
                        &sig.inner,
                        &serialize(&response).expect(
                            "Could not serialize reconstructed PB response on_view_change_message",
                        ),
                    )
                {
                    self.result.lock.replace(message.view);
                }
            }
        }

        if let Some(PPProposal { value, proof }) = message.leader_lock {
            if let Some(sig) = proof.key.view_key_proof {
                let response = PBResponse {
                    id: PBID {
                        id: PPID { inner: self.id },
                        step: PPStatus::Step1,
                    },
                    value,
                };

                if message.view > self.leader_key
                    && self.signer.verify_signature(
                        &sig.inner,
                        &serialize(&response).expect(
                            "Could not serialize reconstructed PB response on_view_change_message",
                        ),
                    )
                {
                    self.result.key.replace(Key {
                        view: message.view,
                        value,
                        proof,
                    });
                }
            }
        }
    }
}

#[derive(Default)]
pub struct ViewChangeResult {
    value: Option<Value>,
    lock: Option<usize>,
    key: Option<Key>,
}

pub struct ViewChangeMessage {
    id: usize,
    index: usize,
    view: usize,
    leader_key: Option<PPProposal>,
    leader_lock: Option<PPProposal>,
    leader_commit: Option<PPProposal>,
}
