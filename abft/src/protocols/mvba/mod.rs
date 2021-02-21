use bincode::serialize;
use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use proposal_promotion::{PPProposal, PPSender, PPStatus};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use std::sync::Arc;
use tokio::sync::Notify;

use self::{
    elect::Elect,
    messages::{
        MVBADoneMessage, MVBASkipMessage, MVBASkipShareMessage, ProtocolMessage, ToProtocolMessage,
    },
    proposal_promotion::PPID,
    provable_broadcast::{PBResponse, PBSig, PBID},
    view_change::ViewChange,
};

mod elect;
mod messages;
mod proposal_promotion;
mod provable_broadcast;
mod view_change;

// Keep LOCK and KEY variable consistent with paper
#[allow(non_snake_case)]

/// Instance of Multi-valued Validated Byzantine Agreement
pub struct MVBA<'s, F: Fn(usize, &ProtocolMessage)> {
    id: MVBAID,
    n_parties: usize,
    status: MVBAStatus,
    LOCK: usize,
    KEY: Key,
    leaders: Vec<Option<usize>>,
    has_received_done: Vec<HashMap<usize, bool>>,
    pp_done: Vec<usize>,
    has_received_skip_share: Vec<HashMap<usize, bool>>,
    has_sent_skip_share: Vec<bool>,
    pp_skip: Vec<HashSet<SkipShare>>,
    has_sent_skip: Vec<bool>,
    notify_skip: Arc<Notify>,
    skip: Vec<bool>,
    send_handle: F,
    signer: &'s Signer,
}

impl<'s, F: Fn(usize, &ProtocolMessage)> MVBA<'s, F> {
    pub fn init(
        id: usize,
        index: usize,
        n_parties: usize,
        value: Value,
        send_handle: F,
        signer: &'s Signer,
    ) -> Self {
        Self {
            id: MVBAID { id, index, view: 0 },
            n_parties,
            status: MVBAStatus::Init,
            LOCK: 0,
            KEY: Key {
                view: 0,
                value,
                proof: None,
            },
            leaders: Default::default(),
            has_received_done: Default::default(),
            pp_done: Default::default(),
            has_received_skip_share: Default::default(),
            has_sent_skip_share: Default::default(),
            pp_skip: Default::default(),
            has_sent_skip: Default::default(),
            skip: Default::default(),
            notify_skip: Arc::new(Notify::new()),
            send_handle,
            signer,
        }
    }

    pub async fn invoke(&mut self) -> Value {
        //TODO: Fix dummy signers

        let coins = Coin::generate_coins(1, 1);
        let coin = &coins[0];

        loop {
            // ***** PROPOSAL PROMOTION *****

            let MVBAID { id, index, view } = self.id;

            let key = PBKey {
                view: self.KEY.view,
                view_key_proof: self.KEY.proof.clone(),
            };

            // promotion_proof = promote ID, <KEY.value, key>

            let mut proposal = PPProposal {
                value: self.KEY.value,
                proof: PBProof {
                    key,
                    proof_prev: None,
                },
            };

            let pp = PPSender::init(
                PPID { inner: self.id },
                self.id.index,
                self.n_parties,
                &proposal,
                &self.signer,
                &self.send_handle,
            );

            // wait for promotion to return. aka: 1. Succesfully promoted value or 2. self.skip[self.view]

            let notify_skip = self.notify_skip.clone();

            let promotion_proof: Option<PBSig> = tokio::select! {
                proof = pp.promote() => proof,
                _ = notify_skip.notified() => {
                    self.skip[view] = true;
                    None
                },
            };

            // if !self.skip[self.view]{ for index in (0..self.n_parties) { send_done(index, view, KEY.value, promotion_proof);} }
            // wait for self.skip[view] = true
            if !self.skip[self.id.view] {
                // update proposal with promotion proof

                proposal.proof.proof_prev = promotion_proof;

                let mvba_done = MVBADoneMessage {
                    id: self.id,
                    proposal,
                };

                for i in 0..self.n_parties {
                    (self.send_handle)(i, &mvba_done.to_protocol_message(id, index, i));
                }
                notify_skip.notified().await;
            }

            // ***** LEADER ELECTION *****

            // for index in (0..self.n_parties){ abandon(id, index, view);}

            // Leader[view] = elect(id, view)
            let elect = Elect::init(id, self.id.index, self.n_parties, &coin, &self.send_handle);

            let leader = elect.invoke().await;

            self.leaders[self.id.view].replace(leader);

            // ***** VIEW CHANGE *****

            // id_leader = <id, Leader[view], view>
            let id_leader = MVBAID {
                id,
                index: leader,
                view,
            };

            // get key, lock commit for leader

            let leader_commit = None;
            let leader_lock = None;
            let leader_key = None;
            // for index in (0..self.n_parties) { send_view_change(index, view, getKey(id_leader), getLock(id_leader), getCommit(id_leader));} }
            // wait for n - f distinct view change messages
            let view_change = ViewChange::init(
                id_leader,
                self.n_parties,
                &self.KEY,
                self.LOCK,
                &self.signer,
                leader_key,
                leader_lock,
                leader_commit,
                &self.send_handle,
            );

            let changes = view_change.invoke().await;

            // Either:
            // 1. Decided on value, should return value up.
            // 2. Could not decide. Update key and lock if able. Invoke again, with current variables.

            if let Some(value) = changes.value {
                return value;
            } else {
                if let Some(lock) = changes.lock {
                    self.LOCK = lock;
                }
                if let Some(key) = changes.key {
                    self.KEY = key;
                }
            }

            self.id.view += 1;
        }
    }

    pub fn on_done_message(&mut self, index: usize, message: MVBADoneMessage) {
        let MVBADoneMessage { id, proposal } = message;
        let PPProposal { value, proof } = proposal;
        let PBProof { proof_prev, .. } = proof;

        // Assert that done message has not already been received from party (index) in view (view)

        if *self.has_received_done[id.view].entry(index).or_default() {
            return;
        }

        // Assert that proof is provided

        if let None = proof_prev {
            return;
        }

        // Assert that proof is valid

        let sig = proof_prev.expect("Checked that the proof is provided exist");

        let response_prev = PBResponse {
            id: PBID {
                id: PPID { inner: id },
                step: PPStatus::Step4,
            },
            value,
        };

        if !self.signer.verify_signature(
            &sig.inner,
            &serialize(&response_prev)
                .expect("Could not serialize response_prev for on_done_message"),
        ) {
            return;
        }

        // Update state
        self.has_received_done[id.view].insert(index, true);
        self.pp_done[id.view] += 1;

        // If enough done messages have been collected to elect leader, and we have not sent out skip_share, send it.

        if !self.has_sent_skip_share[id.view]
            && self.pp_done[id.view] >= (self.n_parties * 2 / 3) + 1
        {
            let tag = self.tag_skip_share(id.id, id.view);

            let share = SkipShare {
                inner: self.signer.sign(&tag.as_bytes()),
            };

            let skip_share_message = MVBASkipShareMessage { id, share };

            for i in 0..self.n_parties {
                (self.send_handle)(
                    i,
                    &skip_share_message.to_protocol_message(id.id, self.id.index, i),
                );
            }

            self.has_sent_skip_share[id.view] = true;
        }
    }

    pub fn on_skip_share_message(&mut self, index: usize, message: MVBASkipShareMessage) {
        let MVBASkipShareMessage { id, share } = message;

        // Assert that skip share message has not already been received from party (index) in view (view)

        if *self.has_received_skip_share[id.view]
            .entry(index)
            .or_default()
        {
            return;
        }

        // Assert that skip share is valid for index

        let tag = self.tag_skip_share(id.id, id.view);

        if !self
            .signer
            .verify_share(index, &share.inner, &tag.as_bytes())
        {
            return;
        }

        // Update state

        self.pp_skip[id.view].insert(share);

        // If we have received enough skip_shares to construct a skip signature, construct and broadcast it.

        if !self.has_sent_skip[id.view]
            && self.pp_skip[id.view].len() >= (self.n_parties * 2 / 3) + 1
        {
            let shares = self.pp_skip[id.view]
                .clone()
                .into_iter()
                .enumerate()
                .map(|(i, skip_share)| (i, skip_share.inner))
                .collect();

            // All signatures should have been individually verified. Expect that the signature is valid.

            let skip_proof = self.signer.combine_signatures(&shares).expect(
                "Invariant that enough valid skip signatures had been collected was broken",
            );

            let skip_message = MVBASkipMessage {
                id,
                sig: SkipSig { inner: skip_proof },
            };

            for i in 0..self.n_parties {
                (self.send_handle)(
                    i,
                    &skip_message.to_protocol_message(id.id, self.id.index, i),
                );
            }

            self.has_sent_skip[id.view] = true;
        }
    }

    pub fn on_skip_message(&mut self, index: usize, message: MVBASkipMessage) {
        let MVBASkipMessage { id, sig } = message;

        // Assert that the skip signature is valid

        let tag = self.tag_skip_share(id.id, id.view);

        if !self.signer.verify_signature(&sig.inner, tag.as_bytes()) {
            return;
        }

        // Update state

        self.skip[id.view] = true;

        // Propogate skip message, if we have not sent a skip message for the current view

        if !self.has_sent_skip[id.view] {
            let skip_message = MVBASkipMessage { id, sig };

            for i in 0..self.n_parties {
                (self.send_handle)(
                    i,
                    &skip_message.to_protocol_message(id.id, self.id.index, i),
                );
            }

            self.has_sent_skip[id.view] = true;
        }

        // wake up invoke()-task, since we are ready to continue to election process

        self.notify_skip.notify_one();
    }

    fn tag_skip_share(&self, id: usize, view: usize) -> String {
        format!("{}-SKIP-{}", id, view)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Value {
    inner: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct MVBAID {
    id: usize,
    index: usize,
    view: usize,
}

enum MVBAStatus {
    Init,
    Nomination,
    Election,
    ViewChange,
    Finished,
}

pub struct Key {
    view: usize,
    value: Value,
    proof: Option<PBSig>,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SkipShare {
    inner: SignatureShare,
}

#[derive(Serialize, Deserialize)]
pub struct SkipSig {
    inner: Signature,
}

#[derive(Default)]
struct LeaderType;
