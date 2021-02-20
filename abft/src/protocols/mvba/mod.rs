use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use futures::{self, FutureExt};
use proposal_promotion::{PPProposal, PPSender};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use std::sync::Arc;
use tokio::sync::Notify;

use self::{
    elect::Elect, messages::ProtocolMessage, proposal_promotion::PPID, provable_broadcast::PBSig,
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
pub struct MVBA<F: Fn(usize, &ProtocolMessage)> {
    id: MVBAID,
    n_parties: usize,
    status: MVBAStatus,
    LOCK: usize,
    KEY: Key,
    leaders: Vec<Option<usize>>,
    pp_done: Vec<usize>,
    pp_skip: Vec<HashSet<SkipType>>,
    notify_skip: Arc<Notify>,
    skip: Vec<bool>,
    send_handle: F,
}

impl<F: Fn(usize, &ProtocolMessage)> MVBA<F> {
    pub fn init(id: usize, index: usize, n_parties: usize, value: Value, send_handle: F) -> Self {
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
            pp_done: Default::default(),
            pp_skip: Default::default(),
            skip: Default::default(),
            notify_skip: Arc::new(Notify::new()),
            send_handle,
        }
    }

    pub async fn invoke(&mut self) -> Value {
        //TODO: Fix dummy signers

        let signers = Signer::generate_signers(1, 1);
        let signer = &signers[0];

        let coins = Coin::generate_coins(1, 1);
        let coin = &coins[0];

        loop {
            self.id.view += 1;

            // ***** PROPOSAL PROMOTION *****

            let MVBAID { id, index, view } = self.id;

            let key = PBKey {
                view: self.KEY.view,
                view_key_proof: self.KEY.proof.clone(),
            };

            // promotion_proof = promote ID, <KEY.value, key>

            let proposal = PPProposal {
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
                &signer,
                &self.send_handle,
            );

            // wait for promotion to return. aka: 1. Succesfully promoted value or 2. self.skip[self.view]

            let notify_skip = self.notify_skip.clone();

            let promotion_proof: Option<PBSig> = tokio::select! {
                proof = pp.promote() => proof,
                _ = notify_skip.notified().fuse() => {
                    self.skip[view] = true;
                    None
                },
            };

            // if !self.skip[self.view]{ for index in (0..self.n_parties) { send_done(index, view, KEY.value, promotion_proof);} }
            // wait for self.skip[view] = true
            if !self.skip[self.id.view] {
                for index in 0..self.n_parties {
                    //self.send_done(index, view, KEY.value, promotion_proof);
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
                &signer,
                leader_key,
                leader_lock,
                leader_commit,
                &self.send_handle,
            );

            let changes = view_change.invoke().await;

            // Either:
            // 1. Decided on value, should return value up.
            // 2. Could not decide. Update key and lock if able. Invoke again, with current variables.

            match changes {
                changes if changes.value.is_some() => return changes.value.unwrap(),
                _ => {
                    if let Some(lock) = changes.lock {
                        self.LOCK = lock;
                    }
                    if let Some(key) = changes.key {
                        self.KEY = key;
                    }
                }
            }
        }
    }

    pub fn on_done_message() {}

    pub fn on_skip_share_message() {}

    pub fn on_skip_message() {}
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

#[derive(Default)]
struct LeaderType;

struct SkipType;
