use bincode::{deserialize, serialize};
use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use futures::{future::join_all, Future};
use messages::{ElectCoinShareMessage, PBSendMessage, PBShareAckMessage, ViewChangeMessage};
use proposal_promotion::{PPProposal, PPReceiver, PPSender, PPStatus};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Mutex,
};

use log::{debug, error, info};
use tokio::sync::RwLock;

use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Notify};

use self::{
    elect::Elect,
    error::{MVBAError, MVBAResult},
    messages::{
        MVBADoneMessage, MVBAReceiver, MVBASender, MVBASkipMessage, MVBASkipShareMessage,
        ProtocolMessage, ProtocolMessageHeader, ToProtocolMessage,
    },
    proposal_promotion::PPID,
    provable_broadcast::{PBResponse, PBSig, PBID},
    view_change::ViewChange,
};

mod elect;
mod error;
mod messages;
mod proposal_promotion;
mod provable_broadcast;
mod view_change;

// Keep LOCK and KEY variable consistent with paper
#[allow(non_snake_case)]

/// Instance of Multi-valued Validated Byzantine Agreement
pub struct MVBA<F: MVBASender> {
    /// Identifier for protocol
    id: usize,
    index: usize,
    n_parties: usize,
    /// Internal state
    state: RwLock<MVBAState>,
    notify_skip: Arc<Notify>,

    // Sub-protocol instances
    pp_send: RwLock<Option<PPSender>>,
    pp_recvs: RwLock<Option<HashMap<usize, PPReceiver>>>,
    elect: RwLock<Option<Elect>>,
    view_change: RwLock<Option<ViewChange>>,

    // Infrastructure
    send_handle: F,
    coin: Coin,
    signer: Signer,
}

impl<F: MVBASender> MVBA<F> {
    pub fn init(
        id: usize,
        index: usize,
        n_parties: usize,
        value: Value,
        send_handle: F,
        signer: Signer,
        coin: Coin,
    ) -> Self {
        Self {
            id,
            index,
            n_parties,
            state: RwLock::new(MVBAState::new(n_parties, value)),
            notify_skip: Arc::new(Notify::new()),
            pp_send: RwLock::new(None),
            pp_recvs: RwLock::new(None),
            elect: RwLock::new(None),
            view_change: RwLock::new(None),
            coin,
            signer,
            send_handle,
        }
    }

    pub async fn invoke(&self) -> MVBAResult<Value> {
        loop {
            let (id, index) = (self.id, self.index);

            self.init_state().await;

            // ***** PROPOSAL PROMOTION *****

            self.init_pp().await;

            let (key, value, view) = self.get_key_value_view().await;

            debug!(
                "Started invoke for id: {}, index: {}, view: {}",
                id, index, view
            );

            let lock = self.pp_send.read().await;

            let pp_send = lock
                .as_ref()
                .ok_or_else(|| MVBAError::UninitState("pp_send".to_string()))?;

            // wait for promotion to return. aka: 1. Succesfully promoted value or 2. self.skip[self.view]

            let notify_skip = self.notify_skip.clone();

            debug!(
                "Party {} started Promoting proposal with value: {:?}, view: {}",
                index, value, key.view
            );

            let promotion_proof: Option<PBSig> = tokio::select! {
                proof = pp_send.promote(value, key, &self.signer, &self.send_handle) => proof,
                _ = notify_skip.notified() => {
                    let mut state = self.state.write().await;
                    state.skip.insert(view, true);
                    None
                },
            };

            debug!(
                "Party {} finished promoting proposal, returning with proof: {:?}",
                index, promotion_proof
            );

            self.send_done_if_not_skip(id, index, promotion_proof)
                .await?;

            // ***** LEADER ELECTION *****

            self.abandon_all_ongoing_proposals();

            self.init_elect();

            let lock = self.elect.read().await;

            let elect = lock.as_ref().unwrap();

            let leader = elect.invoke(&self.coin, &self.send_handle).await;

            let mut state = self.state.write().await;

            state.leaders.insert(view, Some(leader));

            drop(state);

            // ***** VIEW CHANGE *****

            let id_leader = MVBAID {
                id,
                index: leader,
                view,
            };

            self.init_view_change(id_leader, view);

            let lock = self.view_change.read().await;

            let view_change = lock.as_ref().unwrap();

            //TODO: Get leaders proposals
            let leader_key = None;
            let leader_lock = None;
            let leader_commit = None;

            let changes = view_change
                .invoke(leader_key, leader_lock, leader_commit, &self.send_handle)
                .await;

            if let Some(value) = changes.value {
                return Ok(value);
            } else {
                let mut state = self.state.write().await;

                if let Some(lock) = changes.lock {
                    state.LOCK = lock;
                }
                if let Some(key) = changes.key {
                    state.KEY = key;
                }
                state.view += 1;
            }
        }
    }

    pub async fn handle_protocol_message(&mut self, message: ProtocolMessage) {
        let ProtocolMessage {
            header,
            message_data,
            message_type,
        } = message;
        let ProtocolMessageHeader {
            protocol_id,
            send_id,
            recv_id,
        } = header;

        info!(
            "Handling message from {} to {} with message_type {:?}",
            send_id, recv_id, message_type
        );

        match message_type {
            messages::ProtocolMessageType::MVBADone => {
                let inner: MVBADoneMessage = deserialize(&message_data).expect(
                    "Could not deserialize MVBADone message when handling protocol message",
                );

                self.on_done_message(send_id, inner).await;
            }
            messages::ProtocolMessageType::MVBASkipShare => {
                let inner: MVBASkipShareMessage = deserialize(&message_data).expect(
                    "Could not deserialize MVBASkipShare message when handling protocol message",
                );

                self.on_skip_share_message(send_id, inner).await;
            }
            messages::ProtocolMessageType::MVBASkip => {
                let inner: MVBASkipMessage = deserialize(&message_data).expect(
                    "Could not deserialize MVBASkip message when handling protocol message",
                );

                self.on_skip_message(inner).await;
            }
            messages::ProtocolMessageType::PBSend => {
                let pp_recvs = self.pp_recvs.read().await;

                if let Some(pp_recvs) = &*pp_recvs {
                    if let Some(pp) = pp_recvs.get(&send_id) {
                        let inner: PBSendMessage = deserialize(&message_data).expect(
                            "Could not deserialize PBSend message when handling protocol message",
                        );

                        let state = self.state.read().await;

                        let leader_index = state.leaders[&inner.proposal.proof.key.view]
                            .expect("Leader was not found for view");

                        let lock = state.LOCK;

                        let id = MVBAID {
                            id: self.id,
                            index: self.index,
                            view: state.view,
                        };

                        drop(state);

                        pp.on_value_send_message(
                            send_id,
                            inner,
                            &id,
                            leader_index,
                            lock,
                            &self.signer,
                            &self.send_handle,
                        )
                        .await;
                    }
                }
            }
            messages::ProtocolMessageType::PBShareAck => {
                let pp_send = self.pp_send.read().await;

                if let Some(pp_send) = &*pp_send {
                    let inner: PBShareAckMessage = deserialize(&message_data).expect(
                        "Could not deserialize PBShareAck message when handling protocol message",
                    );

                    pp_send.on_share_ack(send_id, inner, &self.signer).await;
                }
            }
            messages::ProtocolMessageType::ElectCoinShare => {
                let elect = self.elect.read().await;

                if let Some(elect) = &*elect {
                    let inner: ElectCoinShareMessage = deserialize(&message_data).expect(
                        "Could not deserialize ElectCoinShare message when handling protocol message",
                    );

                    elect.on_coin_share_message(inner, &self.coin);
                }
            }
            messages::ProtocolMessageType::ViewChange => {
                let view_change = self.view_change.read().await;

                if let Some(view_change) = &*view_change {
                    let inner: ViewChangeMessage = deserialize(&message_data).expect(
                        "Could not deserialize ViewChange message when handling protocol message",
                    );

                    view_change.on_view_change_message(&inner, &self.signer);
                }
            }
        }
    }

    pub async fn on_done_message(&self, index: usize, message: MVBADoneMessage) -> MVBAResult<()> {
        let MVBADoneMessage { id, proposal } = message;
        let PPProposal { value, proof } = proposal;
        let PBProof { proof_prev, .. } = proof;

        // Assert that done message has not already been received from party (index) in view (view)

        let state = self.state.read().await;

        if let Ok(true) = state
            .has_received_done
            .get(&id.view)
            .ok_or_else(|| MVBAError::UninitState("has_received_done".to_string()))?
            .get(&index)
            .ok_or_else(|| MVBAError::UninitState("has_received_done member".to_string()))
        {
            return Ok(());
        }

        drop(state);

        // Assert that proof is provided

        if let None = proof_prev {
            return Ok(());
        }

        // Assert that proof is valid

        let sig = proof_prev.ok_or_else(|| {
            MVBAError::InvariantBroken(
                "PBSig not Some after asserting it was not None ".to_string(),
            )
        })?;

        let response_prev = PBResponse {
            id: PBID {
                id: PPID { inner: id },
                step: PPStatus::Step4,
            },
            value,
        };

        if !self.signer.verify_signature(
            &sig.inner,
            &serialize(&response_prev).map_err(|_| {
                MVBAError::FailedSerialization(
                    "PBResponse".to_string(),
                    "on_done_message".to_string(),
                )
            })?,
        ) {
            return Ok(());
        }

        // Update state

        let mut state = self.state.write().await;

        state
            .has_received_done
            .entry(id.view)
            .or_insert(Default::default())
            .insert(index, true);

        *state.pp_done.entry(id.view).or_insert(0) += 1;

        // If enough done messages have been collected to elect leader, and we have not sent out skip_share, send it.

        if !*state.has_sent_skip_share.entry(id.view).or_default()
            && state.pp_done[&id.view] >= (state.n_parties * 2 / 3) + 1
        {
            let tag = self.tag_skip_share(id.id, id.view);

            let share = SkipShare {
                inner: self.signer.sign(&tag.as_bytes()),
            };

            let skip_share_message = MVBASkipShareMessage { id, share };

            for i in 0..state.n_parties {
                self.send_handle
                    .send(
                        i,
                        skip_share_message.to_protocol_message(id.id, self.index, i),
                    )
                    .await;
            }

            state.has_sent_skip_share.insert(id.view, true);
        }

        Ok(())
    }

    pub async fn on_skip_share_message(
        &self,
        index: usize,
        message: MVBASkipShareMessage,
    ) -> MVBAResult<()> {
        let MVBASkipShareMessage { id, share } = message;

        // Assert that skip share message has not already been received from party (index) in view (view)

        let state = self.state.read().await;

        if let Ok(true) = state
            .has_received_skip_share
            .get(&id.view)
            .ok_or_else(|| MVBAError::UninitState("has_received_skip_share".to_string()))?
            .get(&index)
            .ok_or_else(|| MVBAError::UninitState("has_received_skip_share member".to_string()))
        {
            return Ok(());
        }

        drop(state);

        // Assert that skip share is valid for index

        let tag = self.tag_skip_share(id.id, id.view);

        if !self
            .signer
            .verify_share(index, &share.inner, &tag.as_bytes())
        {
            return Ok(());
        }

        // Update state

        let mut state = self.state.write().await;

        state.pp_skip.entry(id.view).or_default().insert(share);

        // If we have received enough skip_shares to construct a skip signature, construct and broadcast it.

        if !*state.has_sent_skip.entry(id.view).or_default()
            && state.pp_skip.entry(id.view).or_default().len() >= (state.n_parties * 2 / 3) + 1
        {
            let shares = state.pp_skip[&id.view]
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

            state.has_sent_skip.insert(id.view, true);

            for i in 0..state.n_parties {
                self.send_handle
                    .send(i, skip_message.to_protocol_message(id.id, self.index, i))
                    .await;
            }
        }
        Ok(())
    }

    pub async fn on_skip_message(&self, message: MVBASkipMessage) {
        let MVBASkipMessage { id, sig } = message;

        // Assert that the skip signature is valid

        let tag = self.tag_skip_share(id.id, id.view);

        if !self.signer.verify_signature(&sig.inner, tag.as_bytes()) {
            return;
        }

        // Update state

        let mut state = self.state.write().await;

        state.skip.insert(id.view, true);

        // Propogate skip message, if we have not sent a skip message for the current view

        if !*state.has_sent_skip.entry(id.view).or_default() {
            let skip_message = MVBASkipMessage { id, sig };

            for i in 0..state.n_parties {
                self.send_handle
                    .send(i, skip_message.to_protocol_message(id.id, self.index, i))
                    .await;
            }

            state.has_sent_skip.insert(id.view, true);
        }

        // wake up invoke()-task, since we are ready to continue to election process

        self.notify_skip.notify_one();
    }

    async fn get_key_value_view(&self) -> (PBKey, Value, usize) {
        let state = self.state.read().await;

        let key = PBKey {
            view: state.KEY.view,
            view_key_proof: state.KEY.proof.clone(),
        };

        let value = state.KEY.value;

        let view = state.view;

        (key, value, view)
    }

    async fn send_done_if_not_skip(
        &self,
        id: usize,
        index: usize,
        promotion_proof: Option<PBSig>,
    ) -> MVBAResult<()> {
        let state = self.state.read().await;

        if let Ok(false) = state
            .skip
            .get(&state.view)
            .ok_or_else(|| MVBAError::UninitState("skip".to_string()))
        {
            let proposal = PPProposal {
                value: state.KEY.value,
                proof: PBProof {
                    key: PBKey {
                        view: state.KEY.view,
                        view_key_proof: state.KEY.proof.clone(),
                    },
                    proof_prev: promotion_proof,
                },
            };

            let mvba_done = MVBADoneMessage {
                id: MVBAID {
                    id: self.id,
                    index: self.index,
                    view: state.view,
                },
                proposal,
            };

            for i in 0..state.n_parties {
                self.send_handle
                    .send(i, mvba_done.to_protocol_message(id, index, i))
                    .await;
            }
            self.notify_skip.notified().await;
        }

        Ok(())
    }

    async fn init_state(&self) {
        let mut state = self.state.write().await;

        state.step();
    }

    async fn init_pp(&self) {
        let state = self.state.read().await;

        let pp_id = PPID {
            inner: MVBAID {
                id: self.id,
                index: self.index,
                view: state.view,
            },
        };

        drop(state);

        {
            let pp_send = PPSender::init(pp_id, self.index, self.n_parties);

            let mut lock = self.pp_send.write().await;

            lock.replace(pp_send);
        }

        {
            let pp_recvs = (0..self.n_parties)
                .filter_map(|i| {
                    if self.index != i {
                        Some((i, PPReceiver::init(pp_id, self.index)))
                    } else {
                        None
                    }
                })
                .collect();

            let mut lock = self.pp_recvs.write().await;

            lock.replace(pp_recvs);
        }
    }

    async fn init_elect(&self) {
        let elect = Elect::init(self.id, self.index, self.n_parties);

        let mut lock = self.elect.write().await;

        lock.replace(elect);
    }

    async fn init_view_change(&self, id_leader: MVBAID, view: usize) {
        let state = self.state.read().await;
        let view_change =
            ViewChange::init(id_leader, view, self.n_parties, state.KEY.view, state.LOCK);
        drop(state);

        let mut lock = self.view_change.write().await;
        lock.replace(view_change);
    }

    async fn abandon_all_ongoing_proposals(&self) {
        let lock = self.pp_recvs.read().await;

        if let Some(recvs) = &*lock {
            futures::future::join_all(recvs.values().map(|recv| recv.abandon()));
        }
    }

    fn tag_skip_share(&self, id: usize, view: usize) -> String {
        format!("{}-SKIP-{}", id, view)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct Value {
    inner: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct MVBAID {
    id: usize,
    index: usize,
    view: usize,
}

struct MVBAState {
    /// Number of parties taking part in protocol
    view: usize,
    n_parties: usize,
    status: MVBAStatus,
    LOCK: usize,
    KEY: Key,
    /// Index of elected leader per view, if existing.
    leaders: HashMap<usize, Option<usize>>,
    /// Whether a MVBADoneMessage has been received from a certain party, for a particular view.
    has_received_done: HashMap<usize, HashMap<usize, bool>>,
    /// Number of unique MVBADoneMessages received for a particular view.
    pp_done: HashMap<usize, usize>,
    /// Whether a MVBASkipShareMessage has been received from a certain party, for a particular view.
    has_received_skip_share: HashMap<usize, HashMap<usize, bool>>,
    /// Whether the current party has sent out a MVBASkipShareMessage for a particular view.
    has_sent_skip_share: HashMap<usize, bool>,
    /// Collection of unique MVBASkipShareMessage received for a particular view.
    pp_skip: HashMap<usize, HashSet<SkipShare>>,
    /// Whether the current party has sent out a MVBASkipMessage for a particular view.
    has_sent_skip: HashMap<usize, bool>,
    /// Whether the current party can proceed to the election phase for a particular view.
    skip: HashMap<usize, bool>,
}

impl MVBAState {
    fn new(n_parties: usize, value: Value) -> Self {
        Self {
            view: 0,
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
        }
    }

    fn step(&mut self) {
        self.view += 1;

        let view = self.view;

        self.leaders.insert(view, None);
        self.pp_done.insert(view, 0);
        self.has_sent_skip.insert(view, false);
        self.skip.insert(view, false);
        self.pp_skip.insert(view, HashSet::new());

        self.has_received_done
            .insert(view, (0..self.n_parties).map(|i| (i, false)).collect());
        self.has_received_skip_share
            .insert(view, (0..self.n_parties).map(|i| (i, false)).collect());
    }
}

enum MVBAStatus {
    Init,
    Nomination,
    Election,
    ViewChange,
    Finished,
}

#[derive(Clone)]
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

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use futures::future::join_all;

    use super::*;
    use tokio::sync::mpsc::{self, Receiver, Sender};
    use tokio::test;

    const N_PARTIES: usize = 4;
    const THRESHOLD: usize = 1;

    struct ChannelSender {
        senders: HashMap<usize, Sender<ProtocolMessage>>,
    }

    #[async_trait]
    impl MVBASender for ChannelSender {
        async fn send(&self, index: usize, message: ProtocolMessage) {
            if !self.senders.contains_key(&index) {
                return;
            }
            debug!("Sending message to party {}", index);

            let sender = &self.senders[&index];
            if let Err(e) = sender.send(message).await {
                error!("Got error when sending message: {}", e);
            }
        }
    }

    struct ChannelReceiver {
        recv: Receiver<ProtocolMessage>,
    }

    #[async_trait]
    impl MVBAReceiver for ChannelReceiver {
        async fn receive(&mut self) -> Option<ProtocolMessage> {
            self.recv.recv().await
        }
    }

    #[test]
    async fn test_it_works() {
        env_logger::init();

        let mut signers = Signer::generate_signers(N_PARTIES, THRESHOLD);
        let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD);

        assert_eq!(signers.len(), N_PARTIES);
        assert_eq!(coins.len(), N_PARTIES);

        let mut channels: Vec<_> = (0..N_PARTIES)
            .map(|_| {
                let (tx, rx) = mpsc::channel(20);
                (tx, Some(rx))
            })
            .collect();

        let mut handles = Vec::with_capacity(N_PARTIES);

        for i in 0..N_PARTIES {
            let mut recv = channels[i].1.take().unwrap();
            let senders: HashMap<usize, Sender<_>> = channels
                .iter()
                .enumerate()
                .filter_map(|(j, channel)| {
                    if i != j {
                        Some((j, channel.0.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            let signer = signers.remove(0);
            let coin = coins.remove(0);

            let f = ChannelSender { senders };

            let mvba = Arc::new(MVBA::init(
                0,
                i,
                N_PARTIES,
                Value { inner: i * 1000 },
                f,
                signer,
                coin,
            ));

            let mvba2 = mvba.clone();

            let main_handle = tokio::spawn(async move {
                debug!("Started main {}", i);
                mvba.invoke();
            });
            tokio::spawn(async move {
                debug!("Started messaging for {}", i);
                while let Some(message) = recv.recv().await {
                    debug!("Received message at {}", i);
                    mvba2.handle_protocol_message(message).await;
                }
            });

            handles.push(main_handle);
        }

        let results = join_all(handles).await;

        for (i, result) in results.iter().enumerate() {
            if let Ok(value) = result {
                debug!("Value returned party {} = {:?}", i, value);
            }
        }
    }
}
