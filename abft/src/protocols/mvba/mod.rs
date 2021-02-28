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
};

use log::{debug, error, info, warn};
use tokio::sync::RwLock;

use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Mutex, Notify};

use self::{
    buffer::{MVBABuffer, MVBABufferCommand},
    elect::Elect,
    error::{MVBAError, MVBAResult},
    messages::{
        MVBADoneMessage, MVBASender, MVBASkipMessage, MVBASkipShareMessage, ProtocolMessage,
        ProtocolMessageHeader, ToProtocolMessage,
    },
    proposal_promotion::{PPError, PPLeader, PPResult, PPID},
    provable_broadcast::{PBResponse, PBSig, PBID},
    view_change::{ViewChange, ViewChangeError},
};

pub mod buffer;
mod elect;
pub mod error;
pub mod messages;
mod proposal_promotion;
mod provable_broadcast;
mod view_change;

// Keep LOCK and KEY variable consistent with paper
#[allow(non_snake_case)]

/// Instance of Multi-valued Validated Byzantine Agreement
pub struct MVBA<F: MVBASender + Sync + Send> {
    /// Identifier for protocol
    id: usize,
    index: usize,
    n_parties: usize,
    /// Internal state
    state: RwLock<MVBAState>,
    notify_skip: Arc<Notify>,

    // Sub-protocol instances
    pp_send: RwLock<Option<PPSender>>,
    pp_recvs: RwLock<Option<HashMap<usize, Arc<PPReceiver>>>>,
    elect: RwLock<Option<Elect>>,
    view_change: RwLock<Option<ViewChange>>,

    // Infrastructure
    send_handle: F,
    coin: Coin,
    signer: Signer,
}

impl<F: MVBASender + Sync + Send> MVBA<F> {
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

    pub async fn invoke(&self, buff_handle: Sender<MVBABufferCommand>) -> MVBAResult<Value> {
        loop {
            let (id, index) = (self.id, self.index);

            self.init_state().await;

            // ***** PROPOSAL PROMOTION *****

            self.init_pp().await;

            let (key, value, view) = self.get_key_value_view().await;

            info!(
                "Started invoke for id: {}, index: {}, view: {}",
                id, index, view
            );

            // Invoke pp_recvs

            {
                let read_lock = self.pp_recvs.read().await;

                let pp_recvs = read_lock
                    .as_ref()
                    .ok_or_else(|| MVBAError::UninitState("pp_recvs".to_string()))?;

                for pp_recv in pp_recvs.values() {
                    let pp_clone = pp_recv.clone();
                    let buff_clone = buff_handle.clone();

                    tokio::spawn(async move {
                        pp_clone.invoke(buff_clone).await;
                    });
                }
            }

            // Invoke pp_send

            {
                let lock = self.pp_send.read().await;

                let pp_send = lock
                    .as_ref()
                    .ok_or_else(|| MVBAError::UninitState("pp_send".to_string()))?;

                // wait for promotion to return. aka: 1. Succesfully promoted value or 2. self.skip[self.view]

                let notify_skip = self.notify_skip.clone();

                info!(
                    "Party {} started Promoting proposal with value: {:?}, view: {}",
                    index, value, view
                );

                let promotion_proof: Option<PBSig> = tokio::select! {
                    proof = pp_send.promote(value, key, &self.signer, &self.send_handle) => proof,
                    _ = notify_skip.notified() => {
                        None
                    },
                };

                info!(
                    "Party {} finished promoting proposal, returning with proof: {:?}",
                    index, promotion_proof
                );

                self.send_done_if_not_skip(id, index, promotion_proof)
                    .await?;
            }

            // ***** LEADER ELECTION *****

            self.abandon_all_ongoing_proposals().await;

            self.init_elect(view).await;

            let lock = self.elect.read().await;

            let elect = lock.as_ref().unwrap();

            info!("Party {} started electing phase for view: {}", index, view);

            buff_handle
                .send(MVBABufferCommand::ElectCoinShare { view })
                .await?;

            let leader = elect.invoke(&self.coin, &self.send_handle).await?;

            info!(
                "Party {} finished electing phase for view: {}, electing the leader: {} ",
                index, view, leader
            );

            {
                let mut state = self.state.write().await;

                state.leaders.insert(view, Some(leader));
            }

            // ***** VIEW CHANGE *****

            let id_leader = MVBAID {
                id,
                index: leader,
                view,
            };

            let result = self.get_leader_result(leader).await?;

            self.init_view_change(index, id_leader, view).await;

            buff_handle
                .send(MVBABufferCommand::ViewChange { view })
                .await?;

            let lock = self.view_change.read().await;

            let view_change = lock.as_ref().unwrap();

            let changes = view_change
                .invoke(result.key, result.lock, result.commit, &self.send_handle)
                .await?;

            info!("Party {} succesfully completed view change in view: {}. Leader: {}, with result: {:?}", index, view, leader, changes);

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
            }
        }
    }

    pub async fn handle_protocol_message(&self, message: ProtocolMessage) -> MVBAResult<()> {
        let ProtocolMessage {
            header,
            message_data,
            message_type,
        } = message;
        let ProtocolMessageHeader {
            protocol_id,
            send_id,
            recv_id,
            ..
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

                self.on_done_message(send_id, inner).await?;
            }
            messages::ProtocolMessageType::MVBASkipShare => {
                let inner: MVBASkipShareMessage = deserialize(&message_data).expect(
                    "Could not deserialize MVBASkipShare message when handling protocol message",
                );

                self.on_skip_share_message(send_id, inner).await?;
            }
            messages::ProtocolMessageType::MVBASkip => {
                let inner: MVBASkipMessage = deserialize(&message_data).expect(
                    "Could not deserialize MVBASkip message when handling protocol message",
                );

                self.on_skip_message(inner).await?;
            }
            messages::ProtocolMessageType::PBSend => {
                let pp_recvs = self.pp_recvs.read().await;
                if let Some(pp_recvs) = &*pp_recvs {
                    if let Some(pp) = pp_recvs.get(&send_id) {
                        let inner: PBSendMessage = deserialize(&message_data).expect(
                            "Could not deserialize PBSend message when handling protocol message",
                        );

                        match self.on_pb_send_message(pp, inner, send_id).await {
                            Ok(_) => return Ok(()),
                            Err(PPError::NotReadyForSend) => {
                                return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                                    header,
                                    message_data,
                                    message_type,
                                }));
                            }
                            Err(e) => return Err(MVBAError::PPError(e)),
                        }
                    } else {
                        warn!("Did not find PPReceiver {} for Party {}!", send_id, recv_id);
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                } else {
                    warn!("pprecvs was not initialized for Party {}!", recv_id);
                    return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                        header,
                        message_data,
                        message_type,
                    }));
                }
            }
            messages::ProtocolMessageType::PBShareAck => {
                let pp_send = self.pp_send.read().await;

                if let Some(pp_send) = &*pp_send {
                    debug!("Found PPRSender {} for Party {}", send_id, recv_id);
                    let inner: PBShareAckMessage = deserialize(&message_data).expect(
                        "Could not deserialize PBShareAck message when handling protocol message",
                    );

                    if let Err(PPError::NotReadyForShareAck) =
                        pp_send.on_share_ack(send_id, inner, &self.signer).await
                    {
                        warn!("pp_send not ready for message at Party {}!", recv_id);
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
            }
            messages::ProtocolMessageType::ElectCoinShare => {
                let elect = self.elect.read().await;

                if let Some(elect) = &*elect {
                    let inner: ElectCoinShareMessage = deserialize(&message_data).expect(
                        "Could not deserialize ElectCoinShare message when handling protocol message",
                    );

                    elect.on_coin_share_message(inner, &self.coin)?;
                } else {
                    debug!(
                        "Party {}'s elect was not initialized, but got elect message from {}!",
                        recv_id, send_id
                    );
                    return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                        header,
                        message_data,
                        message_type,
                    }));
                }
            }
            messages::ProtocolMessageType::ViewChange => {
                let view_change = self.view_change.read().await;

                if let Some(view_change) = &*view_change {
                    let inner: ViewChangeMessage = deserialize(&message_data).expect(
                        "Could not deserialize ViewChange message when handling protocol message",
                    );

                    match view_change.on_view_change_message(&inner, &self.signer) {
                        Ok(_) => return Ok(()),
                        Err(ViewChangeError::ResultAlreadyTaken) => {
                            // If ViewChangeResult was taken, this should only happen if the result was returned
                            // to the invoke task. It is therefore fine to ignore.
                            return Ok(());
                        }
                        Err(e) => return Err(MVBAError::ViewChangeError(e)),
                    };
                } else {
                    debug!("Party {}'s viewChange was not initialized, but got view_change message from {}!", recv_id, send_id);
                    return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                        header,
                        message_data,
                        message_type,
                    }));
                }
            }
            messages::ProtocolMessageType::Unknown => {}
        }
        Ok(())
    }

    pub async fn on_done_message(&self, index: usize, message: MVBADoneMessage) -> MVBAResult<()> {
        let MVBADoneMessage { id, proposal } = message;
        let PPProposal { value, proof } = proposal;
        let PBProof { proof_prev, .. } = proof;

        debug!(
            "Calling MVBA::on_done_message for Party {} on message from Party {}",
            self.index, index
        );

        // Assert that done message has not already been received from party (index) in view (view)
        {
            let state = self.state.read().await;

            if let Ok(true) = state
                .has_received_done
                .get(&id.view)
                .ok_or_else(|| MVBAError::UninitState("has_received_done".to_string()))?
                .get(&index)
                .ok_or_else(|| MVBAError::UninitState("has_received_done member".to_string()))
            {
                warn!(
                    "Party {} had already received a done message from Party {} in view: {}",
                    self.index, index, state.view
                );
                return Ok(());
            }
        }

        debug!(
            "Had not received done message earlier on MVBA::on_done_message for Party {} on message from Party {}",
            self.index, index
        );

        // Assert that proof is provided

        if let None = proof_prev {
            warn!(
                "Party {} received a done message from Party {} with an empty proof",
                self.index, index,
            );
            return Ok(());
        }

        debug!(
            "Proof was not None for done message earlier on MVBA::on_done_message for Party {} on message from Party {}",
            self.index, index
        );

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
            warn!(
                "Party {} received a done message from Party {} with an invalid proof",
                self.index, index,
            );
            return Ok(());
        }

        debug!(
            "Proof was valid for done message earlier on MVBA::on_done_message for Party {} on message from Party {}",
            self.index, index
        );

        // Update state

        let mut state = self.state.write().await;

        state
            .has_received_done
            .entry(id.view)
            .or_insert(Default::default())
            .insert(index, true);

        *state.pp_done.entry(id.view).or_insert(0) += 1;

        // If enough done messages have been collected to elect leader, and we have not sent out skip_share, send it.

        debug!(
            "Party {} has received enough MVBADone messages to send skip share: {}",
            self.index,
            !*state.has_sent_skip_share.entry(id.view).or_default()
                && state.pp_done[&id.view] >= (state.n_parties * 2 / 3) + 1
        );

        if !*state.has_sent_skip_share.entry(id.view).or_default()
            && state.pp_done[&id.view] >= (state.n_parties * 2 / 3) + 1
        {
            let tag = self.tag_skip_share(id.id, id.view);

            let share = SkipShare {
                inner: self.signer.sign(&tag.as_bytes()),
            };

            let skip_share_message = MVBASkipShareMessage { id, share };

            self.send_handle
                .broadcast(
                    id.id,
                    self.index,
                    self.n_parties,
                    state.view,
                    skip_share_message,
                )
                .await;

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

        {
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
        }

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

        state
            .pp_skip
            .entry(id.view)
            .or_default()
            .insert(index, share);

        // If we have received enough skip_shares to construct a skip signature, construct and broadcast it.

        if !*state.has_sent_skip.entry(id.view).or_default()
            && state.pp_skip.entry(id.view).or_default().len() >= (state.n_parties * 2 / 3) + 1
        {
            let shares = state.pp_skip[&id.view]
                .clone()
                .into_iter()
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

            self.send_handle
                .broadcast(id.id, self.index, self.n_parties, state.view, skip_message)
                .await;
        }
        Ok(())
    }

    pub async fn on_skip_message(&self, message: MVBASkipMessage) -> MVBAResult<()> {
        let MVBASkipMessage { id, sig } = message;

        // Assert that the skip signature is valid

        let tag = self.tag_skip_share(id.id, id.view);

        if !self.signer.verify_signature(&sig.inner, tag.as_bytes()) {
            return Err(MVBAError::InvalidSignature("skip message".to_string()));
        }

        // Update state

        let mut state = self.state.write().await;

        // Propogate skip message, if we have not sent a skip message for the current view

        if !*state.has_sent_skip.entry(id.view).or_default() {
            let skip_message = MVBASkipMessage { id, sig };

            self.send_handle
                .broadcast(id.id, self.index, self.n_parties, state.view, skip_message)
                .await;

            state.has_sent_skip.insert(id.view, true);
        }

        if !*state.skip.entry(id.view).or_default() {
            state.skip.insert(id.view, true);
            // wake up invoke()-task, since we are ready to continue to election process
            self.notify_skip.notify_one();
        }

        Ok(())
    }

    pub async fn on_pb_send_message(
        &self,
        pp: &Arc<PPReceiver>,
        message: PBSendMessage,
        send_id: usize,
    ) -> PPResult<()> {
        let state = self.state.read().await;

        let leader_index = match &message.proposal.proof.key.view {
            view if *view == 0 => 0,
            _ => state.leaders[&message.proposal.proof.key.view]
                .expect("Leader was not found for view"),
        };

        let lock = state.LOCK;

        let id = MVBAID {
            id: self.id,
            index: send_id,
            view: state.view,
        };

        drop(state);

        pp.on_value_send_message(
            send_id,
            message,
            &id,
            leader_index,
            lock,
            &self.signer,
            &self.send_handle,
        )
        .await?;

        Ok(())
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

    async fn get_leader_result(&self, leader: usize) -> MVBAResult<PPLeader> {
        if leader == self.index {
            let lock = self.pp_send.read().await;
            let pp_send = lock
                .as_ref()
                .ok_or_else(|| MVBAError::UninitState("pp_send".to_string()))?;
            Ok(pp_send.result().await)
        } else {
            let lock = self.pp_recvs.read().await;
            let pp_recvs = lock
                .as_ref()
                .ok_or_else(|| MVBAError::UninitState("pp_recvs".to_string()))?;
            let leader_recv = &pp_recvs[&leader];
            Ok(leader_recv.result().await)
        }
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

            self.send_handle
                .broadcast(id, self.index, self.n_parties, state.view, mvba_done)
                .await;

            drop(state);
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
                        Some((i, Arc::new(PPReceiver::init(pp_id, self.index, i))))
                    } else {
                        None
                    }
                })
                .collect();

            let mut lock = self.pp_recvs.write().await;

            lock.replace(pp_recvs);
        }
    }

    async fn init_elect(&self, view: usize) {
        let elect = Elect::init(self.id, self.index, view, self.n_parties);

        let mut lock = self.elect.write().await;

        lock.replace(elect);
    }

    async fn init_view_change(&self, index: usize, id_leader: MVBAID, view: usize) {
        let state = self.state.read().await;
        let view_change = ViewChange::init(
            id_leader,
            index,
            view,
            self.n_parties,
            state.KEY.view,
            state.LOCK,
        );
        drop(state);

        let mut lock = self.view_change.write().await;
        lock.replace(view_change);
    }

    async fn abandon_all_ongoing_proposals(&self) {
        let lock = self.pp_recvs.read().await;

        if let Some(recvs) = &*lock {
            futures::future::join_all(recvs.values().map(|recv| recv.abandon())).await;
        }
    }

    fn tag_skip_share(&self, id: usize, view: usize) -> String {
        format!("{}-SKIP-{}", id, view)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct Value {
    pub(crate) inner: usize,
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
    pp_skip: HashMap<usize, HashMap<usize, SkipShare>>,
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
        self.pp_skip.insert(view, HashMap::new());

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

#[derive(Debug, Clone)]
pub struct Key {
    view: usize,
    value: Value,
    proof: Option<PBSig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SkipShare {
    inner: SignatureShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkipSig {
    inner: Signature,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use async_trait::async_trait;

    use futures::future::join_all;
    use log::{debug, error};

    use super::*;
    use consensus_core::{
        crypto::{commoncoin::Coin, sign::Signer},
        data::message_buffer::MessageBuffer,
    };
    use tokio::sync::mpsc::{self, Receiver, Sender};
    use tokio::test;

    const N_PARTIES: usize = 4;
    const THRESHOLD: usize = 1;
}
