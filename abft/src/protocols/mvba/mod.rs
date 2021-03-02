use crate::messaging::{ProtocolMessage, ProtocolMessageHeader, ProtocolMessageSender};
use bincode::{deserialize, serialize};
use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use proposal_promotion::{PPProposal, PPReceiver, PPSender, PPStatus};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use log::{error, info, warn};
use tokio::sync::RwLock;

use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Notify};

use crate::Value;

use crate::messaging::ProtocolMessageType;

use self::{
    buffer::MVBABufferCommand,
    elect::Elect,
    error::{MVBAError, MVBAResult},
    messages::{
        ElectCoinShareMessage, MVBADoneMessage, MVBAMessageType, MVBASkipMessage,
        MVBASkipShareMessage, PBSendMessage, PBShareAckMessage, ViewChangeMessage,
    },
    proposal_promotion::{PPError, PPLeader, PPResult, PPID},
    provable_broadcast::{PBResponse, PBSig, PBID},
    view_change::{ViewChange, ViewChangeError},
};

pub mod buffer;
pub mod elect;
pub mod error;
pub mod messages;
pub mod proposal_promotion;
pub mod provable_broadcast;
pub mod view_change;

/// Instance of Multi-valued Validated Byzantine Agreement
pub struct MVBA<F: ProtocolMessageSender + Sync + Send> {
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

impl<F: ProtocolMessageSender + Sync + Send> MVBA<F> {
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
                    let index = self.index;

                    tokio::spawn(async move {
                        match pp_clone.invoke(buff_clone).await {
                            Ok(_) => {}
                            Err(PPError::Abandoned) => {}
                            Err(e) => {
                                error!("Party {} received error on invoking pp_recv: {}", index, e);
                            }
                        }
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
                    proof = pp_send.promote(value, key, &self.signer, &self.send_handle) => proof?,
                    _ = notify_skip.notified() => {
                        None
                    },
                };

                info!(
                    "Party {} finished promoting proposal, returning with proof: {:?}",
                    index, promotion_proof
                );

                self.send_done_if_not_skip(promotion_proof).await?;
            }

            // ***** LEADER ELECTION *****

            self.abandon_all_ongoing_proposals().await;

            self.init_elect(view).await;

            let lock = self.elect.read().await;

            let elect = lock.as_ref().expect("Elect should be initialized");

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

            let view_change = lock.as_ref().expect("ViewChange should be initialized");

            info!("Party {} started view change for view: {}", index, view);

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
            send_id, recv_id, ..
        } = header;

        info!(
            "Handling message from {} to {} with message_type {:?}",
            send_id, recv_id, message_type
        );

        if let ProtocolMessageType::MVBA(mvba_message_type) = &message_type {
            match mvba_message_type {
                MVBAMessageType::MVBADone => {
                    let inner: MVBADoneMessage = deserialize(&message_data)?;

                    self.on_done_message(send_id, inner).await?;
                }
                MVBAMessageType::MVBASkipShare => {
                    let inner: MVBASkipShareMessage = deserialize(&message_data)?;

                    self.on_skip_share_message(send_id, inner).await?;
                }
                MVBAMessageType::MVBASkip => {
                    let inner: MVBASkipMessage = deserialize(&message_data)?;

                    self.on_skip_message(inner).await?;
                }
                MVBAMessageType::PBSend => {
                    let pp_recvs = self.pp_recvs.read().await;
                    if let Some(pp_recvs) = &*pp_recvs {
                        if let Some(pp) = pp_recvs.get(&send_id) {
                            let inner: PBSendMessage = deserialize(&message_data)?;

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
                MVBAMessageType::PBShareAck => {
                    let pp_send = self.pp_send.read().await;

                    if let Some(pp_send) = &*pp_send {
                        let inner: PBShareAckMessage = deserialize(&message_data)?;

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
                MVBAMessageType::ElectCoinShare => {
                    let elect = self.elect.read().await;

                    if let Some(elect) = &*elect {
                        let inner: ElectCoinShareMessage = deserialize(&message_data)?;

                        elect.on_coin_share_message(inner, &self.coin)?;
                    } else {
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
                MVBAMessageType::ViewChange => {
                    let view_change = self.view_change.read().await;

                    if let Some(view_change) = &*view_change {
                        let inner: ViewChangeMessage = deserialize(&message_data)?;

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
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header,
                            message_data,
                            message_type,
                        }));
                    }
                }
            }
        } else {
            warn!(
                "Message with other ProtocolMessageType: {:?} than MVBA was passed to MVBA.",
                message_type
            )
        }
        Ok(())
    }

    pub async fn on_done_message(&self, index: usize, message: MVBADoneMessage) -> MVBAResult<()> {
        let MVBADoneMessage { id, proposal } = message;
        let PPProposal { value, proof } = proposal;
        let PBProof { proof_prev, .. } = proof;

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

        // Assert that proof is provided

        if let None = proof_prev {
            warn!(
                "Party {} received a done message from Party {} with an empty proof",
                self.index, index,
            );
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

        if !self
            .signer
            .verify_signature(&sig.inner, &serialize(&response_prev)?)
        {
            warn!(
                "Party {} received a done message from Party {} with an invalid proof",
                self.index, index,
            );
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

            let skip_share_message = MVBASkipShareMessage::new(id, share);

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

            let skip_proof = self
                .signer
                .combine_signatures(&shares)
                .map_err(|_| MVBAError::InvalidSignature("on_skip_share".to_string()))?;

            let skip_message = MVBASkipMessage::new(id, SkipSig { inner: skip_proof });

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

    async fn send_done_if_not_skip(&self, promotion_proof: Option<PBSig>) -> MVBAResult<()> {
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

            let mvba_done = MVBADoneMessage::new(
                MVBAID {
                    id: self.id,
                    index: self.index,
                    view: state.view,
                },
                proposal,
            );

            self.send_handle
                .broadcast(self.id, self.index, self.n_parties, state.view, mvba_done)
                .await;

            drop(state);

            info!("Party {} waiting at send_done_skip", self.index);
            self.notify_skip.notified().await;
            info!("Party {} done waiting at send_done_skip", self.index);
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
pub struct MVBAID {
    id: usize,
    index: usize,
    view: usize,
}

// Keep LOCK and KEY variable consistent with paper
#[allow(non_snake_case)]
struct MVBAState {
    /// Number of parties taking part in protocol
    view: usize,
    n_parties: usize,
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
    use std::collections::HashMap;

    use async_trait::async_trait;

    use futures::future::join_all;

    use crate::messaging::ToProtocolMessage;

    use super::buffer::MVBABuffer;
    use super::*;

    use consensus_core::crypto::{commoncoin::Coin, sign::Signer};
    use tokio::sync::mpsc::{self, Sender};
    use tokio::test;

    use log::error;

    const N_PARTIES: usize = THRESHOLD * 3 + 1;
    const THRESHOLD: usize = 1;
    const BUFFER_CAPACITY: usize = THRESHOLD * 30;

    struct ChannelSender {
        senders: HashMap<usize, Sender<ProtocolMessage>>,
    }

    #[async_trait]
    impl ProtocolMessageSender for ChannelSender {
        async fn send<M: ToProtocolMessage + Send + Sync>(
            &self,
            id: usize,
            send_id: usize,
            recv_id: usize,
            view: usize,
            message: M,
        ) {
            if !self.senders.contains_key(&recv_id) {
                return;
            }

            let sender = &self.senders[&recv_id];
            if let Err(e) = sender
                .send(message.to_protocol_message(id, send_id, recv_id, view))
                .await
            {
                error!("Got error when sending message: {}", e);
            }
        }

        async fn broadcast<M: ToProtocolMessage + Send + Sync>(
            &self,
            id: usize,
            send_id: usize,
            n_parties: usize,
            view: usize,
            message: M,
        ) {
            let message = message.to_protocol_message(id, send_id, 0, view);

            for i in (0..n_parties) {
                if !self.senders.contains_key(&i) {
                    continue;
                }
                let mut inner = message.clone();
                inner.header.recv_id = i;
                let sender = &self.senders[&i];
                if let Err(e) = sender.send(inner).await {
                    error!("Got error when sending message: {}", e);
                }
            }
        }
    }

    #[test]
    async fn test_correctness() {
        env_logger::init();

        let mut signers = Signer::generate_signers(N_PARTIES, N_PARTIES - THRESHOLD - 1);
        let mut coins = Coin::generate_coins(N_PARTIES, THRESHOLD + 1);

        assert_eq!(signers.len(), N_PARTIES);
        assert_eq!(coins.len(), N_PARTIES);

        let mut channels: Vec<_> = (0..N_PARTIES)
            .map(|_| {
                let (tx, rx) = mpsc::channel(BUFFER_CAPACITY);
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

            // Setup buffer manager

            let mut buffer = MVBABuffer::new();

            let buffer_mvba = mvba.clone();

            let (buff_cmd_send, mut buff_cmd_recv) =
                mpsc::channel::<MVBABufferCommand>(BUFFER_CAPACITY);

            tokio::spawn(async move {
                while let Some(command) = buff_cmd_recv.recv().await {
                    let messages = buffer.execute(command);

                    for message in messages {
                        match buffer_mvba.handle_protocol_message(message).await {
                            Ok(_) => {}
                            Err(MVBAError::NotReadyForMessage(early_message)) => {
                                buffer.execute(MVBABufferCommand::Store {
                                    message: early_message,
                                });
                            }

                            Err(e) => error!(
                                "Party {} got error when handling protocol message: {}",
                                i, e
                            ),
                        }
                    }
                }
            });

            // Setup messaging manager

            let msg_buff_send = buff_cmd_send.clone();

            let msg_mvba = mvba.clone();

            tokio::spawn(async move {
                while let Some(message) = recv.recv().await {
                    match msg_mvba.handle_protocol_message(message).await {
                        Ok(_) => {}
                        Err(MVBAError::NotReadyForMessage(early_message)) => msg_buff_send
                            .send(MVBABufferCommand::Store {
                                message: early_message,
                            })
                            .await
                            .unwrap(),

                        Err(e) => error!(
                            "Party {} got error when handling protocol message: {}",
                            i, e
                        ),
                    }
                }
            });

            // setup main thread

            let main_buff_send = buff_cmd_send.clone();

            let main_handle = tokio::spawn(async move { mvba.invoke(main_buff_send).await });

            handles.push(main_handle);
        }

        let results = join_all(handles).await;

        println!();
        println!("-------------------------------------------------------------");
        println!();

        for (i, result) in results.iter().enumerate() {
            if let Ok(value) = result {
                println!("Value returned party {} = {:?}", i, value);
            }
        }
    }
}
