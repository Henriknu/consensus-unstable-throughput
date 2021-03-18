use crate::{
    messaging::ProtocolMessageSender,
    proto::{ProtocolMessage, ProtocolMessageHeader, ProtocolMessageType},
    ABFTValue,
};
use bincode::{deserialize, serialize};
use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use proposal_promotion::{PPProposal, PPReceiver, PPSender, PPStatus};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use log::{debug, error, info, warn};
use tokio::sync::RwLock;

use std::sync::Arc;
use tokio::sync::Notify;

use self::{
    buffer::MVBAReceiver,
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
pub struct MVBA<V: ABFTValue> {
    /// Identifier for protocol
    id: u32,
    index: u32,
    n_parties: u32,
    /// Internal state
    state: RwLock<MVBAState<V>>,
    notify_skip: Arc<Notify>,

    // Sub-protocol instances
    pp_send: RwLock<Option<PPSender<V>>>,
    pp_recvs: RwLock<Option<HashMap<u32, Arc<PPReceiver<V>>>>>,
    elect: RwLock<Option<Elect>>,
    view_change: RwLock<Option<ViewChange<V>>>,
}

impl<V: ABFTValue> MVBA<V> {
    pub fn init(id: u32, index: u32, n_parties: u32, value: V) -> Self {
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
        }
    }

    pub async fn invoke<
        F: ProtocolMessageSender + Sync + Send,
        R: MVBAReceiver + Sync + Send + 'static,
    >(
        &self,
        recv_handle: Arc<R>,
        send_handle: &F,
        signer: &Signer,
        coin: &Coin,
    ) -> MVBAResult<V> {
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
                    let recv_clone = recv_handle.clone();
                    let index = self.index;

                    tokio::spawn(async move {
                        match pp_clone.invoke(&*recv_clone).await {
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
                    proof = pp_send.promote(value, key, signer, send_handle) => proof?,
                    _ = notify_skip.notified() => {
                        None
                    },
                };

                info!(
                    "Party {} finished promoting proposal, returning with proof: {:?}",
                    index, promotion_proof
                );

                self.send_done_if_not_skip(promotion_proof, send_handle)
                    .await?;
            }

            // ***** LEADER ELECTION *****

            self.abandon_all_ongoing_proposals().await;

            self.init_elect(view).await;

            let lock = self.elect.read().await;

            let elect = lock.as_ref().expect("Elect should be initialized");

            info!("Party {} started electing phase for view: {}", index, view);

            recv_handle.drain_elect(view).await?;

            let leader = elect.invoke(coin, send_handle).await?;

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

            recv_handle.drain_view_change(view).await?;

            let lock = self.view_change.read().await;

            let view_change = lock.as_ref().expect("ViewChange should be initialized");

            info!("Party {} started view change for view: {}", index, view);

            let changes = view_change
                .invoke(result.key, result.lock, result.commit, send_handle)
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

    pub async fn handle_protocol_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: ProtocolMessage,
        send_handle: &F,
        signer: &Signer,
        coin: &Coin,
    ) -> MVBAResult<()> {
        let ProtocolMessage {
            header,
            message_data,
            message_type,
        } = message;
        let ProtocolMessageHeader {
            send_id,
            recv_id,
            prbc_index,
            protocol_id,
            view,
        } = header.unwrap();

        info!(
            "Handling message from {} to {} with message_type {:?}",
            send_id,
            recv_id,
            ProtocolMessageType::from_i32(message_type).unwrap()
        );

        match ProtocolMessageType::from_i32(message_type).unwrap() {
            ProtocolMessageType::MvbaDone => {
                let inner: MVBADoneMessage<V> = deserialize(&message_data)?;

                self.on_done_message(send_id, inner, send_handle, signer)
                    .await?;
            }
            ProtocolMessageType::MvbaSkipShare => {
                let inner: MVBASkipShareMessage = deserialize(&message_data)?;

                self.on_skip_share_message(send_id, inner, send_handle, signer)
                    .await?;
            }
            ProtocolMessageType::MvbaSkip => {
                let inner: MVBASkipMessage = deserialize(&message_data)?;

                self.on_skip_message(inner, send_handle, signer).await?;
            }
            ProtocolMessageType::PbSend => {
                let pp_recvs = self.pp_recvs.read().await;
                if let Some(pp_recvs) = &*pp_recvs {
                    if let Some(pp) = pp_recvs.get(&send_id) {
                        let inner: PBSendMessage<V> = deserialize(&message_data)?;

                        match self
                            .on_pb_send_message(pp, inner, send_id, send_handle, signer)
                            .await
                        {
                            Ok(_) => return Ok(()),
                            Err(PPError::NotReadyForSend) => {
                                return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                                    header: Some(ProtocolMessageHeader {
                                        send_id,
                                        recv_id,
                                        prbc_index,
                                        protocol_id,
                                        view,
                                    }),
                                    message_data,
                                    message_type,
                                }));
                            }
                            Err(e) => return Err(MVBAError::PPError(e)),
                        }
                    } else {
                        warn!("Did not find PPReceiver {} for Party {}!", send_id, recv_id);
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header: Some(ProtocolMessageHeader {
                                send_id,
                                recv_id,
                                prbc_index,
                                protocol_id,
                                view,
                            }),
                            message_data,
                            message_type,
                        }));
                    }
                } else {
                    warn!("pprecvs was not initialized for Party {}!", recv_id);
                    return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                        header: Some(ProtocolMessageHeader {
                            send_id,
                            recv_id,
                            prbc_index,
                            protocol_id,
                            view,
                        }),
                        message_data,
                        message_type,
                    }));
                }
            }
            ProtocolMessageType::PbShareAck => {
                let pp_send = self.pp_send.read().await;

                if let Some(pp_send) = &*pp_send {
                    let inner: PBShareAckMessage = deserialize(&message_data)?;

                    if let Err(PPError::NotReadyForShareAck) =
                        pp_send.on_share_ack(send_id, inner, signer).await
                    {
                        warn!("pp_send not ready for message at Party {}!", recv_id);
                        return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                            header: Some(ProtocolMessageHeader {
                                send_id,
                                recv_id,
                                prbc_index,
                                protocol_id,
                                view,
                            }),
                            message_data,
                            message_type,
                        }));
                    }
                }
            }
            ProtocolMessageType::ElectCoinShare => {
                let elect = self.elect.read().await;

                if let Some(elect) = &*elect {
                    let inner: ElectCoinShareMessage = deserialize(&message_data)?;

                    elect.on_coin_share_message(inner, coin)?;
                } else {
                    return Err(MVBAError::NotReadyForMessage(ProtocolMessage {
                        header: Some(ProtocolMessageHeader {
                            send_id,
                            recv_id,
                            prbc_index,
                            protocol_id,
                            view,
                        }),
                        message_data,
                        message_type,
                    }));
                }
            }
            ProtocolMessageType::ViewChange => {
                let view_change = self.view_change.read().await;

                if let Some(view_change) = &*view_change {
                    let inner: ViewChangeMessage<V> = deserialize(&message_data)?;

                    match view_change.on_view_change_message(&inner, signer) {
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
                        header: Some(ProtocolMessageHeader {
                            send_id,
                            recv_id,
                            prbc_index,
                            protocol_id,
                            view,
                        }),
                        message_data,
                        message_type,
                    }));
                }
            }
            _ => {
                warn!(
                    "Message with other ProtocolMessageType: {:?} than MVBA was passed to MVBA.",
                    message_type
                )
            }
        }

        Ok(())
    }

    pub async fn on_done_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        index: u32,
        message: MVBADoneMessage<V>,
        send_handle: &F,
        signer: &Signer,
    ) -> MVBAResult<()> {
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

        if !signer.verify_signature(&sig.inner, &serialize(&response_prev)?) {
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
                inner: signer.sign(&tag.as_bytes()),
            };

            let skip_share_message = MVBASkipShareMessage::new(id, share);

            send_handle
                .broadcast(
                    id.id,
                    self.index,
                    self.n_parties,
                    state.view,
                    0,
                    skip_share_message,
                )
                .await;

            state.has_sent_skip_share.insert(id.view, true);
        }

        Ok(())
    }

    pub async fn on_skip_share_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        index: u32,
        message: MVBASkipShareMessage,
        send_handle: &F,
        signer: &Signer,
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
                warn!(
                    "Party {} already received skip share message from Party {} at view {}",
                    self.index, index, state.view
                );
                return Ok(());
            }
        }

        // Assert that skip share is valid for index

        let tag = self.tag_skip_share(id.id, id.view);

        if !signer.verify_share(index as usize, &share.inner, &tag.as_bytes()) {
            warn!(
                "Party {} received received skip share message from Party {} with invalid signature share",
                self.index, index, 
            );
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
            && state.pp_skip.entry(id.view).or_default().len()
                >= (state.n_parties * 2 / 3 + 1) as usize
        {
      

            let shares = state.pp_skip[&id.view]
                .clone()
                .into_iter()
                .map(|(i, skip_share)| (i as usize, skip_share.inner))
                .collect();

            // All signatures should have been individually verified. Expect that the signature is valid.

            let skip_proof = signer
                .combine_signatures(&shares)
                .map_err(|_| MVBAError::InvalidSignature("on_skip_share".to_string()))?;

            let skip_message = MVBASkipMessage::new(id, SkipSig { inner: skip_proof });

            state.has_sent_skip.insert(id.view, true);

            send_handle
                .broadcast(
                    id.id,
                    self.index,
                    self.n_parties,
                    state.view,
                    0,
                    skip_message,
                )
                .await;
        }
        Ok(())
    }

    pub async fn on_skip_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        message: MVBASkipMessage,
        send_handle: &F,
        signer: &Signer,
    ) -> MVBAResult<()> {
        let MVBASkipMessage { id, sig } = message;

        // Assert that the skip signature is valid

        let tag = self.tag_skip_share(id.id, id.view);

        if !signer.verify_signature(&sig.inner, tag.as_bytes()) {
            return Err(MVBAError::InvalidSignature("skip message".to_string()));
        }

        // Update state

        let mut state = self.state.write().await;

        // Propogate skip message, if we have not sent a skip message for the current view

        if !*state.has_sent_skip.entry(id.view).or_default() {
            let skip_message = MVBASkipMessage { id, sig };

            send_handle
                .broadcast(
                    id.id,
                    self.index,
                    self.n_parties,
                    state.view,
                    0,
                    skip_message,
                )
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

    pub async fn on_pb_send_message<F: ProtocolMessageSender + Sync + Send>(
        &self,
        pp: &Arc<PPReceiver<V>>,
        message: PBSendMessage<V>,
        send_id: u32,
        send_handle: &F,
        signer: &Signer,
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
            signer,
            send_handle,
        )
        .await?;

        Ok(())
    }

    async fn get_key_value_view(&self) -> (PBKey, V, u32) {
        let state = self.state.read().await;

        let key = PBKey {
            view: state.KEY.view,
            view_key_proof: state.KEY.proof.clone(),
        };

        let value = state.KEY.value.clone();

        let view = state.view;

        (key, value, view)
    }

    async fn get_leader_result(&self, leader: u32) -> MVBAResult<PPLeader<V>> {
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

    async fn send_done_if_not_skip<F: ProtocolMessageSender + Sync + Send>(
        &self,
        promotion_proof: Option<PBSig>,
        send_handle: &F,
    ) -> MVBAResult<()> {
        let state = self.state.read().await;

        if let Ok(false) = state
            .skip
            .get(&state.view)
            .ok_or_else(|| MVBAError::UninitState("skip".to_string()))
        {
            let proposal = PPProposal {
                value: state.KEY.value.clone(),
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

            send_handle
                .broadcast(
                    self.id,
                    self.index,
                    self.n_parties,
                    state.view,
                    0,
                    mvba_done,
                )
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

    async fn init_elect(&self, view: u32) {
        let elect = Elect::init(self.id, self.index, view, self.n_parties);

        let mut lock = self.elect.write().await;

        lock.replace(elect);
    }

    async fn init_view_change(&self, index: u32, id_leader: MVBAID, view: u32) {
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

    fn tag_skip_share(&self, id: u32, view: u32) -> String {
        format!("{}-SKIP-{}", id, view)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct MVBAID {
    id: u32,
    index: u32,
    view: u32,
}

// Keep LOCK and KEY variable consistent with paper
#[allow(non_snake_case)]
struct MVBAState<V: ABFTValue> {
    /// Number of parties taking part in protocol
    view: u32,
    n_parties: u32,
    LOCK: u32,
    KEY: Key<V>,
    /// Index of elected leader per view, if existing.
    leaders: HashMap<u32, Option<u32>>,
    /// Whether a MVBADoneMessage has been received from a certain party, for a particular view.
    has_received_done: HashMap<u32, HashMap<u32, bool>>,
    /// Number of unique MVBADoneMessages received for a particular view.
    pp_done: HashMap<u32, u32>,
    /// Whether a MVBASkipShareMessage has been received from a certain party, for a particular view.
    has_received_skip_share: HashMap<u32, HashMap<u32, bool>>,
    /// Whether the current party has sent out a MVBASkipShareMessage for a particular view.
    has_sent_skip_share: HashMap<u32, bool>,
    /// Collection of unique MVBASkipShareMessage received for a particular view.
    pp_skip: HashMap<u32, HashMap<u32, SkipShare>>,
    /// Whether the current party has sent out a MVBASkipMessage for a particular view.
    has_sent_skip: HashMap<u32, bool>,
    /// Whether the current party can proceed to the election phase for a particular view.
    skip: HashMap<u32, bool>,
}

impl<V: ABFTValue> MVBAState<V> {
    fn new(n_parties: u32, value: V) -> Self {
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
pub struct Key<V: ABFTValue> {
    view: u32,
    value: V,
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
