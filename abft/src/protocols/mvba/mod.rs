use bincode::{deserialize, serialize};
use consensus_core::crypto::commoncoin::*;
use consensus_core::crypto::sign::*;
use futures::Future;
use messages::{ElectCoinShareMessage, PBSendMessage, PBShareAckMessage, ViewChangeMessage};
use proposal_promotion::{PPProposal, PPReceiver, PPSender, PPStatus};
use provable_broadcast::{PBKey, PBProof};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    pin::Pin,
};



use log::{debug, error, info};

use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Notify};

use self::{
    elect::Elect,
    messages::{
        MVBADoneMessage, MVBAReceiver, MVBASender, MVBASkipMessage, MVBASkipShareMessage,
        ProtocolMessage, ProtocolMessageHeader, ToProtocolMessage,
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
pub struct MVBA<F: MVBASender, R: MVBAReceiver> {
    // Internal state
    /// Protocol id
    id: MVBAID,
    /// Number of parties taking part in protocol
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
    notify_skip: Arc<Notify>,
    /// Whether the current party can proceed to the election phase for a particular view.
    skip: HashMap<usize, bool>,

    // Sub-protocol instances
    pp_send: Option<PPSender<F>>,
    pp_recvs: Option<HashMap<usize, PPReceiver<F>>>,
    elect: Option<Elect<F>>,
    view_change: Option<ViewChange<F>>,

    // Infrastructure
    send_handle: F,
    receive_handle: R,
    coin: Coin,
    signer: Signer,
}

impl<F: MVBASender, R: MVBAReceiver> MVBA<F> {
    pub fn init(
        id: usize,
        index: usize,
        n_parties: usize,
        value: Value,
        send_handle: F,
        receive_handle: R,
        signer: Signer,
        coin: Coin,
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
            pp_send: None,
            pp_recvs: None,
            elect: None,
            view_change: None,
            coin,
            signer,
            send_handle,
            receive_handle
        }
    }

    pub async fn invoke(&mut self) -> Value {
        loop {
            let MVBAID { id, index, view } = self.id;

            let key = PBKey {
                view: self.KEY.view,
                view_key_proof: self.KEY.proof.clone(),
            };

            debug!(
                "Started invoke for id: {}, index: {}, view: {}",
                id, index, view
            );

            // ***** PROPOSAL PROMOTION *****

            self.init_pp();

            let pp_send = self
                .pp_send
                .as_mut()
                .expect("PPSender instance should be initialized");

            // wait for promotion to return. aka: 1. Succesfully promoted value or 2. self.skip[self.view]

            let notify_skip = self.notify_skip.clone();

            debug!(
                "Party {} started Promoting proposal with value: {:?}, view: {}",
                index, self.KEY.value, self.KEY.view
            );

            let promotion_proof: Option<PBSig> = tokio::select! {
                proof = pp_send.promote(self.KEY.value, key, &self.signer, &self.send_handle) => proof,
                _ = notify_skip.notified() => {
                    self.skip.insert(view, true);
                    None
                },
            };

            debug!(
                "Party {} finished promoting proposal, returning with proof: {:?}",
                index, promotion_proof
            );

            if !*self.skip.entry(self.id.view).or_default() {
                let proposal = PPProposal {
                    value: self.KEY.value,
                    proof: PBProof {
                        key: PBKey {
                            view: self.KEY.view,
                            view_key_proof: self.KEY.proof.clone(),
                        },
                        proof_prev: promotion_proof,
                    },
                };

                let mvba_done = MVBADoneMessage {
                    id: self.id,
                    proposal,
                };

                for i in 0..self.n_parties {
                    self.send_handle
                        .send(i, mvba_done.to_protocol_message(id, index, i))
                        .await;
                }
                notify_skip.notified().await;
            }

            // ***** LEADER ELECTION *****

            self.abandon_all_ongoing_proposals();

            self.init_elect();

            let elect = self
                .elect
                .as_ref()
                .expect("Elect instance should be initialized");

            let leader = elect.invoke(&self.coin, &self.send_handle).await;

            self.leaders.insert(self.id.view, Some(leader));

            // ***** VIEW CHANGE *****

            let id_leader = MVBAID {
                id,
                index: leader,
                view,
            };

            self.init_view_change(id_leader);

            let view_change = self
                .view_change
                .as_mut()
                .expect("ViewChange instance should be initialized");

            let changes = view_change.invoke(&self.send_handle).await;

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
                if let Some(pp_recvs) = &mut self.pp_recvs {
                    if let Some(pp) = &mut pp_recvs.get_mut(&send_id) {
                        let inner: PBSendMessage = deserialize(&message_data).expect(
                            "Could not deserialize PBSend message when handling protocol message",
                        );

                        let leader_index = self.leaders[&inner.proposal.proof.key.view]
                            .expect("Leader was not found for view");

                        pp.on_value_send_message(
                            send_id,
                            inner,
                            &self.id,
                            leader_index,
                            self.LOCK,
                            &self.signer,
                            &self.send_handle,
                        )
                        .await;
                    }
                }
            }
            messages::ProtocolMessageType::PBShareAck => {
                if let Some(pp_send) = &mut self.pp_send {
                    let inner: PBShareAckMessage = deserialize(&message_data).expect(
                        "Could not deserialize PBShareAck message when handling protocol message",
                    );

                    pp_send.on_share_ack(send_id, inner, &self.signer).await;
                }
            }
            messages::ProtocolMessageType::ElectCoinShare => {
                if let Some(elect) = &mut self.elect {
                    let inner: ElectCoinShareMessage = deserialize(&message_data).expect(
                        "Could not deserialize ElectCoinShare message when handling protocol message",
                    );

                    elect.on_coin_share_message(inner, &self.coin);
                }
            }
            messages::ProtocolMessageType::ViewChange => {
                if let Some(view_change) = &mut self.view_change {
                    let inner: ViewChangeMessage = deserialize(&message_data).expect(
                        "Could not deserialize ViewChange message when handling protocol message",
                    );

                    view_change.on_view_change_message(&inner, &self.signer);
                }
            }
        }
    }

    pub async fn on_done_message(&mut self, index: usize, message: MVBADoneMessage) {
        let MVBADoneMessage { id, proposal } = message;
        let PPProposal { value, proof } = proposal;
        let PBProof { proof_prev, .. } = proof;

        // Assert that done message has not already been received from party (index) in view (view)

        if !*self
            .has_received_done
            .entry(id.view)
            .or_default()
            .entry(index)
            .or_default()
        {
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

        self.has_received_done
            .entry(id.view)
            .or_insert(Default::default())
            .insert(index, true);

        *self.pp_done.entry(id.view).or_insert(0) += 1;

        // If enough done messages have been collected to elect leader, and we have not sent out skip_share, send it.

        if !*self.has_sent_skip_share.entry(id.view).or_default()
            && self.pp_done[&id.view] >= (self.n_parties * 2 / 3) + 1
        {
            let tag = self.tag_skip_share(id.id, id.view);

            let share = SkipShare {
                inner: self.signer.sign(&tag.as_bytes()),
            };

            let skip_share_message = MVBASkipShareMessage { id, share };

            for i in 0..self.n_parties {
                self.send_handle
                    .send(
                        i,
                        skip_share_message.to_protocol_message(id.id, self.id.index, i),
                    )
                    .await;
            }

            self.has_sent_skip_share.insert(id.view, true);
        }
    }

    pub async fn on_skip_share_message(&mut self, index: usize, message: MVBASkipShareMessage) {
        let MVBASkipShareMessage { id, share } = message;

        // Assert that skip share message has not already been received from party (index) in view (view)

        if *self
            .has_received_skip_share
            .entry(id.view)
            .or_default()
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

        self.pp_skip.entry(id.view).or_default().insert(share);

        // If we have received enough skip_shares to construct a skip signature, construct and broadcast it.

        if !*self.has_sent_skip.entry(id.view).or_default()
            && self.pp_skip.entry(id.view).or_default().len() >= (self.n_parties * 2 / 3) + 1
        {
            let shares = self.pp_skip[&id.view]
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
                self.send_handle
                    .send(i, skip_message.to_protocol_message(id.id, self.id.index, i))
                    .await;
            }

            self.has_sent_skip.insert(id.view, true);
        }
    }

    pub async fn on_skip_message(&mut self, message: MVBASkipMessage) {
        let MVBASkipMessage { id, sig } = message;

        // Assert that the skip signature is valid

        let tag = self.tag_skip_share(id.id, id.view);

        if !self.signer.verify_signature(&sig.inner, tag.as_bytes()) {
            return;
        }

        // Update state

        self.skip.insert(id.view, true);

        // Propogate skip message, if we have not sent a skip message for the current view

        if !*self.has_sent_skip.entry(id.view).or_default() {
            let skip_message = MVBASkipMessage { id, sig };

            for i in 0..self.n_parties {
                self.send_handle
                    .send(i, skip_message.to_protocol_message(id.id, self.id.index, i))
                    .await;
            }

            self.has_sent_skip.insert(id.view, true);
        }

        // wake up invoke()-task, since we are ready to continue to election process

        self.notify_skip.notify_one();
    }

    fn init_pp(&mut self) {
        let pp_id = PPID { inner: self.id };

        let pp_send = PPSender::init(pp_id, self.id.index, self.n_parties);

        let pp_recvs = (0..self.n_parties - 1)
            .filter_map(|i| {
                if self.id.index != i {
                    Some((i, PPReceiver::init(pp_id, self.id.index)))
                } else {
                    None
                }
            })
            .collect();

        self.pp_send.replace(pp_send);
        self.pp_recvs.replace(pp_recvs);
    }

    fn init_elect(&mut self) {
        let elect = Elect::init(self.id, self.id.index, self.n_parties);

        self.elect.replace(elect);
    }

    fn init_view_change(&mut self, id_leader: MVBAID) {
        //TODO: Get leaders proposals
        let leader_key = None;
        let leader_lock = None;
        let leader_commit = None;

        let view_change = ViewChange::init(
            id_leader,
            self.n_parties,
            self.KEY.view,
            self.LOCK,
            leader_key,
            leader_lock,
            leader_commit,
        );

        self.view_change.replace(view_change);
    }

    fn abandon_all_ongoing_proposals(&mut self) {
        if let Some(recvs) = &mut self.pp_recvs {
            for recv in recvs.values_mut() {
                recv.abandon();
            }
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

    struct ChannelReceiver{
        recv: Receiver<ProtocolMessage>>
    }

    #[async_trait]
    impl MVBAReceiver for ChannelReceiver {
        async fn receive(&self, message: ProtocolMessage) -> impl Future<Output = ProtocolMessage>{
            self.recv.recv()
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

            let mvba = Arc::new(Mutex::new(MVBA::init(
                0,
                i,
                N_PARTIES,
                Value { inner: i * 1000 },
                f,
                signer,
                coin,
            )));

            let mvba2 = mvba.clone();

            let main_handle = tokio::spawn(async move {
                debug!("Started main {}", i);
                let mut lock = mvba.lock().await;
                lock.invoke().await;
            });
            tokio::spawn(async move {
                debug!("Started messaging for {}", i);
                while let Some(message) = recv.recv().await {
                    debug!("Received message at {}", i);
                    let mut lock = mvba2.lock().await;
                    debug!("Got lock at {}", i);
                    lock.handle_protocol_message(message).await;
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
