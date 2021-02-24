use std::{
    collections::HashSet,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use consensus_core::crypto::commoncoin::*;
use tokio::sync::Notify;

use super::{
    messages::{ElectCoinShareMessage, MVBASender, ProtocolMessage, ToProtocolMessage},
    MVBAID,
};

pub struct Elect {
    id: usize,
    index: usize,
    n_parties: usize,
    tag: String,
    shares: Mutex<Vec<CoinShare>>,
    notify_shares: Arc<Notify>,
}

impl Elect {
    pub fn init(id: usize, index: usize, n_parties: usize) -> Elect {
        let tag = format!("{}", id);
        Elect {
            id,
            index,
            n_parties,
            tag,
            shares: Default::default(),
            notify_shares: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke<F: MVBASender>(&self, coin: &Coin, send_handle: &F) -> usize {
        let share = coin.generate_share(self.tag.as_bytes());
        let elect_message = ElectCoinShareMessage {
            share: share.into(),
        };

        for i in 0..self.n_parties {
            send_handle
                .send(i, elect_message.to_protocol_message(self.id, self.index, i))
                .await;
        }

        // wait for Check on shares.len() == (self.num_parties//3) + 1
        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        let shares = self.shares.lock().unwrap();

        coin.combine_shares(&*shares, self.n_parties)
    }

    pub fn on_coin_share_message(&self, message: ElectCoinShareMessage, coin: &Coin) {
        let share = message.share.into();

        let mut shares = self.shares.lock().unwrap();

        if coin.verify_share(&self.tag.as_bytes(), &share) {
            shares.push(share);
        }

        if shares.len() >= (self.n_parties / 3) + 1 {
            self.notify_shares.notify_one();
        }
    }
}
