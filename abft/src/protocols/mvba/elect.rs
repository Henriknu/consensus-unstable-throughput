use std::{collections::HashSet, marker::PhantomData, sync::Arc};

use consensus_core::crypto::commoncoin::*;
use tokio::sync::Notify;

use super::{
    messages::{ElectCoinShareMessage, MVBASender, ProtocolMessage, ToProtocolMessage},
    MVBAID,
};

pub struct Elect<F: MVBASender> {
    id: MVBAID,
    index: usize,
    n_parties: usize,
    tag: String,
    shares: Vec<CoinShare>,
    notify_shares: Arc<Notify>,
    _phantom: PhantomData<F>,
}

impl<F: MVBASender> Elect<F> {
    pub fn init(id: MVBAID, index: usize, n_parties: usize) -> Elect<F> {
        let tag = format!("{}", id.id);
        Elect {
            id,
            index,
            n_parties,
            tag,
            shares: Default::default(),
            notify_shares: Arc::new(Notify::new()),
            _phantom: PhantomData,
        }
    }

    pub async fn invoke(&self, coin: &Coin, send_handle: &F) -> usize {
        let share = coin.generate_share(self.tag.as_bytes());
        let elect_message = ElectCoinShareMessage {
            share: share.into(),
        };

        for i in 0..self.n_parties {
            send_handle
                .send(
                    i,
                    elect_message.to_protocol_message(self.id.id, self.index, i),
                )
                .await;
        }

        // wait for Check on shares.len() == (self.num_parties//3) + 1
        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        coin.combine_shares(&self.shares, self.n_parties)
    }

    pub fn on_coin_share_message(&mut self, message: ElectCoinShareMessage, coin: &Coin) {
        let share = message.share.into();

        if coin.verify_share(&self.tag.as_bytes(), &share) {
            self.shares.push(share);
        }

        if self.shares.len() >= (self.n_parties / 3) + 1 {
            self.notify_shares.notify_one();
        }
    }
}
