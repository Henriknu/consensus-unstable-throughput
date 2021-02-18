use std::{collections::HashSet, sync::Arc};

use consensus_core::crypto::commoncoin::*;
use tokio::sync::Notify;

pub struct Elect<'c> {
    id: usize,
    num_parties: usize,
    tag: String,
    coin: &'c Coin,
    shares: Vec<CoinShare>,
    notify_shares: Arc<Notify>,
}

impl<'c> Elect<'c> {
    pub fn init(id: usize, num_parties: usize, coin: &'c Coin) -> Elect<'c> {
        let tag = format!("{}", id);
        Elect {
            id,
            num_parties,
            tag,
            coin,
            shares: Default::default(),
            notify_shares: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke(&self) -> usize {
        let share = self.coin.generate_share(self.tag.as_bytes());

        // for index in (0..self.num_parties){ send_coin_share(index, self.id, share );}

        // wait for Check on shares.len() == (self.num_parties//3) + 1
        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        self.coin.combine_shares(&self.shares, self.num_parties)
    }

    pub fn on_coin_share(&mut self, share: CoinShare) {
        if self.coin.verify_share(&self.tag.as_bytes(), &share) {
            self.shares.push(share);
        }

        if self.shares.len() >= (self.num_parties / 3) + 1 {
            self.notify_shares.notify_one();
        }
    }
}
