use std::{collections::HashSet, sync::Arc};

use consensus_core::crypto::commoncoin::*;
use tokio::sync::Notify;

use super::{
    messages::{ElectCoinShareMessage, ProtocolMessage, ToProtocolMessage},
    MVBAID,
};

pub struct Elect<'c, F: Fn(usize, ProtocolMessage)> {
    id: MVBAID,
    index: usize,
    n_parties: usize,
    tag: String,
    coin: &'c Coin,
    shares: Vec<CoinShare>,
    notify_shares: Arc<Notify>,
    send_handle: &'c F,
}

impl<'c, F: Fn(usize, ProtocolMessage)> Elect<'c, F> {
    pub fn init(
        id: MVBAID,
        index: usize,
        n_parties: usize,
        coin: &'c Coin,
        send_handle: &'c F,
    ) -> Elect<'c, F> {
        let tag = format!("{}", id.id);
        Elect {
            id,
            index,
            n_parties,
            tag,
            coin,
            shares: Default::default(),
            notify_shares: Arc::new(Notify::new()),
            send_handle,
        }
    }

    pub async fn invoke(&self) -> usize {
        let share = self.coin.generate_share(self.tag.as_bytes());
        let elect_message = ElectCoinShareMessage {
            share: share.into(),
        };

        for i in 0..self.n_parties {
            (self.send_handle)(
                i,
                elect_message.to_protocol_message(self.id.id, self.index, i),
            );
        }

        // wait for Check on shares.len() == (self.num_parties//3) + 1
        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        self.coin.combine_shares(&self.shares, self.n_parties)
    }

    pub fn on_coin_share_message(&mut self, message: ElectCoinShareMessage) {
        let share = message.share.into();

        if self.coin.verify_share(&self.tag.as_bytes(), &share) {
            self.shares.push(share);
        }

        if self.shares.len() >= (self.n_parties / 3) + 1 {
            self.notify_shares.notify_one();
        }
    }
}
