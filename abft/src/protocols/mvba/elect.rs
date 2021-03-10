use std::sync::{Arc, Mutex};

use consensus_core::crypto::commoncoin::*;
use tokio::sync::Notify;

use crate::messaging::ProtocolMessageSender;

use super::messages::ElectCoinShareMessage;
use thiserror::Error;

pub type ElectResult<T> = Result<T, ElectError>;

pub struct Elect {
    id: usize,
    index: usize,
    view: usize,
    n_parties: usize,
    tag: String,
    shares: Mutex<Vec<CoinShare>>,
    notify_shares: Arc<Notify>,
}

impl Elect {
    pub fn init(id: usize, index: usize, view: usize, n_parties: usize) -> Elect {
        let tag = format!("{}", id);
        Elect {
            id,
            index,
            view,
            n_parties,
            tag,
            shares: Default::default(),
            notify_shares: Arc::new(Notify::new()),
        }
    }

    pub async fn invoke<F: ProtocolMessageSender>(
        &self,
        coin: &Coin,
        send_handle: &F,
    ) -> ElectResult<usize> {
        let share = coin.generate_share(self.tag.as_bytes());
        let elect_message = ElectCoinShareMessage::new(share.into());

        send_handle
            .broadcast(
                self.id,
                self.index,
                self.n_parties,
                self.view,
                0,
                elect_message,
            )
            .await;

        let notify_shares = self.notify_shares.clone();

        notify_shares.notified().await;

        let shares = self.shares.lock().map_err(|_| ElectError::PoisonedMutex)?;

        Ok(coin.combine_shares(&*shares, self.n_parties))
    }

    pub fn on_coin_share_message(
        &self,
        message: ElectCoinShareMessage,
        coin: &Coin,
    ) -> ElectResult<()> {
        let share = message.share.into();

        let mut shares = self.shares.lock().map_err(|_| ElectError::PoisonedMutex)?;

        if coin.verify_share(&self.tag.as_bytes(), &share) {
            shares.push(share);
        }

        if shares.len() >= (self.n_parties / 3) + 1 {
            self.notify_shares.notify_one();
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ElectError {
    #[error("Acquired a poisoned mutex during election")]
    PoisonedMutex,
}
