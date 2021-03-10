pub mod messaging;
pub mod protocols;

use bincode::{serialize, Error as BincodeError};
use consensus_core::crypto::{commoncoin::Coin, encrypt::Encrypter, sign::Signer};
use messaging::{ProtocolMessage, ProtocolMessageSender};
use protocols::{
    acs::{ACSError, ACS},
    mvba::buffer::MVBAReceiver,
    prbc::buffer::PRBCReceiver,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

pub type ABFTResult<T> = Result<T, ABFTError>;

pub struct ABFT<
    V: ABFTValue,
    F: ProtocolMessageSender + Sync + Send + 'static,
    R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
> {
    id: usize,
    index: usize,
    n_parties: usize,

    // sub-protocol
    acs: RwLock<Option<ACS<V>>>,

    // infrastructure
    send_handle: F,
    recv_handle: R,
    signer_prbc: Signer,
    signer_mvba: Signer,
    coin: Coin,
    encrypter: Encrypter,
}

impl<
        V: ABFTValue,
        F: ProtocolMessageSender + Sync + Send + 'static,
        R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
    > ABFT<V, F, R>
{
    pub fn init(
        id: usize,
        index: usize,
        n_parties: usize,
        send_handle: F,
        recv_handle: R,
        signer_prbc: Signer,
        signer_mvba: Signer,
        coin: Coin,
        encrypter: Encrypter,
    ) -> Self {
        Self {
            id,
            index,
            n_parties,

            acs: RwLock::const_new(None),

            send_handle,
            recv_handle,
            signer_prbc,
            signer_mvba,
            coin,
            encrypter,
        }
    }

    pub fn invoke(&self, value: V) -> ABFTResult<()> {
        // choose value and encrypt it
        // TODO: Figure out label

        let encrypted = self.encrypter.encrypt(&serialize(&value)?, b"label");

        Ok(())
    }
}

pub trait ABFTValue:
    Default + std::fmt::Debug + Clone + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

impl<V> ABFTValue for V where
    V: Default + std::fmt::Debug + Clone + Send + Sync + Serialize + DeserializeOwned + 'static
{
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, PartialOrd)]
pub struct Value {
    pub(crate) inner: usize,
}

impl Value {
    pub fn new(inner: usize) -> Self {
        Self { inner }
    }
}

#[derive(Error, Debug)]
pub enum ABFTError {
    #[error(transparent)]
    FailedSerialization(#[from] BincodeError),
    #[error("Not ready to handle PRBC message")]
    NotReadyForPRBCMessage(ProtocolMessage),
    #[error("Not ready to handle PRBC message")]
    NotReadyForMVBAMessage(ProtocolMessage),
    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    ACSError(#[from] ACSError),
}
