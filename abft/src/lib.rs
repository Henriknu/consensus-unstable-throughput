use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use bincode::{deserialize, serialize, Error as BincodeError};
use buffer::{ABFTBufferCommand, ABFTReceiver};
use consensus_core::crypto::{
    aes::{SymmetricEncrypter, SymmetricEncrypterError},
    commoncoin::Coin,
    encrypt::{Ciphertext, DecryptionShare, EncodedCiphertext, Encrypter},
    sign::Signer,
};
use log::{debug, info, warn};
use messaging::{ABFTDecryptionShareMessage, ProtocolMessageSender};
use proto::{ProtocolMessage, ProtocolMessageType};
use protocols::{
    acs::{ACSError, ValueVector, ACS},
    mvba::buffer::MVBAReceiver,
    prbc::buffer::PRBCReceiver,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc::error::SendError, Notify, RwLock};

pub mod buffer;
pub mod messaging;
pub mod proto;
pub mod protocols;
pub mod test_helpers;

pub type ABFTResult<T> = Result<T, ABFTError>;

pub struct ABFT<
    F: ProtocolMessageSender + Sync + Send + 'static,
    R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
    V: ABFTValue,
> {
    id: u32,
    index: u32,
    f_tolerance: u32,
    n_parties: u32,

    encrypted_values: RwLock<Option<BTreeMap<u32, EncryptedValue>>>,
    notify_decrypt: Arc<Notify>,
    decryption_shares: RwLock<HashMap<u32, HashMap<u32, DecryptionSharePair>>>,
    decrypted: RwLock<BTreeMap<u32, V>>,

    // sub-protocol
    acs: RwLock<Option<ACS<EncodedEncryptedValue>>>,

    // infrastructure
    send_handle: Arc<F>,
    recv_handle: Arc<R>,
    signer_prbc: Arc<Signer>,
    signer_mvba: Signer,
    coin: Coin,
    encrypter: Encrypter,
}

impl<
        F: ProtocolMessageSender + Sync + Send + 'static,
        R: PRBCReceiver + MVBAReceiver + ABFTReceiver + Send + Sync + 'static,
        V: ABFTValue,
    > ABFT<F, R, V>
{
    pub fn init(
        id: u32,
        index: u32,
        f_tolerance: u32,
        n_parties: u32,
        send_handle: Arc<F>,
        recv_handle: Arc<R>,
        signer_prbc: Arc<Signer>,
        signer_mvba: Signer,
        coin: Coin,
        encrypter: Encrypter,
    ) -> Self {
        Self {
            id,
            index,
            f_tolerance,
            n_parties,

            encrypted_values: RwLock::new(None),
            notify_decrypt: Arc::new(Notify::new()),
            decryption_shares: Default::default(),
            decrypted: Default::default(),

            acs: RwLock::const_new(None),

            send_handle,
            recv_handle,
            signer_prbc,
            signer_mvba,
            coin,
            encrypter,
        }
    }

    pub async fn invoke(&self, value: V) -> ABFTResult<BTreeMap<u32, V>> {
        // choose value and encrypt it
        // TODO: Figure out label

        // Encrypt the value with symmetric encryption
        let (payload, sym_encrypter) = SymmetricEncrypter::encrypt(&serialize(&value)?)?;

        // Encrypt the symmetric encryption key with threshold encrypter.
        let encrypted = EncodedEncryptedValue {
            key: self
                .encrypter
                .encrypt(&sym_encrypter.key(), &[0u8; 32])
                .into(),
            nonce: self
                .encrypter
                .encrypt(&sym_encrypter.nonce(), &[0u8; 32])
                .into(),
            payload,
        };

        // Invoke acs with the encrypted transaction set. Get back a vector of encrypted transactions sets.

        self.init_acs(encrypted).await;

        let value_vector = {
            let acs_lock = self.acs.read().await;

            let acs = acs_lock.as_ref().expect("ACS should be init");

            acs.invoke(
                self.recv_handle.clone(),
                self.send_handle.clone(),
                self.signer_prbc.clone(),
                &self.signer_mvba,
                &self.coin,
            )
            .await?
        };

        let encrypted_values = Self::decode_value_vector(value_vector);

        // save value vector

        {
            let mut lock = self.encrypted_values.write().await;
            lock.replace(encrypted_values);
        }

        {
            // decrypt and broadcast shares

            let encrypted_values_lock = self.encrypted_values.read().await;

            let encrypted_values = encrypted_values_lock.as_ref().unwrap();

            for (index, encrypted_value) in encrypted_values {
                let dec_key = self
                    .encrypter
                    .decrypt_share(&encrypted_value.key)
                    .expect("Ciphertext should be valid. If not, question party #index");
                let dec_nonce = self
                    .encrypter
                    .decrypt_share(&encrypted_value.nonce)
                    .expect("Ciphertext should be valid. If not, question party #index");

                let decrypt_message =
                    ABFTDecryptionShareMessage::new(*index, dec_key.into(), dec_nonce.into());

                self.on_decryption_share(decrypt_message.clone(), self.index)
                    .await?;

                self.send_handle
                    .broadcast(self.id, self.index, self.n_parties, 0, 0, decrypt_message)
                    .await;
            }
        }

        self.recv_handle.drain_decryption_shares().await?;

        // wait for f + 1 decryption shares for each transaction set, decrypt and return

        let notify_decrypt = self.notify_decrypt.clone();

        notify_decrypt.notified().await;

        // Get transaction sets

        let mut lock = self.decrypted.write().await;

        let decrypted = std::mem::take(&mut *lock);

        Ok(decrypted)
    }

    pub async fn handle_protocol_message(&self, message: ProtocolMessage) -> ABFTResult<()> {
        // assume valid existing header and valid message_type

        match message.message_type() {
            ProtocolMessageType::PrbcDone
            | ProtocolMessageType::RbcEcho
            | ProtocolMessageType::RbcValue
            | ProtocolMessageType::RbcReady => {
                // pass to ACS instance
                let acs = self.acs.read().await;

                if let Some(acs) = &*acs {
                    match acs
                        .handle_protocol_message(
                            message,
                            &*self.send_handle,
                            &*self.signer_prbc,
                            &self.signer_mvba,
                            &self.coin,
                        )
                        .await
                    {
                        Ok(_) => {}

                        Err(ACSError::NotReadyForPRBCMessage(message)) => {
                            return Err(ABFTError::NotReadyForPRBCMessage(message));
                        }

                        Err(e) => return Err(ABFTError::ACSError(e)),
                    }
                } else {
                    return Err(ABFTError::NotReadyForPRBCMessage(message));
                }
            }

            ProtocolMessageType::MvbaDone
            | ProtocolMessageType::MvbaSkipShare
            | ProtocolMessageType::MvbaSkip
            | ProtocolMessageType::PbSend
            | ProtocolMessageType::PbShareAck
            | ProtocolMessageType::ElectCoinShare
            | ProtocolMessageType::ViewChange => {
                // pass to ACS instance
                let acs = self.acs.read().await;

                if let Some(acs) = &*acs {
                    match acs
                        .handle_protocol_message(
                            message,
                            &*self.send_handle,
                            &*self.signer_prbc,
                            &self.signer_mvba,
                            &self.coin,
                        )
                        .await
                    {
                        Ok(_) => {}

                        Err(ACSError::NotReadyForMVBAMessage(message)) => {
                            return Err(ABFTError::NotReadyForMVBAMessage(message));
                        }
                        Err(e) => return Err(ABFTError::ACSError(e)),
                    }
                } else {
                    return Err(ABFTError::NotReadyForMVBAMessage(message));
                }
            }

            ProtocolMessageType::AbftDecryptionShare => {
                let vector_lock = self.encrypted_values.read().await;

                if vector_lock.is_some() {
                    let inner: ABFTDecryptionShareMessage = deserialize(&message.message_data)?;

                    self.on_decryption_share(inner, message.send_id).await?;
                } else {
                    return Err(ABFTError::NotReadyForABFTDecryptionShareMessage(message));
                }
            }
            ProtocolMessageType::Default => {

                // ignore
            }
        }

        Ok(())
    }

    async fn on_decryption_share(
        &self,
        message: ABFTDecryptionShareMessage,
        send_id: u32,
    ) -> ABFTResult<()> {
        debug!(
            "Party {} handling decryption share for value {}, from {}",
            self.index, message.index, send_id
        );
        // if we have already decrypted the transaction set, diregard the message
        {
            let decrypted = self.decrypted.read().await;

            if decrypted.contains_key(&message.index) {
                info!(
                    "Party {} already decrypted value {}, discarding message from {}",
                    self.index, message.index, send_id
                );
                return Ok(());
            }
        }

        // if not, if we have already received the share, disregard the message

        let mut shares = self.decryption_shares.write().await;

        if shares
            .entry(message.index)
            .or_default()
            .contains_key(&send_id)
        {
            warn!(
                "Party {} already received decrypt share for value {}, from {}",
                self.index, message.index, send_id
            );
            return Ok(());
        }

        // verify the share is valid
        let n_values;

        {
            let vector_lock = self.encrypted_values.read().await;

            let vector = vector_lock.as_ref().unwrap();

            n_values = vector.len();

            let encrypted = vector.get(&message.index).unwrap();

            if !self
                .encrypter
                .verify_share(&encrypted.key, &message.key.clone().into())
            {
                warn!(
                    "Party {} received a faulty decryption share for value {}'s key, from {}",
                    self.index, message.index, send_id
                );
                return Ok(());
            }

            if !self
                .encrypter
                .verify_share(&encrypted.nonce, &message.nonce.clone().into())
            {
                warn!(
                    "Party {} received a faulty decryption share for value {}'s nonce, from {}",
                    self.index, message.index, send_id
                );
                return Ok(());
            }
        }

        // insert share

        let ABFTDecryptionShareMessage { index, key, nonce } = message;

        let share = DecryptionSharePair {
            key: key.into(),
            nonce: nonce.into(),
        };

        shares.entry(index).or_default().insert(send_id, share);

        // if we have enough shares, decrypt

        debug!(
            "Party {} has received {} decryption share for value {}, need {}",
            self.index,
            shares.entry(index).or_default().len(),
            index,
            (self.n_parties / 3 + 1)
        );

        if shares.entry(index).or_default().len() as u32 >= (self.f_tolerance + 1) {
            drop(shares);
            self.decrypt_value(index).await?;

            // if we have decrypted everything, notify

            let decrypted = self.decrypted.read().await;

            if decrypted.len() >= n_values {
                self.notify_decrypt.notify_one();
            }
        }

        Ok(())
    }

    async fn decrypt_value(&self, index: u32) -> ABFTResult<()> {
        // take the shares. If two tasks are trying to decrypt at same time, return early if no shares found.

        let (key_shares, nonce_shares): (Vec<_>, Vec<_>) = {
            let mut shares_lock = self.decryption_shares.write().await;

            let shares = std::mem::take(shares_lock.get_mut(&index).unwrap());

            shares
                .into_iter()
                .map(|(_, pair)| (pair.key, pair.nonce))
                .unzip()
        };

        debug!(
            "Party {} extracted decrypt info for {}. Key shares: {:?}, Nonce shares: {:?}",
            self.index, index, key_shares, nonce_shares
        );

        if key_shares.is_empty() || nonce_shares.is_empty() {
            return Ok(());
        }

        let vector_lock = self.encrypted_values.read().await;

        let vector = vector_lock.as_ref().unwrap();

        let encrypted = vector.get(&index).unwrap();

        let key = self
            .encrypter
            .combine_shares(&encrypted.key, key_shares)
            .unwrap();

        let nonce = self
            .encrypter
            .combine_shares(&encrypted.nonce, nonce_shares)
            .unwrap();

        let symmetric = SymmetricEncrypter {
            key: key.data,
            nonce: nonce.data,
        };

        info!(
            "Party {} decrypting payload from Party {}",
            self.index, index
        );

        let decrypted = symmetric.decrypt(&encrypted.payload)?;

        let value: V = deserialize(&decrypted)?;

        {
            let mut decryptions = self.decrypted.write().await;
            decryptions.insert(index, value);
        }

        Ok(())
    }

    async fn init_acs(&self, encrypted: EncodedEncryptedValue) {
        let acs = ACS::init(
            self.id,
            self.index,
            self.f_tolerance,
            self.n_parties,
            encrypted,
        );

        let mut lock = self.acs.write().await;

        lock.replace(acs);
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    fn decode_value_vector(
        value_vector_encoded: ValueVector<EncodedEncryptedValue>,
    ) -> BTreeMap<u32, EncryptedValue> {
        let mut inner = BTreeMap::new();

        for (index, encoded) in value_vector_encoded.inner {
            inner.insert(index, encoded.into());
        }

        inner
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

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct EncodedEncryptedValue {
    key: EncodedCiphertext,
    nonce: EncodedCiphertext,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncryptedValue {
    key: Ciphertext,
    nonce: Ciphertext,
    payload: Vec<u8>,
}

impl From<EncodedEncryptedValue> for EncryptedValue {
    fn from(encoded: EncodedEncryptedValue) -> Self {
        let EncodedEncryptedValue {
            key,
            nonce,
            payload,
        } = encoded;

        let key = key.into();

        let nonce = nonce.into();

        EncryptedValue {
            key,
            nonce,
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptionSharePair {
    key: DecryptionShare,
    nonce: DecryptionShare,
}

/// Dummy value, useful for testing
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, PartialOrd)]
pub struct Value {
    pub(crate) inner: u32,
}

impl Value {
    pub fn new(inner: u32) -> Self {
        Self { inner }
    }
}

#[derive(Error, Debug)]
pub enum ABFTError {
    #[error(transparent)]
    FailedSerialization(#[from] BincodeError),
    #[error(transparent)]
    FailedSymmetricEncryption(#[from] SymmetricEncrypterError),
    #[error("Not ready to handle PRBC message")]
    NotReadyForPRBCMessage(ProtocolMessage),
    #[error("Not ready to handle MVBA message")]
    NotReadyForMVBAMessage(ProtocolMessage),
    #[error("Not ready to handle ABFT Decryption share message")]
    NotReadyForABFTDecryptionShareMessage(ProtocolMessage),
    #[error("Failed to send PRBCBufferCommand from MVBA instance")]
    BufferSender(#[from] SendError<ABFTBufferCommand>),
    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    ACSError(#[from] ACSError),
}
