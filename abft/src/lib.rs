use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use bincode::{deserialize, serialize, Error as BincodeError};
use buffer::{ABFTBufferCommand, ABFTReceiver};
use consensus_core::crypto::{
    aes::{SymmetricEncrypter, SymmetricEncrypterError},
    commoncoin::Coin,
    encrypt::{EncodedCiphertext, Encrypter},
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
    n_parties: u32,

    encrypted_values: RwLock<Option<ValueVector<EncryptedValue>>>,
    notify_decrypt: Arc<Notify>,
    decryption_shares: RwLock<HashMap<u32, HashMap<u32, ABFTDecryptionShareMessage>>>,
    decrypted: RwLock<BTreeMap<u32, V>>,

    // sub-protocol
    acs: RwLock<Option<ACS<EncryptedValue>>>,

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
        let encrypted = EncryptedValue {
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

        // save value vector

        {
            let mut vector = self.encrypted_values.write().await;
            vector.replace(value_vector);
        }

        {
            // decrypt and broadcast shares

            let vector_lock = self.encrypted_values.read().await;

            let vector = vector_lock.as_ref().unwrap();

            for (index, transaction_set) in &vector.inner {
                let dec_key = self
                    .encrypter
                    .decrypt_share(&transaction_set.key.clone().into())
                    .expect("Ciphertext should be valid. If not, question party #index");
                let dec_nonce = self
                    .encrypter
                    .decrypt_share(&transaction_set.nonce.clone().into())
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

            n_values = vector.inner.len();

            let encrypted = vector.inner.get(&message.index).unwrap();

            if !self
                .encrypter
                .verify_share(&encrypted.key.clone().into(), &message.key.clone().into())
            {
                warn!(
                    "Party {} received a faulty decryption share for value {}'s key, from {}",
                    self.index, message.index, send_id
                );
                return Ok(());
            }

            if !self.encrypter.verify_share(
                &encrypted.nonce.clone().into(),
                &message.nonce.clone().into(),
            ) {
                warn!(
                    "Party {} received a faulty decryption share for value {}'s nonce, from {}",
                    self.index, message.index, send_id
                );
                return Ok(());
            }
        }

        // insert share
        let index = message.index;

        shares
            .entry(message.index)
            .or_default()
            .insert(send_id, message);

        // if we have enough shares, decrypt

        debug!(
            "Party {} has received {} decryption share for value {}, need {}",
            self.index,
            shares.entry(index).or_default().len(),
            index,
            (self.n_parties / 3 + 1)
        );

        if shares.entry(index).or_default().len() as u32 >= (self.n_parties / 3 + 1) {
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
        //assume that we do actually have enough shares for this.

        let (key_shares, nonce_shares) = {
            let shares_lock = self.decryption_shares.read().await;

            let shares = shares_lock.get(&index).unwrap();

            let key_shares = shares
                .iter()
                .map(|(_, message)| message.key.clone().into())
                .collect();

            let nonce_shares = shares
                .iter()
                .map(|(_, message)| message.nonce.clone().into())
                .collect();

            (key_shares, nonce_shares)
        };

        let vector_lock = self.encrypted_values.read().await;

        let vector = vector_lock.as_ref().unwrap();

        let encrypted = vector.inner.get(&index).unwrap();

        let key = self
            .encrypter
            .combine_shares(&encrypted.key.clone().into(), key_shares)
            .unwrap();

        let nonce = self
            .encrypter
            .combine_shares(&encrypted.nonce.clone().into(), nonce_shares)
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

    async fn init_acs(&self, encrypted: EncryptedValue) {
        let acs = ACS::init(self.id, self.index, self.n_parties, encrypted);

        let mut lock = self.acs.write().await;

        lock.replace(acs);
    }

    pub fn index(&self) -> u32 {
        self.index
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
pub struct EncryptedValue {
    key: EncodedCiphertext,
    nonce: EncodedCiphertext,
    payload: Vec<u8>,
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
