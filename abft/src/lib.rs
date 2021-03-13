pub mod messaging;
pub mod protocols;

use std::{collections::HashMap, sync::Arc};

use bincode::{deserialize, serialize, Error as BincodeError};
use consensus_core::crypto::{
    aes::{SymmetricEncrypter, SymmetricEncrypterError},
    commoncoin::Coin,
    encrypt::{Ciphertext, DecryptionShare, EncodedCiphertext, Encrypter},
    sign::Signer,
};
use log::info;
use messaging::{
    ABFTDecryptionShareMessage, ProtocolMessage, ProtocolMessageSender, ProtocolMessageType,
};
use protocols::{
    acs::{ACSError, ValueVector, ACS},
    mvba::buffer::MVBAReceiver,
    prbc::buffer::PRBCReceiver,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Notify, RwLock};

pub type ABFTResult<T> = Result<T, ABFTError>;

pub struct ABFT<
    F: ProtocolMessageSender + Sync + Send + 'static,
    R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
> {
    id: usize,
    index: usize,
    n_parties: usize,

    encrypted_values: RwLock<Option<ValueVector<EncryptedTransactionSet>>>,
    notify_decrypt: Arc<Notify>,
    decryption_shares: RwLock<HashMap<usize, HashMap<usize, ABFTDecryptionShareMessage>>>,
    decrypted: RwLock<HashMap<usize, EncryptedTransactionSet>>,

    // sub-protocol
    acs: RwLock<Option<ACS<EncryptedTransactionSet>>>,

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
        R: PRBCReceiver + MVBAReceiver + Send + Sync + 'static,
    > ABFT<F, R>
{
    pub fn init(
        id: usize,
        index: usize,
        n_parties: usize,
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

    pub async fn invoke<V: ABFTValue>(&self, value: V) -> ABFTResult<()> {
        // choose value and encrypt it
        // TODO: Figure out label

        // Encrypt the value with symmetric encryption
        let (payload, sym_encrypter) = SymmetricEncrypter::encrypt(&serialize(&value)?)?;

        // Encrypt the symmetric encryption key with threshold encrypter.
        let encrypted = EncryptedTransactionSet {
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

        // decrypt and broadcast shares

        for (index, transaction_set) in &value_vector.inner {
            let dec_key = self
                .encrypter
                .decrypt_share(&transaction_set.key.clone().into())
                .expect("Ciphertext should be valid. If not, question party #index");
            let dec_nonce = self
                .encrypter
                .decrypt_share(&transaction_set.nonce.clone().into())
                .expect("Ciphertext should be valid. If not, question party #index");

            let message = ABFTDecryptionShareMessage::new(*index, dec_key.into(), dec_nonce.into());

            self.send_handle
                .broadcast(self.id, self.index, self.n_parties, 0, 0, message)
                .await;
        }

        // save value vector

        {
            let mut vector = self.encrypted_values.write().await;
            vector.replace(value_vector);
        }

        // wait for f + 1 decryption shares for each transaction set, decrypt and return

        let notify_decrypt = self.notify_decrypt.clone();

        notify_decrypt.notified().await;

        // Get transaction sets

        Ok(())
    }

    pub async fn handle_protocol_message(&self, message: ProtocolMessage) -> ABFTResult<()> {
        info!(
            "Handling message from {} to {} with message_type {:?}",
            message.header.send_id, message.header.recv_id, message.message_type
        );

        match message.message_type {
            ProtocolMessageType::PRBC(_) => {
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
                    return Err(ABFTError::NotReadyForMVBAMessage(message));
                }
            }

            ProtocolMessageType::MVBA(_) => {
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

            ProtocolMessageType::ABFTDecryptionShare => {
                let inner: ABFTDecryptionShareMessage = deserialize(&message.message_data)?;

                self.on_decryption_share(inner, message.header.send_id)
                    .await;
            }
            ProtocolMessageType::Default => {

                // ignore
            }
        }

        Ok(())
    }

    async fn on_decryption_share(&self, message: ABFTDecryptionShareMessage, send_id: usize) {
        // if we have already decrypted the transaction set, diregard the message
        {
            let decrypted = self.decrypted.read().await;

            if decrypted.contains_key(&send_id) {
                return;
            }
        }

        // if not, if we have already received the share, disregard the message

        let mut shares = self.decryption_shares.write().await;

        if shares
            .entry(message.index)
            .or_default()
            .contains_key(&send_id)
        {
            return;
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
                return;
            }

            if !self.encrypter.verify_share(
                &encrypted.nonce.clone().into(),
                &message.nonce.clone().into(),
            ) {
                return;
            }
        }

        // insert share
        let index = message.index;

        shares
            .entry(message.index)
            .or_default()
            .insert(send_id, message);

        // if we have enough shares, decrypt

        if shares.entry(index).or_default().len() >= (self.n_parties / 3 + 1) {
            self.decrypt_value(index);

            // if we have decrypted everything, notify

            let decrypted = self.decrypted.read().await;

            if decrypted.len() >= n_values {
                self.notify_decrypt.notify_one();
            }
        }
    }

    async fn decrypt_value(&self, index: usize) {
        //assume that we do actually have enough shares for this.

        let (key_shares, nonce_shares) = {
            let shares_lock = self.decryption_shares.read().await;

            let shares = shares_lock.get(&index).unwrap();

            let key_shares = shares
                .iter()
                .map(|(index, message)| message.key.clone().into())
                .collect();

            let nonce_shares = shares
                .iter()
                .map(|(index, message)| message.nonce.clone().into())
                .collect();

            (key_shares, nonce_shares)
        };

        let key = self
            .encrypter
            .combine_shares(ciphertext, key_shares)
            .unwrap();

        let nonce = self
            .encrypter
            .combine_shares(ciphertext, nonce_shares)
            .unwrap();

        let symmetric = SymmetricEncrypter {
            key: key.inner,
            nonce: nonce.inner,
        };

        let decrypted = symmetric.decrypt(payload)?;
    }

    async fn init_acs(&self, encrypted: EncryptedTransactionSet) {
        let acs = ACS::init(self.id, self.index, self.n_parties, encrypted);

        let mut lock = self.acs.write().await;

        lock.replace(acs);
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EncryptedTransactionSet {
    key: EncodedCiphertext,
    nonce: EncodedCiphertext,
    payload: Vec<u8>,
}

/// Dummy value, useful for testing
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
    #[error(transparent)]
    FailedSymmetricEncryption(#[from] SymmetricEncrypterError),
    #[error("Not ready to handle PRBC message")]
    NotReadyForPRBCMessage(ProtocolMessage),
    #[error("Not ready to handle PRBC message")]
    NotReadyForMVBAMessage(ProtocolMessage),
    // Errors propogated from sub-protocol instances
    #[error(transparent)]
    ACSError(#[from] ACSError),
}
