use serde::{Deserialize, Serialize};

pub mod aes;
pub mod commoncoin;
pub mod encrypt;
pub mod encrypt_dalek;
pub mod hash;
pub mod merkle;
pub mod sign;
//pub mod sign2;

#[derive(Serialize, Deserialize)]
pub struct KeySet {
    pub signer_prbc: sign::Signer,
    pub signer_mvba: sign::Signer,
    pub coin: commoncoin::EncodedCoin,
    pub encrypter: encrypt::EncodedEncrypter,
}

impl KeySet {
    pub fn new(
        signer_prbc: sign::Signer,
        signer_mvba: sign::Signer,
        coin: commoncoin::Coin,
        encrypter: encrypt::Encrypter,
    ) -> Self {
        let coin = coin.into();
        let encrypter = encrypter.into();

        Self {
            signer_prbc,
            signer_mvba,
            coin,
            encrypter,
        }
    }
}
