use serde::{Deserialize, Serialize};

pub mod aes;
pub mod hash;
pub mod merkle;
pub mod sign;
pub mod sign_ecdsa;

pub mod encrypt_dalek;
pub mod encrypt_dalek_precomputed;
pub mod encrypt_p256;

pub mod commoncoin_dalek_precomputed;
pub mod commoncoin_p256;

pub mod encrypt {

    #[cfg(feature = "encrypt-dalek-precomputed")]
    pub use crate::crypto::encrypt_dalek_precomputed::*;

    #[cfg(all(not(feature = "encrypt-dalek-precomputed"), feature = "encrypt-dalek"))]
    pub use crate::crypto::encrypt_dalek::*;

    #[cfg(all(
        not(feature = "encrypt-dalek-precomputed"),
        not(feature = "encrypt-dalek")
    ))]
    pub use crate::crypto::encrypt_p256::*;
}

pub mod commoncoin {
    #[cfg(feature = "commoncoin-dalek-precomputed")]
    pub use crate::crypto::commoncoin_dalek_precomputed::*;

    #[cfg(not(feature = "commoncoin-dalek-precomputed"))]
    pub use crate::crypto::commoncoin_p256::*;
}

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
