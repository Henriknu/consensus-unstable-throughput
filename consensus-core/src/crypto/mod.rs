use serde::{Deserialize, Serialize};

pub mod aes;
pub mod hash;
pub mod merkle;
pub mod sign_ecdsa;
pub mod sign_pairing;

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

pub mod sign {
    #[cfg(feature = "sign-ecdsa")]
    pub use crate::crypto::sign_ecdsa::*;

    #[cfg(not(feature = "sign-ecdsa"))]
    pub use crate::crypto::sign_pairing::*;
}

#[cfg(feature = "sign-ecdsa")]
#[derive(Serialize, Deserialize)]
pub struct KeySet {
    pub signer_prbc: sign_ecdsa::EncodedSigner,
    pub signer_mvba: sign_ecdsa::EncodedSigner,
    pub coin: commoncoin::EncodedCoin,
    pub encrypter: encrypt::EncodedEncrypter,
}
#[cfg(feature = "sign-ecdsa")]
impl KeySet {
    pub fn new(
        signer_prbc: sign_ecdsa::Signer,
        signer_mvba: sign_ecdsa::Signer,
        coin: commoncoin::Coin,
        encrypter: encrypt::Encrypter,
    ) -> Self {
        let coin = coin.into();
        let encrypter = encrypter.into();
        let signer_prbc = signer_prbc.into();
        let signer_mvba = signer_mvba.into();

        Self {
            signer_prbc,
            signer_mvba,
            coin,
            encrypter,
        }
    }
}

#[cfg(not(feature = "sign-ecdsa"))]
#[derive(Serialize, Deserialize)]
pub struct KeySet {
    pub signer_prbc: sign_pairing::Signer,
    pub signer_mvba: sign_pairing::Signer,
    pub coin: commoncoin::EncodedCoin,
    pub encrypter: encrypt::EncodedEncrypter,
}
#[cfg(not(feature = "sign-ecdsa"))]
impl KeySet {
    pub fn new(
        signer_prbc: sign_pairing::Signer,
        signer_mvba: sign_pairing::Signer,
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

pub struct SignatureIdentifier {
    pub(crate) id: usize,
    pub(crate) index: usize,
}

impl SignatureIdentifier {
    pub fn new(id: usize, index: usize) -> Self {
        Self { id, index }
    }
}
