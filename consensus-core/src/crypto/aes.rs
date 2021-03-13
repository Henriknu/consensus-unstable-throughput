use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use aes_gcm::Error;
use rand::{rngs::StdRng, FromEntropy, Rng, SeedableRng};
use thiserror::Error;

pub struct SymmetricEncrypter {
    pub key: [u8; 32],
    pub nonce: [u8; 32],
}

impl SymmetricEncrypter {
    pub fn encrypt(data: &[u8]) -> Result<(Vec<u8>, Self), SymmetricEncrypterError> {
        let mut rng = StdRng::from_entropy();

        let mut key = [0u8; 32];

        let mut nonce = [0u8; 32];

        rng.fill(&mut key);
        rng.fill(&mut nonce);

        let cipher = Aes256Gcm::new(&GenericArray::from_slice(&key));

        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce[0..12]), data)
            .map_err(|e| SymmetricEncrypterError::FailedEncrypt(format!("{}", e)))?;

        let encrypter = SymmetricEncrypter { key, nonce };

        Ok((ciphertext, encrypter))
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricEncrypterError> {
        let cipher = Aes256Gcm::new(&GenericArray::from_slice(&self.key));

        let plaintext = cipher
            .decrypt(GenericArray::from_slice(&self.nonce[0..12]), ciphertext)
            .map_err(|e| SymmetricEncrypterError::FailedDecrypt(format!("{}", e)))?;

        Ok(plaintext)
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn nonce(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(Error, Debug)]
pub enum SymmetricEncrypterError {
    #[error("Failed to Encrypt data: {0}")]
    FailedEncrypt(String),
    #[error("Failed to Decrypt data: {0}")]
    FailedDecrypt(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let (ciphertext, encrypter) = SymmetricEncrypter::encrypt(b"plaintext message".as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        let plaintext = encrypter.decrypt(&ciphertext).expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }
}
