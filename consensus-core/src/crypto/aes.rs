use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use rand::{rngs::StdRng, Rng, SeedableRng};
use thiserror::Error;

#[derive(Debug)]
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
        &self.nonce
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
    use crate::crypto::encrypt::Encrypter;

    #[test]
    fn it_works() {
        let (ciphertext, encrypter) = SymmetricEncrypter::encrypt(b"plaintext message".as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        let plaintext = encrypter.decrypt(&ciphertext).expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }

    #[test]
    fn threshold_on_symmetric() {
        let threshold = Encrypter::generate_keys(4, 1);

        let thresh1 = &threshold[0];

        let (ciphertext, encrypter) = SymmetricEncrypter::encrypt(b"plaintext message".as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        // Encrypt the symmetric key info

        let encrypted_key = thresh1.encrypt(&encrypter.key, &[0u8; 32]);

        let encrypted_nonce = thresh1.encrypt(&encrypter.nonce, &[0u8; 32]);

        // Decrypt the key info

        let key_shares = threshold
            .iter()
            .map(|encrypter| encrypter.decrypt_share(&encrypted_key).unwrap())
            .collect();

        let nonce_shares = threshold
            .iter()
            .map(|encrypter| encrypter.decrypt_share(&encrypted_nonce).unwrap())
            .collect();

        let key = thresh1.combine_shares(&encrypted_key, key_shares).unwrap();

        let nonce = thresh1
            .combine_shares(&encrypted_nonce, nonce_shares)
            .unwrap();

        assert_eq!(key.data, encrypter.key, "Key not equal");

        assert_eq!(nonce.data, encrypter.nonce, "Nonce not equal");

        let decoded_encrypter = SymmetricEncrypter {
            key: key.data,
            nonce: nonce.data,
        };

        let plaintext = decoded_encrypter
            .decrypt(&ciphertext)
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }
}
