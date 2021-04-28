use rand::{rngs::StdRng, SeedableRng};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use threshold_crypto::{Signature, SignatureShare};

pub use threshold_crypto::error::Error;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeySet, SecretKeyShare};

use super::SignatureIdentifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct Signer {
    secret: SerdeSecret<SecretKeyShare>,
    publics: PublicKeySet,
    threshold: usize,
}

impl Signer {
    pub fn generate_signers(n_parties: usize, threshold: usize) -> Vec<Signer> {
        let mut rng = StdRng::from_entropy();
        let sk_set = SecretKeySet::random(threshold - 1, &mut rng);
        let pk_set = sk_set.public_keys();

        (0..n_parties)
            .map(|i| Signer {
                secret: SerdeSecret {
                    0: sk_set.secret_key_share(i),
                },
                publics: pk_set.clone(),
                threshold,
            })
            .collect()
    }

    pub fn sign(&self, data: &[u8], _identifier: &SignatureIdentifier) -> SignatureShare {
        self.secret.sign(&data)
    }

    pub fn verify_share(&self, index: usize, share: &SignatureShare, data: &[u8]) -> bool {
        self.publics.public_key_share(index).verify(share, data)
    }

    pub fn combine_signatures(
        &self,
        shares: &BTreeMap<usize, SignatureShare>,
        _identifier: &SignatureIdentifier,
    ) -> Signature {
        self.publics.combine_signatures(shares).unwrap()
    }

    pub fn verify_signature(&self, sig: &Signature, data: &[u8]) -> bool {
        self.publics.public_key().verify(sig, data)
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_threshold_sig() {
        let mut rng = StdRng::from_entropy();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_signer() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(10, 5);
        let identifier = SignatureIdentifier::new(0, 0);

        let shares: BTreeMap<usize, SignatureShare> = signers
            .iter()
            .enumerate()
            .map(|(index, signer)| (index, signer.sign(&data, &identifier)))
            .collect();

        for share in &shares {
            assert!(
                signers[0].verify_share(*share.0, share.1, &data),
                "Could not verify for Signer {}",
                share.0
            );
        }

        let sig = signers[0].combine_signatures(&shares, &identifier);

        assert!(signers[0].verify_signature(&sig, &data));
    }
}
