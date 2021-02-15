use std::collections::HashMap;

use rand::rngs::ThreadRng;

use std::collections::BTreeMap;

use rand_core::OsRng;

use threshold_crypto::{
    error::Error, PublicKeySet, PublicKeyShare, SecretKeySet, SecretKeyShare, Signature,
    SignatureShare,
};
#[derive(Debug)]
pub struct Signer {
    secret: SecretKeyShare,
    publics: PublicKeySet,
}

impl Signer {
    pub fn new(secret: SecretKeyShare, publics: PublicKeySet) -> Signer {
        Signer { secret, publics }
    }

    pub fn generate_signers(n_parties: usize, threshold: usize) -> Vec<Signer> {
        let sk_set = SecretKeySet::random(threshold, &mut OsRng);
        let pk_set = sk_set.public_keys();

        (0..n_parties)
            .map(|i| Signer::new(sk_set.secret_key_share(i), pk_set.clone()))
            .collect()
    }

    pub fn sign(&self, data: &[u8]) -> SignatureShare {
        self.secret.sign(&data)
    }

    pub fn verify_share(&self, index: usize, share: &SignatureShare, data: &[u8]) -> bool {
        self.publics.public_key_share(index).verify(share, data)
    }

    pub fn combine_signatures(
        &self,
        shares: &BTreeMap<usize, SignatureShare>,
    ) -> Result<Signature, Error> {
        self.publics.combine_signatures(shares)
    }

    pub fn verify_signature(&self, sig: &Signature, data: &[u8]) -> bool {
        self.publics.public_key().verify(sig, data)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_threshold_sig() {
        let mut rng = OsRng;
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_master = pk_set.public_key();

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

        let shares: BTreeMap<usize, SignatureShare> = signers
            .iter()
            .enumerate()
            .map(|(index, signer)| (index, signer.sign(&data)))
            .collect();

        for share in &shares {
            assert!(
                signers[0].verify_share(*share.0, share.1, &data),
                "Could not verify for Signer {}",
                share.0
            );
        }

        let sig = signers[0].combine_signatures(&shares).unwrap();

        assert!(signers[0].verify_signature(&sig, &data));
    }
}
