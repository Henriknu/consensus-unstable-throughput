use crate::crypto::hash::dalek::*;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{constants, traits::Identity};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Clone)]
struct PublicK {
    g1: Box<RistrettoBasepointTable>,
    h: Box<RistrettoBasepointTable>,
}
#[derive(Clone)]
struct VerifyK {
    elements: Vec<RistrettoBasepointTable>,
}
#[derive(Clone, Copy)]
struct SecretK {
    secret_scalar: Scalar,
}

/// Actor within the threshold cryptosystem. Has access to public key, verification key, and their own secret key.
pub struct Encrypter {
    index: usize,
    public: PublicK,
    verify: VerifyK,
    secret: SecretK,
}

impl Encrypter {
    pub fn generate_keys(n_actors: usize, threshold: usize) -> Vec<Encrypter> {
        // Should generate the keyset, to be used in a trusted setup environment.

        assert!(threshold > 0);
        assert!(n_actors >= threshold);

        let mut rng = thread_rng();

        let g1 = Box::new(RistrettoBasepointTable::create(
            &(&constants::RISTRETTO_BASEPOINT_TABLE * &Scalar::random(&mut rng)),
        ));

        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

        let secrets: Vec<Scalar> = (0..n_actors + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let mut publics: Vec<RistrettoBasepointTable> = secrets
            .iter()
            .map(|secret| {
                RistrettoBasepointTable::create(&(&constants::RISTRETTO_BASEPOINT_TABLE * secret))
            })
            .collect();

        let h = Box::new(publics.remove(0));

        let public = PublicK { g1, h };

        let verify = VerifyK { elements: publics };

        let secrets: Vec<_> = secrets
            .into_iter()
            .skip(1)
            .map(|secret_scalar| SecretK { secret_scalar })
            .collect();

        (0..n_actors)
            .map(|index| Encrypter {
                index,
                public: public.clone(),
                verify: verify.clone(),
                secret: secrets[index],
            })
            .collect()
    }

    pub fn encrypt(&self, data: &[u8; 32], label: &[u8; 32]) -> Ciphertext {
        let mut rng = thread_rng();

        let r = Scalar::random(&mut rng);
        let s = Scalar::random(&mut rng);

        let h1 = hash1(&*self.public.h * &r);

        let mut c = [0u8; 32];

        for (i, (m, h)) in data.iter().zip(&h1).enumerate() {
            c[i] = m ^ h;
        }

        let u = &constants::RISTRETTO_BASEPOINT_TABLE * &r;
        let w = &constants::RISTRETTO_BASEPOINT_TABLE * &s;
        let u1 = &*self.public.g1 * &r;
        let w1 = &*self.public.g1 * &s;

        let e = hash2(&c, label, u, w, u1, w1);
        let f = s + &(r * &e);

        Ciphertext {
            c,
            label: *label,
            u,
            u1,
            e,
            f,
        }
    }
    pub fn extract_label(&self, ciphertext: &Ciphertext) -> Vec<u8> {
        ciphertext.label.to_vec()
    }

    pub fn decrypt_share(&self, ciphertext: &Ciphertext) -> Option<DecryptionShare> {
        let mut rng = thread_rng();

        let ss = Scalar::random(&mut rng);

        let uu = ciphertext.u * self.secret.secret_scalar;
        let uu1 = ciphertext.u * ss;
        let hh = &constants::RISTRETTO_BASEPOINT_TABLE * &ss;
        let ee = hash4(uu, uu1, hh);
        let ff = ss + (self.secret.secret_scalar * ee);

        Some(DecryptionShare {
            index: self.index,
            uu,
            ee,
            ff,
        })
    }

    // TODO: Verify_share should really accept a decryption share for a invalid ciphertext (e.g. "i, ?"). Currently just return false on invalid proof.
    pub fn verify_share(&self, ciphertext: &Ciphertext, decrypt_share: &DecryptionShare) -> bool {
        let DecryptionShare { uu, ee, ff, index } = decrypt_share;

        let uu1 = ciphertext.u * ff - *uu * ee;
        let hh1 = &constants::RISTRETTO_BASEPOINT_TABLE * ff - &self.verify.elements[*index] * ee;

        *ee == hash4(*uu, uu1, hh1)
    }

    pub fn combine_shares(
        &self,
        ciphertext: &Ciphertext,
        shares: Vec<DecryptionShare>,
    ) -> Option<Plaintext> {
        let coefficients = self.calculate_lagrange_coefficients(&shares);

        // res = Summation over uu * coeff

        let result = shares
            .iter()
            .zip(coefficients)
            .fold(RistrettoPoint::identity(), |acc, (share, coeff)| {
                acc + (share.uu * coeff)
            });

        // m = H1(res) XOR c
        let h1 = hash1(result);

        let mut data = [0u8; 32];

        for (i, (h, c)) in h1.iter().zip(&ciphertext.c).enumerate() {
            data[i] = h ^ c;
        }

        Some(Plaintext { data })
    }

    fn _is_ciphertext_valid(&self, ciphertext: &Ciphertext) -> bool {
        let Ciphertext {
            c,
            label,
            u,
            u1,
            e,
            f,
        } = ciphertext;
        let w = (&constants::RISTRETTO_BASEPOINT_TABLE * f) - (*u * e);
        let w1 = (&*self.public.g1 * f) - (u1 * e);
        ciphertext.e == hash2(c, label, *u, w, *u1, w1)
    }

    fn calculate_lagrange_coefficients(&self, shares: &Vec<DecryptionShare>) -> Vec<Scalar> {
        let index_set: Vec<_> = shares.iter().map(|share| share.index).collect();

        // Interpolate over the points, get coefficients
        shares
            .iter()
            .map(|share| {
                // S = subset of Zq (Set of scalars). i = 0. j is the index of the share.

                let numerator = index_set.iter().fold(Scalar::one(), |acc, index| {
                    acc * match index {
                        index if index == &share.index => Scalar::one(),
                        _ => {
                            Scalar::zero()
                                - Scalar::one() * Scalar::from(*index as u64)
                                - Scalar::one()
                        }
                    }
                });

                let denumerator = index_set.iter().fold(Scalar::one(), |acc, index| {
                    acc * match index {
                        index if index == &share.index => Scalar::one(),
                        _ => {
                            Scalar::one() * Scalar::from(share.index as u64)
                                - Scalar::one() * Scalar::from(*index as u64)
                        }
                    }
                });

                numerator * denumerator.invert()
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncodedEncrypter {
    index: usize,
    g1: [u8; 32],
    h: [u8; 32],
    elements: Vec<[u8; 32]>,
    secret_scalar: [u8; 32],
}

impl From<Encrypter> for EncodedEncrypter {
    fn from(encrypter: Encrypter) -> Self {
        let Encrypter {
            index,
            public: PublicK { g1, h },
            verify: VerifyK { elements },
            secret: SecretK { secret_scalar },
        } = encrypter;

        let g1 = g1.basepoint().compress().to_bytes();
        let h = h.basepoint().compress().to_bytes();
        let elements = elements
            .into_iter()
            .map(|ele| ele.basepoint().compress().to_bytes())
            .collect();
        let secret_scalar = secret_scalar.to_bytes();

        Self {
            index,
            g1,
            h,
            elements,
            secret_scalar,
        }
    }
}

impl From<EncodedEncrypter> for Encrypter {
    fn from(encoded: EncodedEncrypter) -> Self {
        let EncodedEncrypter {
            index,
            g1,
            h,
            elements,
            secret_scalar,
        } = encoded;

        let g1 = Box::new(RistrettoBasepointTable::create(
            &CompressedRistretto::decompress(&CompressedRistretto::from_slice(&g1))
                .expect("Could not decode encoded point as ristretto point"),
        ));

        let h = Box::new(RistrettoBasepointTable::create(
            &CompressedRistretto::decompress(&CompressedRistretto::from_slice(&h))
                .expect("Could not decode encoded point as ristretto point"),
        ));

        let elements = elements
            .into_iter()
            .map(|ele| {
                RistrettoBasepointTable::create(
                    &CompressedRistretto::decompress(&CompressedRistretto::from_slice(&ele))
                        .expect("Could not decode encoded point as ristretto point"),
                )
            })
            .collect();

        let secret_scalar = Scalar::from_bytes_mod_order(secret_scalar);

        Self {
            index,
            public: PublicK { g1, h },
            verify: VerifyK { elements },
            secret: SecretK { secret_scalar },
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Ciphertext {
    c: [u8; 32],
    label: [u8; 32],
    u: RistrettoPoint,
    u1: RistrettoPoint,
    e: Scalar,
    f: Scalar,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncodedCiphertext {
    c: [u8; 32],
    label: [u8; 32],
    u: [u8; 32],
    u1: [u8; 32],
    e: [u8; 32],
    f: [u8; 32],
}

impl From<Ciphertext> for EncodedCiphertext {
    fn from(ciphetext: Ciphertext) -> Self {
        let Ciphertext {
            c,
            label,
            u,
            u1,
            e,
            f,
        } = ciphetext;

        let u = u.compress().to_bytes();
        let u1 = u1.compress().to_bytes();

        let e = e.to_bytes();

        let f = f.to_bytes();

        Self {
            c,
            label,
            u,
            u1,
            e,
            f,
        }
    }
}

impl From<EncodedCiphertext> for Ciphertext {
    fn from(encoded: EncodedCiphertext) -> Self {
        let EncodedCiphertext {
            c,
            label,
            u,
            u1,
            e,
            f,
        } = encoded;

        let u = CompressedRistretto::decompress(&CompressedRistretto::from_slice(&u))
            .expect("Could not decode encoded point as ristretto point");

        let u1 = CompressedRistretto::decompress(&CompressedRistretto::from_slice(&u1))
            .expect("Could not decode encoded point as ristretto point");

        let e = Scalar::from_bytes_mod_order(e);
        let f = Scalar::from_bytes_mod_order(f);

        Self {
            c,
            label,
            u,
            u1,
            e,
            f,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptionShare {
    index: usize,
    uu: RistrettoPoint,
    ee: Scalar,
    ff: Scalar,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EncodedDecryptionShare {
    index: usize,
    uu: [u8; 32],
    ee: [u8; 32],
    ff: [u8; 32],
}

impl From<DecryptionShare> for EncodedDecryptionShare {
    fn from(share: DecryptionShare) -> Self {
        let DecryptionShare { index, uu, ee, ff } = share;

        let uu = uu.compress().to_bytes();

        let ee = ee.to_bytes();

        let ff = ff.to_bytes();

        Self { index, uu, ee, ff }
    }
}

impl From<EncodedDecryptionShare> for DecryptionShare {
    fn from(encoded: EncodedDecryptionShare) -> Self {
        let EncodedDecryptionShare { index, uu, ee, ff } = encoded;

        let uu = CompressedRistretto::decompress(&CompressedRistretto::from_slice(&uu))
            .expect("Could not decode encoded point as ristretto point");

        let ee = Scalar::from_bytes_mod_order(ee);

        let ff = Scalar::from_bytes_mod_order(ff);

        Self { index, uu, ee, ff }
    }
}

pub struct Plaintext {
    pub data: [u8; 32],
}

#[cfg(test)]
mod tests {

    use super::*;

    const N_ACTORS_MULTIPLE: usize = 5;
    const THRESHOLD_MULTIPLE: usize = 2;

    #[test]
    fn test_proof_valid() {
        let actors = Encrypter::generate_keys(N_ACTORS_MULTIPLE, THRESHOLD_MULTIPLE);

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        let encrypted = actors[0].encrypt(&data, &data);

        for actor in &actors {
            assert!(actor._is_ciphertext_valid(&encrypted));
        }
    }

    #[test]
    #[should_panic]
    fn test_threshold_encrypt_should_fail_with_threshold_less_than_1() {
        threshold_crypto_scenario(1, 0);
    }

    #[test]
    #[should_panic]
    fn test_threshold_encrypt_should_fail_with_threshold_larger_than_n() {
        threshold_crypto_scenario(1, 2);
    }

    #[test]
    fn test_threshold_encrypt_single_actor_threshold_1() {
        threshold_crypto_scenario(1, 1);
    }

    #[test]
    fn test_threshold_encrypt_multiple_actors_threshold_1() {
        threshold_crypto_scenario(N_ACTORS_MULTIPLE, 1);
    }

    #[test]
    fn test_threshold_encrypt_multiple_actors() {
        threshold_crypto_scenario(N_ACTORS_MULTIPLE, THRESHOLD_MULTIPLE);
    }

    #[test]
    fn test_threshold_encrypt_multiple_actors_equal_threshold() {
        threshold_crypto_scenario(N_ACTORS_MULTIPLE, N_ACTORS_MULTIPLE);
    }

    fn threshold_crypto_scenario(n_actors: usize, threshold: usize) {
        let actors = Encrypter::generate_keys(n_actors, threshold);

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        assert!(message.as_bytes().len() == 32);

        println!("Message bytes: {:?}", &message.as_bytes());
        println!("Message bytes len: {:?}", &message.as_bytes().len());
        println!(
            "Message str: {:?}",
            str::from_utf8(&message.as_bytes()).expect("Message data should be valid utf-8")
        );

        let encrypted = actors[0].encrypt(&data, &data);

        println!("Ciphertext bytes: {:?}", &encrypted.c);
        println!(
            "Ciphertext label: {:?}",
            str::from_utf8(&encrypted.label).expect("Label should be valid utf-8")
        );

        let decrypt_shares: Vec<_> = actors
            .iter()
            .map(|actor| actor.decrypt_share(&encrypted).unwrap())
            .collect();

        for share in &decrypt_shares {
            for actor in &actors {
                if actor.index != share.index {
                    assert!(
                        actor.verify_share(&encrypted, share),
                        "Actor {} could not verify share: {}",
                        actor.index,
                        share.index
                    );
                }
            }
        }

        let plaintext = actors[0]
            .combine_shares(&encrypted, decrypt_shares)
            .expect("Plaintext could not be retrieved from shares");

        println!("Plaintext bytes: {:?}", &plaintext.data);
        println!(
            "Plaintext message: {:?}",
            str::from_utf8(&plaintext.data).expect("Plaintext data should be valid utf-8")
        );
    }

    #[test]
    fn cipher_to_encoded() {
        let actors = Encrypter::generate_keys(2, 1);

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        let encrypted = actors[0].encrypt(&data, &data);

        let encoded: EncodedCiphertext = encrypted.clone().into();

        let decoded = encoded.into();

        assert_eq!(encrypted, decoded);
    }
    #[test]
    fn decrypt_to_encoded() {
        let actors = Encrypter::generate_keys(2, 1);

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        let encrypted = actors[0].encrypt(&data, &data);

        let decrypt_share = actors[1].decrypt_share(&encrypted).unwrap();

        let encoded: EncodedDecryptionShare = decrypt_share.clone().into();

        let decoded = encoded.into();

        assert_eq!(decrypt_share, decoded);
    }

    #[test]
    #[should_panic]
    fn fails_to_decrypt_if_not_enough_shares() {
        let mut actors = Encrypter::generate_keys(4, 2);

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        assert!(message.as_bytes().len() == 32);

        println!("Message bytes: {:?}", &message.as_bytes());
        println!("Message bytes len: {:?}", &message.as_bytes().len());
        println!(
            "Message str: {:?}",
            str::from_utf8(&message.as_bytes()).expect("Message data should be valid utf-8")
        );

        let encrypted = actors[0].encrypt(&data, &data);

        println!("Ciphertext bytes: {:?}", &encrypted.c);
        println!(
            "Ciphertext label: {:?}",
            str::from_utf8(&encrypted.label).expect("Label should be valid utf-8")
        );

        actors.remove(1);
        actors.remove(1);

        let actor = actors.remove(0);

        let decrypt_shares: Vec<_> = actors
            .iter()
            .map(|actor| actor.decrypt_share(&encrypted).unwrap())
            .collect();

        println!("Decrypt share len: {}", decrypt_shares.len());

        for share in &decrypt_shares {
            for actor in &actors {
                if actor.index != share.index {
                    assert!(
                        actor.verify_share(&encrypted, share),
                        "Actor {} could not verify share: {}",
                        actor.index,
                        share.index
                    );
                }
            }
        }

        let plaintext = actor
            .combine_shares(&encrypted, decrypt_shares)
            .expect("Plaintext could not be retrieved from shares");

        println!("Plaintext bytes: {:?}", &plaintext.data);
        println!(
            "Plaintext message: {:?}",
            str::from_utf8(&plaintext.data).expect("Plaintext data should be valid utf-8")
        );
    }
}
