use openssl::{
    ec::*,
    nid::Nid,
    pkey::{PKey, Private},
};

use byteorder::{BigEndian, ReadBytesExt};
use p256::*;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::Group, EncodedPoint, NistP256, ProjectivePoint,
    PublicKey, SecretKey,
};
use p256::{elliptic_curve::ff::PrimeField, pkcs8::FromPrivateKey};
use p256::{pkcs8::FromPublicKey, Scalar};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::{collections::HashSet, error::Error, io::Read, ops::Deref, str};

use super::hash::{hash1, hash2, hash4, hash_sha256};

const CURVE_ID: Nid = Nid::X9_62_PRIME256V1;
/// TODO: Remove this stuff, not needed. Can generate keys through p256 only.
pub fn generate_keys() -> Result<(PublicKey, SecretKey), Box<dyn Error>> {
    let key: EcKey<Private> = EcKey::generate(EcGroup::from_curve_name(CURVE_ID)?.as_ref())?;

    let public: PublicKey =
        FromPublicKey::from_public_key_pem(str::from_utf8(key.public_key_to_pem()?.as_slice())?)
            .expect("Could not parse public key");

    let private: SecretKey = FromPrivateKey::from_pkcs8_pem(str::from_utf8(
        PKey::from_ec_key(key)?
            .private_key_to_pem_pkcs8()?
            .as_slice(),
    )?)
    .expect("Could not parse private key");

    Ok((public, private))
}

/// Generate keyset -> Public key, public verification key, secret keys.
pub struct Dealer {}

impl Dealer {
    pub fn generate_keys(n_actors: usize, threshold: usize) -> KeySet {
        // Should generate the keyset, to be used in a trusted setup environment.

        let g = AffinePoint::generator();

        let g1 = AffinePoint::generator() * NonZeroScalar::random(&mut OsRng);

        let coefficients: Vec<NonZeroScalar> = (0..threshold)
            .map(|_| NonZeroScalar::random(&mut OsRng))
            .collect();

        let secrets: Vec<Scalar> = (0..n_actors + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff.deref() * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let mut publics: Vec<AffinePoint> = secrets
            .iter()
            .map(|secret| (ProjectivePoint::generator() * secret).to_affine())
            .collect();

        let h = publics.remove(0);

        let public = PublicK { g, g1, h };

        let verify = VerifyK { elements: publics };

        let secrets: Vec<_> = secrets
            .into_iter()
            .skip(1)
            .map(|secret_scalar| SecretK { secret_scalar })
            .collect();

        KeySet {
            public,
            verify,
            secrets,
        }
    }
}

pub struct KeySet {
    public: PublicK,
    verify: VerifyK,
    secrets: Vec<SecretK>,
}

#[derive(Clone, Copy)]
struct PublicK {
    g: AffinePoint,
    g1: AffinePoint,
    h: AffinePoint,
}
#[derive(Clone)]
struct VerifyK {
    elements: Vec<AffinePoint>,
}
#[derive(Clone, Copy)]
struct SecretK {
    secret_scalar: Scalar,
}

/// Actor within the threshold cryptosystem. Has access to public key, verification key, and their own secret key.
pub struct Actor {
    index: usize,
    public: PublicK,
    verify: VerifyK,
    secret: SecretK,
}

impl Actor {
    pub fn encrypt(&self, data: &[u8; 32], label: &[u8; 32]) -> Ciphertext {
        let r = NonZeroScalar::random(&mut OsRng);
        let s = NonZeroScalar::random(&mut OsRng);

        let h1 = hash1(*&self.public.h * r);
        let c: Vec<u8> = data.iter().zip(&h1).map(|(m, h)| m ^ h).collect();

        let u = *&self.public.g * r;
        let w = *&self.public.g * s;
        let u1 = *&self.public.g1 * r;
        let w1 = *&self.public.g1 * s;

        let e = hash2(&c, label, u, w, u1, w1);
        let f = s.deref() + &(r.deref() * &e);

        Ciphertext {
            c,
            label: label.to_vec(),
            u,
            u1,
            e,
            f,
        }
    }
    pub fn extract_label(&self, ciphertext: &Ciphertext) -> Vec<u8> {
        ciphertext.label.clone()
    }

    pub fn decrypt_share(&self, ciphertext: &Ciphertext) -> Option<DecryptionShare> {
        if !self.is_proof_valid(&ciphertext) {
            return None;
        };

        let ss = NonZeroScalar::random(&mut OsRng);

        let uu = (ProjectivePoint::from(ciphertext.u) * self.secret.secret_scalar).to_affine();
        let uu1 = ciphertext.u * ss;
        let hh = *&self.public.g * ss;
        let ee = hash4(uu, uu1, hh);
        let ff = *ss + (self.secret.secret_scalar * ee);

        Some(DecryptionShare {
            index: self.index,
            uu,
            ee,
            ff,
        })
    }
    // TODO: Verify_share should really accept a decryption share for a invalid ciphertext (e.g. "i, ?"). Currently just return false on invalid proof.
    pub fn verify_share(&self, ciphertext: &Ciphertext, decrypt_share: &DecryptionShare) -> bool {
        if !self.is_proof_valid(&ciphertext) {
            return false;
        };

        let DecryptionShare { uu, ee, ff, index } = decrypt_share;

        assert!(
            &self.verify.elements.len() > index,
            "Fewer verify elements ({}) than index {}",
            &self.verify.elements.len(),
            index
        );

        let uu1 = (ProjectivePoint::from(ciphertext.u) * ff) - (ProjectivePoint::from(*uu) * ee);
        let hh1 = (ProjectivePoint::from(*&self.public.g) * ff)
            - (ProjectivePoint::from(*&self.verify.elements[*index]) * ee);

        *ee == hash4(*uu, uu1.to_affine(), hh1.to_affine())
    }

    pub fn combine_shares(
        &self,
        ciphertext: &Ciphertext,
        shares: Vec<DecryptionShare>,
    ) -> Option<Plaintext> {
        if !self.is_proof_valid(&ciphertext) {
            return None;
        };

        let coefficients = self.calculate_lagrange_coefficients(&shares);

        // res = Summation over uu * coeff

        let result = shares
            .iter()
            .zip(coefficients)
            .fold(ProjectivePoint::identity(), |acc, (share, coeff)| {
                acc + (ProjectivePoint::from(share.uu) * coeff)
            });

        // m = H1(res) XOR c
        let h1 = hash1(result.to_affine());

        let mut data = [0u8; 32];

        data.copy_from_slice(
            &h1.iter()
                .zip(&ciphertext.c)
                .map(|(h_ele, c_ele)| h_ele ^ c_ele)
                .collect::<Vec<u8>>(),
        );

        Some(Plaintext { data })
    }

    fn is_proof_valid(&self, ciphertext: &Ciphertext) -> bool {
        let Ciphertext {
            c,
            label,
            u,
            u1,
            e,
            f,
        } = ciphertext;
        let w = (ProjectivePoint::from(*&self.public.g) * f) - (ProjectivePoint::from(*u) * e);
        let w1 = (ProjectivePoint::from(*&self.public.g1) * f) - (ProjectivePoint::from(*u1) * e);
        ciphertext.e == hash2(c, label, *u, w.to_affine(), *u1, w1.to_affine())
    }

    fn calculate_lagrange_coefficients(&self, shares: &Vec<DecryptionShare>) -> Vec<Scalar> {
        let index_set: HashSet<_> = shares.iter().map(|share| share.index).collect();

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

                assert_ne!(numerator, Scalar::zero(), "Expect numerator to not be zero");
                assert_ne!(
                    denumerator,
                    Scalar::zero(),
                    "Expect denumerator to not be zero"
                );
                // TODO: Ensure Denumerator is always  invertible, e.g. not zero.
                numerator * denumerator.invert().unwrap()
            })
            .collect()
    }
}

pub struct Ciphertext {
    c: Vec<u8>,
    label: Vec<u8>,
    u: AffinePoint,
    u1: AffinePoint,
    e: Scalar,
    f: Scalar,
}

pub struct DecryptionShare {
    index: usize,
    uu: AffinePoint,
    ee: Scalar,
    ff: Scalar,
}

pub struct Plaintext {
    data: [u8; 32],
}

#[cfg(test)]
mod tests {

    use super::*;

    const N_ACTORS_MULTIPLE: usize = 10;
    const THRESHOLD_MULTIPLE: usize = 5;

    #[test]
    fn test_proof_valid() {
        let keyset = Dealer::generate_keys(N_ACTORS_MULTIPLE, THRESHOLD_MULTIPLE);

        let actors: Vec<Actor> = (0..N_ACTORS_MULTIPLE)
            .into_iter()
            .map(|index| Actor {
                index,
                public: keyset.public,
                verify: keyset.verify.clone(),
                secret: keyset.secrets[index],
            })
            .collect();

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        let encrypted = actors[0].encrypt(&data, &data);

        for actor in &actors {
            assert!(actor.is_proof_valid(&encrypted));
        }
    }

    #[test]
    fn test_verify_share() {
        let keyset = Dealer::generate_keys(N_ACTORS_MULTIPLE, THRESHOLD_MULTIPLE);

        let actors: Vec<Actor> = (0..N_ACTORS_MULTIPLE)
            .into_iter()
            .map(|index| Actor {
                index,
                public: keyset.public,
                verify: keyset.verify.clone(),
                secret: keyset.secrets[index],
            })
            .collect();

        let message = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(message.as_bytes());

        let encrypted = actors[0].encrypt(&data, &data);

        let decrypt_shares: Vec<_> = actors
            .iter()
            .map(|actor| actor.decrypt_share(&encrypted).unwrap())
            .collect();

        assert_eq!(actors.len(), N_ACTORS_MULTIPLE);
        assert_eq!(decrypt_shares.len(), N_ACTORS_MULTIPLE);
        assert!(
            actors[0].verify_share(&encrypted, &decrypt_shares[0]),
            "Actor 0 could not verify share 0"
        );
        assert!(
            actors[1].verify_share(&encrypted, &decrypt_shares[1]),
            "Actor 1 could not verify share 1"
        );
    }

    #[test]
    fn test_threshold_encrypt_single_actor() {
        let keyset = Dealer::generate_keys(1, 1);

        let actors: Vec<Actor> = (0..1)
            .into_iter()
            .map(|index| Actor {
                index,
                public: keyset.public,
                verify: keyset.verify.clone(),
                secret: keyset.secrets[index],
            })
            .collect();

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
    fn test_threshold_encrypt_multiple_actors() {
        let keyset = Dealer::generate_keys(N_ACTORS_MULTIPLE, THRESHOLD_MULTIPLE);

        let actors: Vec<Actor> = (0..N_ACTORS_MULTIPLE)
            .into_iter()
            .map(|index| Actor {
                index,
                public: keyset.public,
                verify: keyset.verify.clone(),
                secret: keyset.secrets[index],
            })
            .collect();

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
}
