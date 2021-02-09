use openssl::{
    ec::*,
    nid::Nid,
    pkey::{PKey, Private},
};

use byteorder::{BigEndian, ReadBytesExt};
use p256::*;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::Group, EncodedPoint, NistP256, PublicKey, SecretKey,
};
use p256::{elliptic_curve::ff::PrimeField, pkcs8::FromPrivateKey};
use p256::{pkcs8::FromPublicKey, Scalar};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::{error::Error, io::Read, ops::Deref, str};

use super::hash::hash_sha256;

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

        let secrets: Vec<Scalar> = (0..n_actors)
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

struct PublicK {
    g: AffinePoint,
    g1: AffinePoint,
    h: AffinePoint,
}

struct VerifyK {
    elements: Vec<AffinePoint>,
}

struct SecretK {
    secret_scalar: Scalar,
}

/// Actor within the threshold cryptosystem. Has access to public key, verification key, and their own secret key.
pub struct Actor {
    public: PublicK,
    verify: VerifyK,
    secret: SecretK,
}

impl Actor {
    pub fn encrypt(data: &[u8]) {
        let r = AffinePoint::generator() * NonZeroScalar::random(&mut OsRng);
        let s = AffinePoint::generator() * NonZeroScalar::random(&mut OsRng);

        todo!()
    }
    pub fn extract_label(ciphertext: &[u8]) {
        todo!()
    }

    pub fn decrypt_share(ciphetext: &[u8]) {
        todo!()
    }

    pub fn verify_share(decrypt_share: &[u8]) -> bool {
        todo!()
    }

    pub fn combine_shares(shares: &[u8]) {
        todo!()
    }
}

struct ElgamalCipherPair {
    c1: ProjectivePoint,
    c2: ProjectivePoint,
}

/// Encode message into vector of Scalars
fn encode(msg: &str) -> Vec<Scalar> {
    let mut bytes = msg.as_bytes();

    let mut scalars = vec![];

    while let Ok(num) = bytes.read_u64::<BigEndian>() {
        let scalar = Scalar::from(num);
        scalars.push(scalar);
    }

    // Handle remaining bytes, if any
    if bytes.len() > 0 {
        let padding = vec![0; 8 - bytes.len()];
        let num = [padding.as_slice(), bytes]
            .concat()
            .as_slice()
            .read_u64::<BigEndian>()
            .unwrap();

        let scalar = p256::Scalar::from(num);
        scalars.push(scalar);
    }

    scalars
}

fn encode_to_points(msg: &str) -> Vec<EncodedPoint> {
    vec![]
}

fn decode(scalars: Vec<Scalar>) -> Vec<u8> {
    scalars
        .into_iter()
        .map(|scalar| scalar.to_bytes().as_slice().to_owned())
        .flatten()
        .collect()
}

fn elgamal(msg: &str, public: &PublicKey) -> Vec<u8> {
    let scalars = encode(msg);

    let y = RngCore::next_u64(&mut OsRng);

    let y = Scalar::from(y);

    decode(scalars)
}

#[cfg(test)]
mod tests {

    use std::{
        borrow::Borrow,
        ops::{Deref, Mul},
    };

    use super::*;

    #[test]
    fn test_gen_key() {
        let (public, private) = generate_keys().unwrap();
    }

    #[test]
    fn test_elgamal() {
        let (public, private) = generate_keys().unwrap();

        // public contains: random point alpha, point beta (from beta = alpha * a) + Curve and modulus p.

        let generator = ProjectivePoint::generator();

        // private contains secret integer, less than p.
        let secret_scalar = private.secret_scalar();

        let msg = "Hello world everyone here!";
        println!("Message: {}", msg);

        let cipher = elgamal(msg, &public);

        let resp = str::from_utf8(cipher.as_slice()).unwrap();

        println!("Response: {}", resp);
    }

    #[test]
    fn test_ecdh() {
        // Alice
        let alice_secret = EphemeralSecret::random(&mut OsRng);
        let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());

        // Bob
        let bob_secret = EphemeralSecret::random(&mut OsRng);
        let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());

        // Alice decodes Bob's serialized public key and computes a shared secret from it
        let bob_public = PublicKey::from_sec1_bytes(bob_pk_bytes.as_ref())
            .expect("bob's public key is invalid!"); // In real usage, don't panic, handle this!

        let alice_shared = alice_secret.diffie_hellman(&bob_public);

        // Bob deocdes Alice's serialized public key and computes the same shared secret
        let alice_public = PublicKey::from_sec1_bytes(alice_pk_bytes.as_ref())
            .expect("alice's public key is invalid!"); // In real usage, don't panic, handle this!

        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        // Both participants arrive on the same shared secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_elliptic_curve_mul() {
        let (public, private) = generate_keys().unwrap();

        let generator = ProjectivePoint::generator();

        // private contains secret integer, less than p.
        let secret_scalar = private.secret_scalar();

        let result = generator.mul(secret_scalar.deref());

        // point kept inside public key should be g * secret

        assert_eq!(public.to_projective(), result)
    }
}
