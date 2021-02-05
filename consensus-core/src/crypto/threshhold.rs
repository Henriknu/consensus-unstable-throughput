use openssl::{
    ec::*,
    pkey::HasPrivate,
    pkey::PKeyRef,
    pkey::{PKey, Private},
};
use openssl::{error::ErrorStack, nid::Nid};
use p256::pkcs8::FromPrivateKey;
use p256::pkcs8::FromPublicKey;
use p256::{ecdh::EphemeralSecret, EncodedPoint, NistP256, PublicKey, SecretKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::{error::Error, str};

const CURVE_ID: Nid = Nid::X9_62_PRIME256V1;

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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gen_key() {
        let (public, private) = generate_keys().unwrap();
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
}
