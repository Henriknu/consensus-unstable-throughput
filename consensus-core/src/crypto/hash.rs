use p256::{AffinePoint, EncodedPoint, FieldBytes, NistP256, Scalar};
use tiny_keccak::{Hasher, Sha3};

pub fn hash_sha256(bytes: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];
    sha3.update(&bytes);
    sha3.finalize(&mut output);
    output
}

pub fn verify_sha256(bytes: &[u8], hash: [u8; 32]) -> bool {
    let computed = hash_sha256(bytes);

    computed == hash
}

pub(crate) fn hash1(point: AffinePoint) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];
    sha3.update(EncodedPoint::from(point).as_bytes());
    sha3.finalize(&mut output);
    output
}

pub(crate) fn hash2(
    ciphertext: &[u8],
    label: &[u8],
    u: AffinePoint,
    w: AffinePoint,
    u1: AffinePoint,
    w1: AffinePoint,
) -> Scalar {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];

    sha3.update(ciphertext);
    sha3.update(label);
    sha3.update(EncodedPoint::from(u).as_bytes());
    sha3.update(EncodedPoint::from(w).as_bytes());
    sha3.update(EncodedPoint::from(u1).as_bytes());
    sha3.update(EncodedPoint::from(w1).as_bytes());
    sha3.finalize(&mut output);

    // Translate 32 byte output into integer mod p

    Scalar::from_bytes_reduced(FieldBytes::from_slice(&output))
}

pub(crate) fn hash4(u: AffinePoint, u1: AffinePoint, h: AffinePoint) -> Scalar {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];

    sha3.update(EncodedPoint::from(u).as_bytes());
    sha3.update(EncodedPoint::from(u1).as_bytes());
    sha3.update(EncodedPoint::from(h).as_bytes());
    sha3.finalize(&mut output);

    // Translate 32 byte output into integer mod p

    Scalar::from_bytes_reduced(FieldBytes::from_slice(&output))
}
