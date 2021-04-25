use std::fmt::Display;

use p256::{AffinePoint, EncodedPoint, FieldBytes, Scalar};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use uint::{construct_uint, unroll};

construct_uint! {
    pub struct U256(4);
}

pub trait Hashable {
    fn hash(&self) -> H256;
}

impl Hashable for Vec<u8> {
    fn hash(&self) -> H256 {
        H256 {
            inner: hash_sha256(&self),
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Hash, Ord,
)]
pub struct H256 {
    pub inner: [u8; 32],
}

impl H256 {
    pub fn hash_together(first: H256, second: H256) -> H256 {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];
        sha3.update(&first.inner);
        sha3.update(&second.inner);
        sha3.finalize(&mut output);
        H256 { inner: output }
    }
}

impl Display for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}..{}{}",
            self.inner[0], self.inner[1], self.inner[30], self.inner[31],
        )
    }
}

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

/// Hash functions used within the TDH2 threshold encryption system.
pub(crate) mod threshold {
    use super::*;

    /// Hash function H: G -> {0, 1}^32
    pub(crate) fn hash1(point: AffinePoint) -> [u8; 32] {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];
        sha3.update(EncodedPoint::from(point).as_bytes());
        sha3.finalize(&mut output);
        output
    }

    /// Hash function H: {0, 1}^32 x {0, 1}^32 x  G^4 -> Zq
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

        Scalar::from_bytes_reduced(FieldBytes::from_slice(&output))
    }

    /// Hash function H: G^3 -> Zq
    pub(crate) fn hash4(u: AffinePoint, u1: AffinePoint, h: AffinePoint) -> Scalar {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(EncodedPoint::from(u).as_bytes());
        sha3.update(EncodedPoint::from(u1).as_bytes());
        sha3.update(EncodedPoint::from(h).as_bytes());
        sha3.finalize(&mut output);

        Scalar::from_bytes_reduced(FieldBytes::from_slice(&output))
    }
}

pub(crate) mod dalek {

    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use tiny_keccak::{Hasher, Sha3};

    /// Hash function H: G -> {0, 1}^32
    pub(crate) fn hash1(point: RistrettoPoint) -> [u8; 32] {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];
        sha3.update(point.compress().as_bytes());
        sha3.finalize(&mut output);
        output
    }

    /// Hash function H: {0, 1}^32 x {0, 1}^32 x  G^4 -> Zq
    pub(crate) fn hash2(
        ciphertext: &[u8],
        label: &[u8],
        u: RistrettoPoint,
        w: RistrettoPoint,
        u1: RistrettoPoint,
        w1: RistrettoPoint,
    ) -> Scalar {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(ciphertext);
        sha3.update(label);
        sha3.update(u.compress().as_bytes());
        sha3.update(u1.compress().as_bytes());
        sha3.update(w.compress().as_bytes());
        sha3.update(w1.compress().as_bytes());
        sha3.finalize(&mut output);

        Scalar::from_bytes_mod_order(output)
    }

    /// Hash function H: G^3 -> Zq
    pub(crate) fn hash4(u: RistrettoPoint, u1: RistrettoPoint, h: RistrettoPoint) -> Scalar {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(u.compress().as_bytes());
        sha3.update(u1.compress().as_bytes());
        sha3.update(h.compress().as_bytes());
        sha3.finalize(&mut output);

        Scalar::from_bytes_mod_order(output)
    }
}

/// Hash functions used within the TDH2 threshold encryption system.
pub(crate) mod commoncoin {

    use p256::ProjectivePoint;

    use super::*;

    // TODO: Verify assumption that H(m) = (h(m) to Zq) * g is sufficient. If not, current draft: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-4.
    // Would require implementing square root functions for p-256. Rust impl: https://dusk-network.github.io/dusk-zerocaf/src/zerocaf/backend/u64/field.rs.html#380-442
    /// Hash function H: {0, 1}^32 -> G.
    pub(crate) fn hash_1(data: &[u8]) -> AffinePoint {
        let mut sha3_256 = Sha3::v256();
        let mut output = [0u8; 32];
        sha3_256.update(data);
        sha3_256.finalize(&mut output);

        (ProjectivePoint::generator() * Scalar::from_bytes_reduced(FieldBytes::from_slice(&output)))
            .to_affine()
    }

    // Hash function H:  G^6 -> Zq
    pub(crate) fn hash_2(
        g: AffinePoint,
        gg: AffinePoint,
        h: AffinePoint,
        g1: AffinePoint,
        gg1: AffinePoint,
        h1: AffinePoint,
    ) -> Scalar {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(EncodedPoint::from(g).as_bytes());
        sha3.update(EncodedPoint::from(gg).as_bytes());
        sha3.update(EncodedPoint::from(h).as_bytes());
        sha3.update(EncodedPoint::from(g1).as_bytes());
        sha3.update(EncodedPoint::from(gg1).as_bytes());
        sha3.update(EncodedPoint::from(h1).as_bytes());
        sha3.finalize(&mut output);

        Scalar::from_bytes_reduced(FieldBytes::from_slice(&output))
    }

    // Hash function H:  G -> {0,1}^32.
    pub(crate) fn hash_3(g: AffinePoint) -> [u8; 32] {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(EncodedPoint::from(g).as_bytes());
        sha3.finalize(&mut output);

        output
    }
}

pub(crate) mod commoncoin_dalek {
    /// Hash functions used within the TDH2 threshold encryption system.
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use tiny_keccak::{Hasher, Sha3};

    pub(crate) fn hash_1(data: &[u8]) -> RistrettoPoint {
        let mut sha3 = Sha3::v512();
        let mut output = [0u8; 64];
        sha3.update(data);
        sha3.finalize(&mut output);

        RistrettoPoint::from_uniform_bytes(&output)
    }

    // Hash function H:  G^6 -> Zq
    pub(crate) fn hash_2(
        g: RistrettoPoint,
        gg: RistrettoPoint,
        h: RistrettoPoint,
        g1: RistrettoPoint,
        gg1: RistrettoPoint,
        h1: RistrettoPoint,
    ) -> Scalar {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(g.compress().as_bytes());
        sha3.update(gg.compress().as_bytes());
        sha3.update(h.compress().as_bytes());
        sha3.update(g1.compress().as_bytes());
        sha3.update(gg1.compress().as_bytes());
        sha3.update(h1.compress().as_bytes());
        sha3.finalize(&mut output);

        Scalar::from_bytes_mod_order(output)
    }

    // Hash function H:  G -> {0,1}^32.
    pub(crate) fn hash_3(g: RistrettoPoint) -> [u8; 32] {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(g.compress().as_bytes());
        sha3.finalize(&mut output);

        output
    }
}

#[cfg(test)]
mod test_super {
    use super::*;

    use byteorder::ByteOrder;
    use p256::elliptic_curve::ff::PrimeField;

    #[test]
    fn test_() {
        let mut output = [0u8; 32];

        U256::from_dec_str(
            "57896044605178124381348723474703786764998477612067880171211129530534256022184",
        )
        .unwrap()
        .to_big_endian(&mut output);

        println!("hei");

        let mut result = [0u64; 4];

        result[3] = byteorder::BigEndian::read_u64(&output[0..8]);
        result[2] = byteorder::BigEndian::read_u64(&output[8..16]);
        result[1] = byteorder::BigEndian::read_u64(&output[16..24]);
        result[0] = byteorder::BigEndian::read_u64(&output[24..32]);

        println!("{:?}", result);

        let num = Scalar::from_str(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        )
        .unwrap();
        println!("{:?}", num);
    }
}
