use byteorder::{BigEndian, ReadBytesExt};
use p256::{AffinePoint, EncodedPoint, FieldBytes, NistP256, Scalar};
use tiny_keccak::{Hasher, Sha3};
use uint::{construct_uint, unroll};

construct_uint! {
    pub struct U256(4);
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

pub(crate) mod commoncoin {

    use std::borrow::Borrow;

    use p256::{
        elliptic_curve::{ff::PrimeField, group::ScalarMul, sec1::FromEncodedPoint},
        ProjectivePoint,
    };

    use super::*;

    static P256_B: &str =
        "41058363725152142129326129780047268409114441015993725554835256314039467401291";

    /// Hash function H: {0, 1}^32 -> G. Implement F(m) = f(h1(m)) + f(h2(m)) icart scheme.
    pub(crate) fn hash_1(data: &[u8]) -> AffinePoint {
        let mut sha3_256 = Sha3::v256();
        let mut output1 = [0u8; 32];
        sha3_256.update(data);
        sha3_256.finalize(&mut output1);
        let f1 = icart(Scalar::from_bytes_reduced(FieldBytes::from_slice(&output1)));

        let mut sha3_224 = Sha3::v224();
        let mut output2 = [0u8; 32];
        sha3_224.update(data);
        sha3_224.finalize(&mut output2);
        let f2 = icart(Scalar::from_bytes_reduced(FieldBytes::from_slice(&output2)));

        (ProjectivePoint::from(f1) + ProjectivePoint::from(f2)).to_affine()
    }

    fn icart(u: Scalar) -> AffinePoint {
        if u == Scalar::zero() {
            return AffinePoint::identity();
        }

        // ((3a - u^4)/6u)
        let v = (Scalar::zero() - Scalar::from(9) - u.square().square())
            * (u * Scalar::from(6)).invert_vartime().unwrap();

        let partial = v.square()
            - Scalar::from_str(P256_B).unwrap()
            - u.pow_vartime(&[6, 0, 0, 0]) * Scalar::from(27).invert_vartime().unwrap();

        let x = (partial
            * (partial.pow_vartime(&[3, 0, 0, 0]))
                .invert_vartime()
                .unwrap())
            + u.square() * Scalar::from(3).invert_vartime().unwrap();

        let y = u * x + v;

        AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x.to_bytes(),
            &y.to_bytes(),
            false,
        ))
        .unwrap()
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

    // Hash function H:  G -> {0,1}.
    pub(crate) fn hash_3(g: AffinePoint) -> bool {
        let mut sha3 = Sha3::v256();
        let mut output = [0u8; 32];

        sha3.update(EncodedPoint::from(g).as_bytes());
        sha3.finalize(&mut output);

        (output[0] & (1 << 7)) != 0
    }
}
