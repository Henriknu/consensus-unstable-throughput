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
/// Hash functions used within the TDH2 threshold encryption system.
pub(crate) mod commoncoin {

    use std::borrow::Borrow;

    use p256::{
        elliptic_curve::{ff::PrimeField, group::ScalarMul, sec1::FromEncodedPoint},
        ProjectivePoint,
    };

    use super::*;

    static P256_B: &str =
        "41058363725152142129326129780047268409114441015993725554835256314039467401291";

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

        assert_ne!(partial, Scalar::one());

        // Cube root: N^12865787690039583195855271883267508169999661691570640038046917673452056893819
        // P - 1 / 3 = [12003011744808111216, 4537280849171177345, 6148914691236517205, 6148914689804861440]
        // 2P - 1 / 3 = [5559279415906670816, 9074561698342354691, 12297829382473034410, 12297829379609722880]
        // p + 2 / 9 = [16298833297409071483, 1512426949723725781, 8198552921648689607, 2049638229934953813]
        let x = (partial.pow_vartime(&[
            16298833297409071483,
            1512426949723725781,
            8198552921648689607,
            2049638229934953813,
        ])) + (u.square() * Scalar::from(3).invert_vartime().unwrap());

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

#[cfg(test)]
mod test_super {
    use super::*;

    use byteorder::ByteOrder;
    use p256::elliptic_curve::ff::PrimeField;
    use uint::construct_uint;

    construct_uint! {
        pub struct U256(4);
    }

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
