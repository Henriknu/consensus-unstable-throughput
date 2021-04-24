use consensus_core::crypto::encrypt_dalek::Encrypter;
use curve25519_dalek::traits::BasepointTable;
use curve25519_dalek::{constants, traits::Identity};
use curve25519_dalek::{
    edwards::{EdwardsBasepointTableRadix256, EdwardsPoint},
    ristretto::RistrettoPoint,
};
use curve25519_dalek::{ristretto::RistrettoBasepointTable, scalar::Scalar};

fn main() {
    let point = EdwardsPoint::identity();
    let table = EdwardsBasepointTableRadix256::create(&point);
    let s = &table * &Scalar::one();
}
