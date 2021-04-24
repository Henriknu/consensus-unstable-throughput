use criterion::{criterion_group, criterion_main, Criterion};

use curve25519_dalek::traits::BasepointTable;
use curve25519_dalek::{constants, traits::Identity};
use curve25519_dalek::{
    edwards::{
        EdwardsBasepointTableRadix128, EdwardsBasepointTableRadix16, EdwardsBasepointTableRadix256,
        EdwardsBasepointTableRadix32, EdwardsBasepointTableRadix64, EdwardsPoint,
    },
    ristretto::RistrettoPoint,
};
use curve25519_dalek::{ristretto::RistrettoBasepointTable, scalar::Scalar};
use rand::{self, Rng};

fn ristretto(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let scalar = Scalar::random(&mut rng);

    let mut seed: [u8; 64] = [0u8; 64];
    rng.fill(&mut seed);

    let point = RistrettoPoint::from_uniform_bytes(&seed);
    let table = RistrettoBasepointTable::create(&point);

    c.bench_function("Scalar mul point w/o table", |b| b.iter(|| point * scalar));
    c.bench_function("Scalar mul point with table", |b| {
        b.iter(|| &table * &scalar)
    });
}

fn edward(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let scalar = Scalar::random(&mut rng);

    let mut seed: [u8; 64] = [0u8; 64];
    rng.fill(&mut seed);

    let point = EdwardsPoint::identity() * scalar;

    let table16 = EdwardsBasepointTableRadix16::create(&point);
    let table32 = EdwardsBasepointTableRadix32::create(&point);
    let table64 = EdwardsBasepointTableRadix64::create(&point);
    let table128 = EdwardsBasepointTableRadix128::create(&point);
    let table256 = EdwardsBasepointTableRadix256::create(&point);

    c.bench_function("Scalar mul point w/o table", |b| b.iter(|| point * scalar));
    c.bench_function("Scalar mul point with table16", |b| {
        b.iter(|| &table16 * &scalar)
    });
    c.bench_function("Scalar mul point with table32", |b| {
        b.iter(|| &table32 * &scalar)
    });
    c.bench_function("Scalar mul point with table64", |b| {
        b.iter(|| &table64 * &scalar)
    });
    c.bench_function("Scalar mul point with table128", |b| {
        b.iter(|| &table128 * &scalar)
    });
    c.bench_function("Scalar mul point with table256", |b| {
        b.iter(|| &table256 * &scalar)
    });
}

criterion_group!(benches, edward);
criterion_main!(benches);
