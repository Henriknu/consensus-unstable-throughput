use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::{data::transaction::TransactionSet, erasure::*};

use bincode::serialize;

fn erasure_encode(encoder: &ErasureCoder, data: &[u8]) {
    encoder.encode(data);
}

const N: u32 = 100;
const F: u32 = N / 4;
const SEED_TRANSACTION_SET: u32 = 899923234;

fn criterion_benchmark(c: &mut Criterion) {
    let encoder = ErasureCoder::new(
        NonZeroUsize::new((N - 2 * F) as usize).unwrap(),
        NonZeroUsize::new((2 * F) as usize).unwrap(),
    )
    .unwrap();
    let t1 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, N as u64)
            .random_selection(N as usize),
    )
    .unwrap();

    let t2 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 10_000 as u64)
            .random_selection(N as usize),
    )
    .unwrap();

    let t3 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 1_000_000 as u64)
            .random_selection(N as usize),
    )
    .unwrap();

    c.bench_function("erasure_encode N=100, B=N", |b| {
        b.iter(|| erasure_encode(&encoder, &t1))
    });

    c.bench_function("erasure_encode N=100, B=10_000", |b| {
        b.iter(|| erasure_encode(&encoder, &t2))
    });

    c.bench_function("erasure_encode N=100, B=1_000_000", |b| {
        b.iter(|| erasure_encode(&encoder, &t3))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
