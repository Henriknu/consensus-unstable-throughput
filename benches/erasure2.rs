use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::{data::transaction::TransactionSet, erasure::*};

use bincode::serialize;

const SEED_TRANSACTION_SET: u32 = 899923234;

fn criterion_benchmark(c: &mut Criterion) {
    let n = 100;
    let f = n / 4;
    let w1 = 7;
    let w2 = 7;
    let p1 = 1;
    let p2 = 8192;

    let encoder1 = ErasureCoder::new(
        NonZeroUsize::new((n - 2 * f) as usize).unwrap(),
        NonZeroUsize::new((2 * f) as usize).unwrap(),
        NonZeroUsize::new(p1).unwrap(),
        NonZeroUsize::new(w1).unwrap(),
    )
    .unwrap();

    let encoder2 = ErasureCoder::new(
        NonZeroUsize::new((n - 2 * f) as usize).unwrap(),
        NonZeroUsize::new((2 * f) as usize).unwrap(),
        NonZeroUsize::new(p2).unwrap(),
        NonZeroUsize::new(w2).unwrap(),
    )
    .unwrap();

    let t1 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 100).random_selection(n),
    )
    .unwrap();

    c.bench_function(
        format!("erasure_encode N={},B={}, W={}, P={},", n, 100, w1, p1).as_str(),
        |b| b.iter(|| encoder1.encode(&t1)),
    );

    c.bench_function(
        format!("erasure_encode N={},B={}, W={}, P={},", n, 100, w2, p2).as_str(),
        |b| b.iter(|| encoder2.encode(&t1)),
    );

    let t1 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 100_000).random_selection(n),
    )
    .unwrap();

    c.bench_function(
        format!("erasure_encode N={},B={}, W={}, P={},", n, 100_000, w1, p1).as_str(),
        |b| b.iter(|| encoder1.encode(&t1)),
    );

    c.bench_function(
        format!("erasure_encode N={},B={}, W={}, P={},", n, 100_000, w2, p2).as_str(),
        |b| b.iter(|| encoder2.encode(&t1)),
    );

    let t1 = serialize(
        &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 2_000_000).random_selection(n),
    )
    .unwrap();

    c.bench_function(
        format!(
            "erasure_encode N={},B={}, W={}, P={},",
            n, 2_000_000, w1, p1
        )
        .as_str(),
        |b| b.iter(|| encoder1.encode(&t1)),
    );

    c.bench_function(
        format!(
            "erasure_encode N={},B={}, W={}, P={},",
            n, 2_000_000, w2, p2
        )
        .as_str(),
        |b| b.iter(|| encoder2.encode(&t1)),
    );

}

criterion_group! {
name = benches;
config = Criterion::default().sample_size(10);
targets = criterion_benchmark
}
criterion_main!(benches);
