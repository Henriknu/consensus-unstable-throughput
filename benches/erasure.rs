use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::{data::transaction::TransactionSet, erasure::*};

use bincode::serialize;

const N: usize = 32; // 8, 32, 64, 100
const F: usize = N / 4;
const WORD_SIZES: [usize; 1] = [8]; //4, 8, 16, 32
const PACKET_SIZES: [usize; 1] = [8]; //1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
const BATCH_SIZE: u32 = 1000;
const SEED_TRANSACTION_SET: u32 = 899923234;

fn criterion_benchmark(c: &mut Criterion) {
    let n = &N;
    let f = &F;

    for w in WORD_SIZES.iter() {
        for p in PACKET_SIZES.iter() {
            let encoder = ErasureCoder::new(
                NonZeroUsize::new((n - 2 * f) as usize).unwrap(),
                NonZeroUsize::new((2 * f) as usize).unwrap(),
                NonZeroUsize::new(*p).unwrap(),
                NonZeroUsize::new(*w).unwrap(),
            )
            .unwrap();

            {
                let t1 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, BATCH_SIZE)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B={}, W={}, P={},", n, BATCH_SIZE, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t1)),
                );
            }

            {
                let t2 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 1000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B=1000, W={}, P={},", n, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t2)),
                );
            }

            {
                let t3 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 10_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B=10_000, W={}, P={},", n, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t3)),
                );
            }

            {
                let t4 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 100_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B=100_000, W={}, P={},", n, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t4)),
                );
            }

            {
                let t5 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 1_000_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B=1_000_000, W={}, P={},", n, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t5)),
                );
            }

            {
                let t6 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 2_000_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B=2_000_000, W={}, P={},", n, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t6)),
                );
            }

            {
                let t1 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 100 as u32)
                        .random_selection(*n),
                )
                .unwrap();
                let encoded1 = encoder.encode(&t1);
                let encoded1: Vec<_> = encoded1
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();
                c.bench_function(
                    format!("erasure_decode N={},B=100, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded1, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }

            {
                let t2 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 1000 as u32)
                        .random_selection(*n),
                )
                .unwrap();
                let encoded2 = encoder.encode(&t2);
                let encoded2 = encoded2
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();
                c.bench_function(
                    format!("erasure_decode N={},B=1000, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded2, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }

            {
                let t3 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 10_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();
                let encoded3 = encoder.encode(&t3);
                let encoded3 = encoded3
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();

                c.bench_function(
                    format!("erasure_decode N={},B=10_000, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded3, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }

            {
                let t4 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 100_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();
                let encoded4 = encoder.encode(&t4);
                let encoded4 = encoded4
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();
                c.bench_function(
                    format!("erasure_decode N={},B=100_000, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded4, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }

            {
                let t5 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 1_000_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();
                let encoded5 = encoder.encode(&t5);
                let encoded5 = encoded5
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();
                c.bench_function(
                    format!("erasure_decode N={},B=1_000_000, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded5, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }

            {
                let t6 = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, 2_000_000 as u32)
                        .random_selection(*n),
                )
                .unwrap();

                let encoded6 = encoder.encode(&t6);
                let encoded6 = encoded6
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                    .collect();

                c.bench_function(
                    format!("erasure_decode N={},B=2_000_000, W={}, P={},", n, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded6, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
}

criterion_group! {
name = benches;
config = Criterion::default().sample_size(10);
targets = criterion_benchmark
}
criterion_main!(benches);
