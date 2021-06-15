use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::{data::transaction::TransactionSet, erasure::*};

use bincode::serialize;

const N: usize = 8; // LAN 4, 7, 8, 16, 32, 48, 64, 80, 100 WAN 8, 32, 64, 100
const F: usize = N/4;
const WORD_SIZES: [usize; 2] = [3, 4]; // 1,2,3,4,5,6,7,8
const PACKET_SIZES: [usize; 17 ] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]; //1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
const BATCH_SIZES: [u32;6 ] = [100, 1000, 10_000, 100_000, 1_000_000, 2_000_000];
const SEED_TRANSACTION_SET: u32 = 899923234;

fn criterion_benchmark(c: &mut Criterion) {
    let n = &N;
    let f = &F;

    for b in BATCH_SIZES.iter() {


        for w in WORD_SIZES.iter() {
            for p in PACKET_SIZES.iter() {
        
                let encoder = ErasureCoder::new(
                    NonZeroUsize::new((n - 2 * f) as usize).unwrap(),
                    NonZeroUsize::new((2 * f) as usize).unwrap(),
                    NonZeroUsize::new(*p).unwrap(),
                    NonZeroUsize::new(*w).unwrap(),
                )
                .unwrap();

                let t = serialize(
                    &TransactionSet::generate_transactions(SEED_TRANSACTION_SET, *b)
                        .random_selection(*n),
                )
                .unwrap();

                c.bench_function(
                    format!("erasure_encode N={},B={}, W={}, P={},", n, b, w, p).as_str(),
                    |b| b.iter(|| encoder.encode(&t)),
                );

                let encoded = encoder.encode(&t)
                .into_iter()
                .enumerate()
                .filter_map(|(i, v)| if i >= 2 * *f { Some(v) } else { None })
                .collect();

                c.bench_function(
                    format!("erasure_decode N={},B={}, W={}, P={},", n, b, w, p).as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(2 * *f as i32)).collect(),
                            |erasures| encoder.decode(&encoded, erasures).unwrap(),
                            criterion::BatchSize::SmallInput,
                        )
                    },
                );

                let encoded: Vec<_> = encoder.encode(&t)
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, v)| if i >= *f { Some(v) } else { None })
                        .collect();

                c.bench_function(
                    format!(
                        "erasure_reconstruct N={},B={}, W={}, P={},",
                        n, b, w, p
                    )
                    .as_str(),
                    |b| {
                        b.iter_batched(
                            || (0i32..(*f as i32)).collect(),
                            |erasures| encoder.reconstruct(&encoded, erasures).unwrap(),
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
config = Criterion::default().sample_size(100);
targets = criterion_benchmark
}
criterion_main!(benches);
