use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::erasure::*;

fn erasure_encode(encoder: &ErasureCoder, data: &[u8]) {
    encoder.encode(data);
}

fn criterion_benchmark(c: &mut Criterion) {
    let n = 100;
    let encoder = ErasureCoder::new(
        NonZeroUsize::new((n / 3 + 1) as usize).unwrap(),
        NonZeroUsize::new((n * 2 / 3) as usize).unwrap(),
    )
    .unwrap();
    let data1 = [54u8; 1024];
    let data2 = [54u8; 1024000];

    c.bench_function("erasure_encode_kb", |b| {
        b.iter(|| erasure_encode(&encoder, &data1))
    });

    c.bench_function("erasure_encode_mb", |b| {
        b.iter(|| erasure_encode(&encoder, &data2))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
