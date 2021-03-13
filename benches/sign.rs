use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use consensus_core::crypto::sign::Signer;

fn threshold_crypto_sign(signer: &Signer, data: &[u8]) {
    signer.sign(data);
}

fn criterion_benchmark(c: &mut Criterion) {
    let signer = Signer::generate_signers(2, 1);
    let data = "Hello world!".as_bytes();

    c.bench_function("threshold_crypto sign", |b| {
        b.iter(|| threshold_crypto_sign(&signer[0], data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
