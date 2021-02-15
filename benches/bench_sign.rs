use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use consensus_core::crypto::sign1::Signer;

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn threshold_crypto_sign(signer: &Signer, data: &[u8]) {
    signer.sign(data);
}

fn criterion_benchmark(c: &mut Criterion) {
    let signer = Signer::generate_signers(2, 1);
    let data = "Hello world!".as_bytes();

    c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
    c.bench_function("threshold_crypto sign", |b| {
        b.iter(|| threshold_crypto_sign(&signer[0], data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
