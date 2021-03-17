use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use consensus_core::crypto::aes::SymmetricEncrypter;

fn symmetric_encrypt(data: &[u8]) {
    SymmetricEncrypter::encrypt(data).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let data = "Hello world!".as_bytes();

    c.bench_function("Symmetric encryption AES256 GCM", |b| {
        b.iter(|| symmetric_encrypt(data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
