use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::crypto::encrypt::Encrypter;

fn threshold_encrypt(encrypter: &Encrypter, data: &[u8; 32]) {
    encrypter.encrypt(data, data);
}

fn criterion_benchmark(c: &mut Criterion) {
    let encrypters = Encrypter::generate_keys(2, 1);
    let data = [0u8; 32];

    c.bench_function("threshold_encrypt", |b| {
        b.iter(|| threshold_encrypt(&encrypters[0], &data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
