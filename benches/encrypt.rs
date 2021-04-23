use criterion::{criterion_group, criterion_main, Criterion};

use threshold_crypto::{PublicKey, SecretKey};

use consensus_core::crypto::encrypt::Encrypter;

fn threshold_encrypt_tdh2(encrypter: &Encrypter, data: &[u8; 32]) {
    encrypter.encrypt(data, data);
}

fn threshold_encrypt_pairing(encrypter: &PublicKey, data: &[u8; 32]) {
    encrypter.encrypt(data);
}

fn bench_tdh2(c: &mut Criterion) {
    let encrypters = Encrypter::generate_keys(2, 1);
    let encrypter = &encrypters[0];

    let data = [0u8; 32];

    c.bench_function("threshold_encrypt_tdh2", |b| {
        b.iter(|| threshold_encrypt_tdh2(encrypter, &data))
    });
}

fn bench_pairing(c: &mut Criterion) {
    let public = SecretKey::random().public_key();
    let data = [0u8; 32];

    c.bench_function("threshold_encrypt_pairing", |b| {
        b.iter(|| threshold_encrypt_pairing(&public, &data))
    });
}

criterion_group!(benches, bench_tdh2, bench_pairing);
criterion_main!(benches);
