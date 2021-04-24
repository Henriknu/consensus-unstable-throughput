use criterion::{criterion_group, criterion_main, Criterion};

use threshold_crypto::{PublicKey, SecretKey, SecretKeySet};

use consensus_core::crypto::encrypt::Encrypter as EncrypterP256;
use consensus_core::crypto::encrypt_dalek::Encrypter as EncrypterDalek;
use rand;

fn encrypt(c: &mut Criterion) {
    let encrypters = EncrypterP256::generate_keys(2, 1);
    let encrypter_p256 = &encrypters[0];
    let encrypters = EncrypterDalek::generate_keys(2, 1);
    let encrypter_dalek = &encrypters[0];
    let public = SecretKey::random().public_key();

    let data = [0u8; 32];

    c.bench_function("threshold_encrypt_tdh2_p256", |b| {
        b.iter(|| encrypter_p256.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_pairing", |b| {
        b.iter(|| public.encrypt(&data))
    });
}

fn decrypt_share(c: &mut Criterion) {
    let encrypters = EncrypterP256::generate_keys(2, 1);
    let encrypter_p256 = &encrypters[0];
    let encrypters = EncrypterDalek::generate_keys(2, 1);
    let encrypter_dalek = &encrypters[0];
    let secrets = SecretKeySet::random(1, &mut rand::thread_rng());
    let public = secrets.public_keys().public_key();
    let secret = secrets.secret_key_share(0);

    let data = [0u8; 32];

    let ciphertext_p256 = encrypter_p256.encrypt(&data, &data);
    let ciphertext_dalek = encrypter_dalek.encrypt(&data, &data);
    let ciphertext_pairing = public.encrypt(&data);

    c.bench_function("threshold_decrypt_share_tdh2_p256", |b| {
        b.iter(|| encrypter_p256.decrypt_share(&ciphertext_p256))
    });
    c.bench_function("threshold_decrypt_shar_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.decrypt_share(&ciphertext_dalek))
    });
    c.bench_function("threshold_decrypt_shar_pairing", |b| {
        b.iter(|| secret.decrypt_share_no_verify(&ciphertext_pairing))
    });
}

criterion_group!(benches, encrypt, decrypt_share);
criterion_main!(benches);
