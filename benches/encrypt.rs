use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, Criterion};

use threshold_crypto::SecretKeySet;

use consensus_core::crypto::encrypt::Encrypter as EncrypterP256;
use consensus_core::crypto::encrypt_dalek::Encrypter as EncrypterDalek;
use consensus_core::crypto::encrypt_dalek_precomputed::Encrypter as EncrypterDalekPreComputed;

use rand;

const N: usize = T;
const T: usize = 25;

fn encrypt(c: &mut Criterion) {
    let encrypters_vec_256 = EncrypterP256::generate_keys(N, T);
    let encrypter_p256 = &encrypters_vec_256[0];
    let encrypters_vec_dalek = EncrypterDalek::generate_keys(N, T);
    let encrypter_dalek = &encrypters_vec_dalek[0];
    let encrypters_vec_dalek_precomputed = EncrypterDalekPreComputed::generate_keys(N, T);
    let encrypter_dalek_precomputed = &encrypters_vec_dalek_precomputed[0];
    let secrets = SecretKeySet::random(T, &mut rand::thread_rng());
    let publics = secrets.public_keys();
    let public_master = secrets.public_keys().public_key();
    let secret = secrets.secret_key_share(0);
    let public = secret.public_key_share();

    let data = [0u8; 32];

    // Encryption
    c.bench_function("threshold_encrypt_tdh2_p256", |b| {
        b.iter(|| encrypter_p256.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_curve25519_dalek_precomputed", |b| {
        b.iter(|| encrypter_dalek_precomputed.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_pairing", |b| {
        b.iter(|| public_master.encrypt(&data))
    });

    let ciphertext_p256 = encrypter_p256.encrypt(&data, &data);
    let ciphertext_dalek = encrypter_dalek.encrypt(&data, &data);
    let ciphertext_dalek_precomputed = encrypter_dalek_precomputed.encrypt(&data, &data);
    let ciphertext_pairing = public_master.encrypt(&data);

    // Decryption share, no verify
    c.bench_function("threshold_decrypt_share_tdh2_p256", |b| {
        b.iter(|| encrypter_p256.decrypt_share(&ciphertext_p256))
    });
    c.bench_function("threshold_decrypt_share_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.decrypt_share(&ciphertext_dalek))
    });
    c.bench_function(
        "threshold_decrypt_share_curve25519_dalek_precomputed",
        |b| b.iter(|| encrypter_dalek_precomputed.decrypt_share(&ciphertext_dalek_precomputed)),
    );
    c.bench_function("threshold_decrypt_share_pairing", |b| {
        b.iter(|| secret.decrypt_share_no_verify(&ciphertext_pairing))
    });

    let dec_share_p256 = encrypter_p256.decrypt_share(&ciphertext_p256).unwrap();
    let dec_share_dalek = encrypter_dalek.decrypt_share(&ciphertext_dalek).unwrap();
    let dec_share_dalek_precomputed = encrypter_dalek_precomputed
        .decrypt_share(&ciphertext_dalek_precomputed)
        .unwrap();
    let dec_share_pairing = secret.decrypt_share(&ciphertext_pairing).unwrap();

    // Verify share
    c.bench_function("P256 Verify Share", |b| {
        b.iter(|| encrypter_p256.verify_share(&ciphertext_p256, &dec_share_p256))
    });
    c.bench_function("Curve25519 Dalek Verify Share", |b| {
        b.iter(|| encrypter_dalek.verify_share(&ciphertext_dalek, &dec_share_dalek))
    });
    c.bench_function(
        "Curve25519 Dalek Verify Share w Precomputed Basepoint Tables",
        |b| {
            b.iter(|| {
                encrypter_dalek_precomputed
                    .verify_share(&ciphertext_dalek_precomputed, &dec_share_dalek_precomputed)
            })
        },
    );
    c.bench_function("Threshold_crypto Pairing Based Verify Share", |b| {
        b.iter(|| public.verify_decryption_share(&dec_share_pairing, &ciphertext_pairing))
    });

    let combine_share_p256: Vec<_> = encrypters_vec_256
        .iter()
        .map(|encrypter| encrypter.decrypt_share(&ciphertext_p256).unwrap())
        .collect();

    let combine_share_dalek: Vec<_> = encrypters_vec_dalek
        .iter()
        .map(|encrypter| encrypter.decrypt_share(&ciphertext_dalek).unwrap())
        .collect();

    let combine_share_dalek_precomputed: Vec<_> = encrypters_vec_dalek_precomputed
        .iter()
        .map(|encrypter| {
            encrypter
                .decrypt_share(&ciphertext_dalek_precomputed)
                .unwrap()
        })
        .collect();

    let combine_share_pairing: BTreeMap<usize, _> = (0..N + 1)
        .map(|i| {
            (
                i,
                secrets
                    .secret_key_share(i)
                    .decrypt_share(&ciphertext_pairing)
                    .unwrap(),
            )
        })
        .collect();

    // Combine shares

    c.bench_function("P256 Combine 2 Shares ", |b| {
        b.iter_batched(
            || combine_share_p256.clone(),
            |shares| encrypter_p256.combine_shares(&ciphertext_p256, shares),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("Curve25519 Dalek Combine 2 Shares ", |b| {
        b.iter_batched(
            || combine_share_dalek.clone(),
            |shares| encrypter_dalek.combine_shares(&ciphertext_dalek, shares),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function(
        "Curve25519 Dalek Combine 2 Shares w Precomputed BasePoint Tables ",
        |b| {
            b.iter_batched(
                || combine_share_dalek_precomputed.clone(),
                |shares| {
                    encrypter_dalek_precomputed
                        .combine_shares(&ciphertext_dalek_precomputed, shares)
                },
                criterion::BatchSize::SmallInput,
            )
        },
    );

    c.bench_function("Threshold_crypto Pairing Based 2 Shares ", |b| {
        b.iter_batched(
            || combine_share_pairing.clone(),
            |shares| publics.decrypt(&shares, &ciphertext_pairing),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group! {
name = benches;
config = Criterion::default().sample_size(1000);
targets = encrypt
}
criterion_main!(benches);
