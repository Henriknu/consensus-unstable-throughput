use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::crypto::encrypt_dalek::Encrypter as EncrypterDalek;
use consensus_core::crypto::encrypt_dalek_precomputed::Encrypter as EncrypterDalekPreComputed;

const N: usize = 100;
const T: usize = N / 4;

fn precomputed(c: &mut Criterion) {
    let encrypters_vec_dalek = EncrypterDalek::generate_keys(N, T);
    let encrypter_dalek = &encrypters_vec_dalek[0];
    let encrypters_vec_dalek_precomputed = EncrypterDalekPreComputed::generate_keys(N, T);
    let encrypter_dalek_precomputed = &encrypters_vec_dalek_precomputed[0];

    let data = [0u8; 32];

    // Encryption

    c.bench_function("threshold_encrypt_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.encrypt(&data, &data))
    });
    c.bench_function("threshold_encrypt_curve25519_dalek_precomputed", |b| {
        b.iter(|| encrypter_dalek_precomputed.encrypt(&data, &data))
    });

    let ciphertext_dalek = encrypter_dalek.encrypt(&data, &data);
    let ciphertext_dalek_precomputed = encrypter_dalek_precomputed.encrypt(&data, &data);

    // Decryption share, no verify

    c.bench_function("threshold_decrypt_share_curve25519_dalek", |b| {
        b.iter(|| encrypter_dalek.decrypt_share(&ciphertext_dalek))
    });
    c.bench_function(
        "threshold_decrypt_share_curve25519_dalek_precomputed",
        |b| b.iter(|| encrypter_dalek_precomputed.decrypt_share(&ciphertext_dalek_precomputed)),
    );

    let dec_share_dalek = encrypter_dalek.decrypt_share(&ciphertext_dalek).unwrap();
    let dec_share_dalek_precomputed = encrypter_dalek_precomputed
        .decrypt_share(&ciphertext_dalek_precomputed)
        .unwrap();

    // Verify share

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

    // Combine shares

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
}

criterion_group! {
name = benches;
config = Criterion::default().sample_size(1000);
targets = precomputed
}
criterion_main!(benches);
