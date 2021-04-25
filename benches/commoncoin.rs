use criterion::{criterion_group, criterion_main, Criterion};

use threshold_crypto::{PublicKey, SecretKey};

use consensus_core::crypto::commoncoin_dalek_precomputed::Coin as CoinDalekPreComputed;
use consensus_core::crypto::commoncoin_p256::Coin as CoinP256;

const N: usize = T;
const T: usize = 25;

fn bench_commoncoin(c: &mut Criterion) {
    let coins_vec_p256 = CoinP256::generate_coins(N, T);
    let coin_p256 = &coins_vec_p256[0];
    let coins_vec_dalek_precomputed = CoinDalekPreComputed::generate_coins(N, T);
    let coin_dalek_precomputed = &coins_vec_dalek_precomputed[0];

    let data = [0u8; 32];

    c.bench_function("P256 Generate Share", |b| {
        b.iter(|| coin_p256.generate_share(&data))
    });
    c.bench_function("Dalek w Precompute Generate Share", |b| {
        b.iter(|| coin_dalek_precomputed.generate_share(&data))
    });

    let share_p256 = coin_p256.generate_share(&data);
    let share_dalek_precomputed = coin_dalek_precomputed.generate_share(&data);

    c.bench_function("P256 Verify Share", |b| {
        b.iter(|| coin_p256.verify_share(&data, &share_p256))
    });
    c.bench_function("Dalek w Precompute Verify Share", |b| {
        b.iter(|| coin_dalek_precomputed.verify_share(&data, &share_dalek_precomputed))
    });

    let shares_p256 = coins_vec_p256
        .iter()
        .map(|c| c.generate_share(&data))
        .collect();

    let shares_dalek_precomputed = coins_vec_dalek_precomputed
        .iter()
        .map(|c| c.generate_share(&data))
        .collect();

    let range = N as u32;

    c.bench_function("P256 Combine Shares, N = 25", |b| {
        b.iter(|| coin_p256.combine_shares(&shares_p256, range))
    });
    c.bench_function("Dalek w Precompute Combine Shares, N = 25", |b| {
        b.iter(|| coin_dalek_precomputed.combine_shares(&shares_dalek_precomputed, range))
    });
}

criterion_group!(benches, bench_commoncoin);
criterion_main!(benches);
