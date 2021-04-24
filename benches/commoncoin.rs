use criterion::{criterion_group, criterion_main, Criterion};

use threshold_crypto::{PublicKey, SecretKey};

use consensus_core::crypto::commoncoin::Coin;

fn toss_coin(coin: &Coin, data: &[u8; 32]) {
    coin.generate_share(data);
}

fn bench_commoncoin(c: &mut Criterion) {
    let coins = Coin::generate_coins(2, 1);
    let coin = &coins[0];

    let data = [0u8; 32];

    c.bench_function("commoncoin", |b| b.iter(|| toss_coin(coin, &data)));
}

criterion_group!(benches, bench_commoncoin);
criterion_main!(benches);
