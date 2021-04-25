use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::crypto::sign::Signer;

const N: usize = T * 4;
const T: usize = 25;

fn criterion_benchmark(c: &mut Criterion) {
    let signers = Signer::generate_signers(N, T);
    let signer = &signers[0];
    let data = "Hello world!".as_bytes();

    c.bench_function("threshold_crypto Sign Share", |b| {
        b.iter(|| signer.sign(data))
    });

    let sig_share = signer.sign(data);

    c.bench_function("threshold_crypto Verify Share", |b| {
        b.iter(|| signer.verify_share(0, &sig_share, data))
    });

    let shares = signers
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.sign(data)))
        .collect();

    c.bench_function("threshold_crypto Combine Shares, N = 100, T = 25", |b| {
        b.iter(|| signer.combine_signatures(&shares))
    });

    let signature = signer.combine_signatures(&shares).unwrap();

    c.bench_function("threshold_crypto Verify Signature, N = 100, T = 25", |b| {
        b.iter(|| signer.verify_signature(&signature, data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
