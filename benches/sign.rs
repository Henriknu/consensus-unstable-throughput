use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::crypto::sign::Signer;
use consensus_core::crypto::sign_ecdsa::Signer as ECDSA;

const N: usize = T * 4;
const T: usize = 25;

fn criterion_benchmark(c: &mut Criterion) {
    let signers_vec_pairing = Signer::generate_signers(N, T);
    let signer_pairing = &signers_vec_pairing[0];
    let signers_vec_ecdsa = ECDSA::generate_signers(N, T);
    let signer_ecdsa = &signers_vec_ecdsa[0];

    let data = "Hello world!".as_bytes();

    c.bench_function("threshold_crypto Sign Share", |b| {
        b.iter(|| signer_pairing.sign(data))
    });
    c.bench_function("ECDSA Sign Share", |b| {
        b.iter(|| signer_ecdsa.sign_reuse_pre_signed(data))
    });

    let sig_share_pairing = signer_pairing.sign(data);

    c.bench_function("threshold_crypto Verify Share", |b| {
        b.iter(|| signer_pairing.verify_share(0, &sig_share_pairing, data))
    });

    let shares_pairing = signers_vec_pairing
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.sign(data)))
        .collect();
    let shares_ecdsa = signers_vec_ecdsa
        .iter()
        .map(|s| s.sign_reuse_pre_signed(data))
        .collect();

    c.bench_function("threshold_crypto Combine Shares, N = 100, T = 25", |b| {
        b.iter(|| signer_pairing.combine_signatures(&shares_pairing))
    });

    c.bench_function("ECDSA Combine Shares, N = 100, T = 25", |b| {
        b.iter(|| signer_ecdsa.combine_signatures(&shares_ecdsa))
    });

    let signature_pairing = signer_pairing.combine_signatures(&shares_pairing).unwrap();
    let signature_ecdsa = signer_ecdsa.combine_signatures(&shares_ecdsa);

    c.bench_function("threshold_crypto Verify Signature, N = 100, T = 25", |b| {
        b.iter(|| signer_pairing.verify_signature(&signature_pairing, data))
    });

    c.bench_function("ECDSA Verify Signature, N = 100, T = 25", |b| {
        b.iter(|| signer_ecdsa.verify_signature(&signature_ecdsa, data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
