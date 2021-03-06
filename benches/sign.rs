use criterion::{criterion_group, criterion_main, Criterion};

use consensus_core::crypto::sign_ecdsa::Signer as ECDSA;
use consensus_core::crypto::{sign_pairing::Signer, SignatureIdentifier};

const N: usize = T * 4;
const T: usize = 25;

fn criterion_benchmark(c: &mut Criterion) {
    let signers_vec_pairing = Signer::generate_signers(N, T);
    let signer_pairing = &signers_vec_pairing[0];
    let signers_vec_ecdsa = ECDSA::generate_signers(N, T);
    let signer_ecdsa = &signers_vec_ecdsa[0];
    let identifier = SignatureIdentifier::new(0, 0);

    let data = "Hello world!".as_bytes();

    c.bench_function("threshold_crypto Sign Share", |b| {
        b.iter(|| signer_pairing.sign(data, &identifier))
    });
    c.bench_function("ECDSA Sign Share", |b| {
        b.iter(|| signer_ecdsa.sign_reuse_pre_signed(data))
    });

    let shares_pairing = signers_vec_pairing
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.sign(data, &identifier)))
        .collect();
    let shares_ecdsa = signers_vec_ecdsa
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.sign(data, &identifier)))
        .collect();

    c.bench_function("threshold_crypto Combine Shares, N = 100, T = 25", |b| {
        b.iter(|| signer_pairing.combine_signatures(&shares_pairing, &identifier))
    });

    c.bench_function("ECDSA Combine Shares, N = 100, T = 25", |b| {
        b.iter(|| signer_ecdsa.combine_signatures(&shares_ecdsa, &identifier))
    });

    let signature_pairing = signer_pairing.combine_signatures(&shares_pairing, &identifier);
    let signature_ecdsa = signer_ecdsa.combine_signatures(&shares_ecdsa, &identifier);

    c.bench_function("threshold_crypto Verify Signature, N = 100, T = 25", |b| {
        b.iter(|| signer_pairing.verify_signature(&signature_pairing, data))
    });

    c.bench_function("ECDSA Verify Signature, N = 100, T = 25", |b| {
        b.iter(|| signer_ecdsa.verify_signature(&signature_ecdsa, data))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
