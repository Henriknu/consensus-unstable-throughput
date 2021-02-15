use std::todo;

use bls12_381::*;
use rand::{CryptoRng, RngCore};

pub struct CommitmentKey {
    g: G2Affine,
    h: Vec<G2Projective>,
    h1: Vec<Vec<G2Projective>>,
}
pub struct VectorCommitment {
    commitment: G2Projective,
    messages: Vec<Scalar>,
}

impl CommitmentKey {
    pub fn generate_keys(num_commiters: usize) -> CommitmentKey {
        let mut rng = rand::thread_rng();

        let g = G2Affine::generator();

        let secrets: Vec<Scalar> = (0..num_commiters)
            .map(|_| random_scalar(&mut rng))
            .collect();

        let h: Vec<G2Projective> = secrets.iter().map(|secret| g * secret).collect();

        let h1: Vec<Vec<G2Projective>> = secrets
            .iter()
            .enumerate()
            .map(|(secret_index, secret)| {
                let mut publics: Vec<G2Projective> = Vec::with_capacity(num_commiters);
                for (public_index, public) in h.iter().enumerate() {
                    if secret_index != public_index {
                        publics.push(public * secret);
                    }
                }
                publics
            })
            .collect();

        CommitmentKey { g, h, h1 }
    }

    pub fn commit(&self, messages: &[Scalar]) -> VectorCommitment {
        let commitment = self
            .h
            .iter()
            .zip(messages)
            .fold(G2Projective::identity(), |acc, (public, message)| {
                acc + (public * message)
            });

        VectorCommitment {
            commitment,
            messages: messages.to_vec(),
        }
    }

    pub fn open(
        &self,
        message: &Scalar,
        index: usize,
        commitment: &VectorCommitment,
    ) -> VectorCommitmentProof {
        let proof = self.h1[index].iter().zip(&commitment.messages).fold(
            G2Projective::identity(),
            |acc, (public, other_message)| {
                if message != other_message {
                    acc + public * other_message
                } else {
                    G2Projective::identity()
                }
            },
        );
        VectorCommitmentProof(proof)
    }

    pub fn verify(
        &self,
        commitment: &VectorCommitment,
        message: &Scalar,
        index: usize,
        proof: &VectorCommitmentProof,
    ) -> bool {
        let e1 = pairing(
            commitment.commitment - self.h[index] * message,
            self.h[index],
        );
        let e2 = pairing(proof.0, self.g);

        e1 == e2
    }

    pub fn update(
        commitment: VectorCommitment,
        message: &[u8],
        new_message: &[u8],
        index: usize,
    ) -> VectorCommitment {
        todo!()
    }

    pub fn proof_update(
        commitment: VectorCommitment,
        proof: &VectorCommitmentProof,
        new_message: &[u8],
        index: usize,
        update_info: UpdateInfo,
    ) -> VectorCommitmentProof {
        todo!()
    }
}

fn random_scalar(rng: &mut (impl CryptoRng + RngCore)) -> Scalar {
    let mut buf = [0; 64];
    rng.fill_bytes(&mut buf);
    Scalar::from_bytes_wide(&buf)
}

pub struct VectorCommitmentProof(G2Projective);

pub struct AuxInfo;

pub struct UpdateInfo;
