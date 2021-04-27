#![allow(non_snake_case)]
use std::sync::atomic::{AtomicUsize, Ordering};

use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{constants, traits::Identity};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use super::hash::dalek::hash1;

use super::hash::hash_sha256;

const N_MATERIAL: usize = 6;

pub struct Signer {
    index: usize,
    public: RistrettoBasepointTable,
    publics: Vec<RistrettoBasepointTable>,
    secret: Scalar,
    lagrange_constants: Vec<Scalar>,
    pre_signed: Vec<Vec<PreSignMaterial>>,
    counter: AtomicUsize,
    threshold: usize,
}

impl Signer {
    pub fn generate_signers(n_parties: usize, threshold: usize) -> Vec<Signer> {
        let mut rng = rand::thread_rng();

        // Calculate secret key shares x_i

        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

        let mut x_set: Vec<Scalar> = (0..n_parties + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let mut publics: Vec<RistrettoBasepointTable> = x_set
            .iter()
            .map(|x| RistrettoBasepointTable::create(&(&constants::RISTRETTO_BASEPOINT_TABLE * x)))
            .collect();

        // Calculate lagrange coefficients for i = 0, ..., N, j = t + 1

        let lagrange_constants = Self::calculate_lagrange_constants(n_parties, threshold);

        let public = publics.remove(0);

        let x = x_set.remove(0);

        // Precompute pre-sign material
        let pre_signed = Self::pre_sign_material(x, n_parties, threshold);

        // Map to signer instances

        (0..n_parties)
            .map(|index| Signer {
                index,
                public: public.clone(),
                publics: publics.clone(),
                secret: x_set[index],
                lagrange_constants: lagrange_constants.clone(),
                pre_signed: pre_signed[index].clone(),
                threshold,
                counter: AtomicUsize::new(0),
            })
            .collect()
    }

    /// Pre-compute `l` set of pre sign material, for `n_parties` parties.
    ///
    /// For ABFT, we generate pre-sign material in order to handle the maximal amount of signatures needed for a single round of the consensus algorithm.
    /// Per party n, this is 1 for PRBC, 5 for MVBA * number of views. Given honest parties, this will never be more than 6.
    /// For dishonest parties, one would generate according to the expected number of rounds needed for MVBA (2/3 chance pr round to elect honest leader, expected number of rounds < 3/2.)
    fn pre_sign_material(
        x: Scalar,
        n_parties: usize,
        threshold: usize,
    ) -> Vec<Vec<Vec<PreSignMaterial>>> {
        let mut rng = rand::thread_rng();

        let mut result = vec![vec![Vec::with_capacity(N_MATERIAL); n_parties]; n_parties];

        for i in 0..n_parties {
            for j in 0..N_MATERIAL {
                // generate shares of k

                let coefficients: Vec<Scalar> =
                    (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

                let mut k_set: Vec<Scalar> = (0..n_parties + 1)
                    .map(|i| {
                        let mut sum = Scalar::zero();
                        let mut factor = Scalar::one();
                        let index = Scalar::from(i as u64);

                        for coeff in &coefficients {
                            sum = sum + (coeff * &factor);
                            factor = factor * index;
                        }
                        sum
                    })
                    .collect();

                let k = k_set.remove(0);

                // generate shares of w = k * x

                let mut coefficients: Vec<Scalar> =
                    (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

                coefficients[0] = k * x;

                let mut sigma_set: Vec<Scalar> = (0..n_parties + 1)
                    .map(|i| {
                        let mut sum = Scalar::zero();
                        let mut factor = Scalar::one();
                        let index = Scalar::from(i as u64);

                        for coeff in &coefficients {
                            sum = sum + (coeff * &factor);
                            factor = factor * index;
                        }
                        sum
                    })
                    .collect();

                let _ = sigma_set.remove(0);

                // compute nonce R

                let r = &constants::RISTRETTO_BASEPOINT_TABLE * &(k.invert());

                for index in 0..n_parties {
                    result[index][i].push(PreSignMaterial {
                        id: i,
                        k: k_set[index],
                        sigma: sigma_set[index],
                        R: r.clone(),
                    });
                }
            }
        }

        result
    }

    pub fn sign(&self, data: &[u8], identifier: &SignatureIdentifier) -> SignatureShare {
        let SignatureIdentifier { id, index } = identifier;
        let PreSignMaterial { id, k, sigma, R } = &self.pre_signed[*index][*id];

        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let r = Scalar::from_bytes_mod_order(hash1(*R));

        SignatureShare {
            id: *id,
            inner: m * k + r * sigma,
        }
    }

    /// Produce signature share on data. Reuses pre-sign material, only for benchmark purposes.
    pub fn sign_reuse_pre_signed(&self, data: &[u8]) -> SignatureShare {
        let PreSignMaterial { id, k, sigma, R } = &self.pre_signed[0][0];

        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let r = Scalar::from_bytes_mod_order(hash1(*R));

        SignatureShare {
            id: *id,
            inner: m * k + r * sigma,
        }
    }

    pub fn combine_signatures(
        &self,
        shares: &Vec<SignatureShare>,
        identifier: &SignatureIdentifier,
    ) -> Signature {
        let SignatureIdentifier { id, index } = identifier;

        let s = shares
            .iter()
            .take(self.threshold)
            .zip(self.lagrange_constants.iter().take(self.threshold))
            .fold(Scalar::zero(), |acc, (share, coeff)| {
                acc + (share.inner * coeff)
            });

        let r = Scalar::from_bytes_mod_order(hash1(self.pre_signed[*index][*id].R));

        Signature {
            id: shares[0].id,
            s,
            r,
        }
    }

    pub fn verify_signature(&self, sig: &Signature, data: &[u8]) -> bool {
        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let w = sig.s.invert();

        let r1 = &constants::RISTRETTO_BASEPOINT_TABLE * &(m * w) + &self.public * &(sig.r * w);

        sig.r == Scalar::from_bytes_mod_order(hash1(r1))
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return `n_parties` lagrange constants, evaluated for polynomial of degree `threshold`
    fn calculate_lagrange_constants(n_parties: usize, threshold: usize) -> Vec<Scalar> {
        let indexes = 0..n_parties;
        let points: Vec<_> = (0..threshold).collect();

        // Interpolate over the points, get coefficients
        indexes
            .map(|i| {
                // S = subset of Zq (Set of scalars). i = 0. j is the index of the share.

                let numerator = points.iter().fold(Scalar::one(), |acc, j| {
                    acc * match j {
                        j if i == *j => Scalar::one(),
                        _ => {
                            Scalar::zero() - Scalar::one() * Scalar::from(*j as u64) - Scalar::one()
                        }
                    }
                });

                let denumerator = points.iter().fold(Scalar::one(), |acc, j| {
                    acc * match j {
                        j if i == *j => Scalar::one(),
                        _ => {
                            Scalar::one() * Scalar::from(i as u64)
                                - Scalar::one() * Scalar::from(*j as u64)
                        }
                    }
                });

                numerator * denumerator.invert()
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PreSignMaterial {
    id: usize,
    k: Scalar,
    sigma: Scalar,
    R: RistrettoPoint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureShare {
    id: usize,
    inner: Scalar,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature {
    id: usize,
    r: Scalar,
    s: Scalar,
}

pub struct SignatureIdentifier {
    id: usize,
    index: usize,
}

impl SignatureIdentifier {
    pub fn new(id: usize, index: usize) -> Self {
        Self { id, index }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const N: usize = T * 4;
    const T: usize = 1;

    #[test]
    fn test_signer_n() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        assert!(signers[0].verify_signature(&sig, &data));
    }

    #[test]
    fn test_signer_t() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .take(T)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        assert!(signers[0].verify_signature(&sig, &data));
    }

    #[test]
    #[should_panic]
    fn test_signer_invalid_share() {
        let mut rng = rand::thread_rng();

        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let mut shares: Vec<_> = signers
            .iter()
            .take(T)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        shares[0] = SignatureShare {
            id: 1,
            inner: Scalar::random(&mut rng),
        };

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        assert!(signers[0].verify_signature(&sig, &data));
    }
    #[test]
    #[should_panic]
    fn test_signer_invalid_data() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let shares: Vec<_> = signers
            .iter()
            .take(T)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        let data = "Some other data".as_bytes();

        assert!(signers[0].verify_signature(&sig, &data));
    }

    #[test]
    fn test_signer_n8_t2() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(8, 2);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .take(2)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        assert!(signers[0].verify_signature(&sig, &data));
    }

    #[test]
    #[should_panic]
    fn test_signer_n8_t2_single_share() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(8, 2);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .take(1)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        dbg!(&shares);

        let sig = signers[0].combine_signatures(&shares, &identifier);

        dbg!(&sig);

        assert!(signers[0].verify_signature(&sig, &data));
    }

    #[test]
    #[should_panic]
    fn test_signer_too_few_pre_signed() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(8, 2);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        let shares = signers
            .iter()
            .take(1)
            .map(|signer| signer.sign(data, &identifier))
            .collect();

        let sig = signers[0].combine_signatures(&shares, &identifier);

        assert!(signers[0].verify_signature(&sig, &data));

        let data = "Another thing to sign...".as_bytes();

        let _ = signers[0].sign(data, &identifier);
    }

    #[test]
    fn test_lagrange() {
        let mut rng = rand::thread_rng();

        let lagrange_constants = Signer::calculate_lagrange_constants(N, T);

        let coefficients: Vec<Scalar> = (0..T).map(|_| Scalar::random(&mut rng)).collect();

        let mut k_set: Vec<Scalar> = (0..N + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let k = k_set.remove(0);

        // check that it sums up to k

        assert_eq!(k_set.len(), N);
        assert_eq!(lagrange_constants.len(), N);

        let k_set = k_set.iter().take(T).clone();

        let lagrange_constants = lagrange_constants.iter().take(T).clone();

        let k1 = k_set
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, (share, coeff)| acc + (share * coeff));

        assert_eq!(k, k1);
    }

    #[test]
    fn test_lagrange_multiplicative() {
        let mut rng = rand::thread_rng();

        let x = Scalar::random(&mut rng);

        let lagrange_constants = Signer::calculate_lagrange_constants(N, T);

        let coefficients: Vec<Scalar> = (0..T).map(|_| Scalar::random(&mut rng)).collect();

        let mut k_set: Vec<Scalar> = (0..N + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let k = k_set.remove(0);

        // check that it sums up to k

        assert_eq!(k_set.len(), N);
        assert_eq!(lagrange_constants.len(), N);

        let k_set = k_set.iter().take(T).clone();

        let lagrange_constants = lagrange_constants.iter().take(T).clone();

        let k1 = k_set
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, (share, coeff)| acc + (share * coeff));

        assert_eq!(k, k1);

        // sigma

        // generate shares of w = k * x

        let mut coefficients: Vec<Scalar> = (0..T).map(|_| Scalar::random(&mut rng)).collect();

        coefficients[0] = k * x;

        let mut sigma_set: Vec<Scalar> = (0..N + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let _ = sigma_set.remove(0);

        let sigma_set = sigma_set.iter().take(T).clone();

        let lagrange_constants = Signer::calculate_lagrange_constants(N, T);
        let lagrange_constants = lagrange_constants.iter().take(T).clone();

        let sigma1 = sigma_set
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, (share, coeff)| acc + (share * coeff));

        assert_eq!(sigma1, k * x);
    }
}
