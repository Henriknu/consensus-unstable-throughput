#![allow(non_snake_case)]
use std::collections::BTreeMap;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::prelude::ThreadRng;
use serde::{Deserialize, Serialize};

use super::{hash::dalek::hash1, SignatureIdentifier};

use super::hash::hash_sha256;

const N_MATERIAL: usize = 5;

pub struct Signer {
    index: usize,
    public: Box<RistrettoBasepointTable>,
    lagrange_constants: Vec<Scalar>,
    pre_signed: Vec<Vec<PreSignMaterial>>,
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

        let lagrange_constants = Self::calculate_lagrange_constants(threshold);

        let public = Box::new(publics.remove(0));

        let x = x_set.remove(0);

        // Precompute pre-sign material
        let pre_signed = Self::pre_sign_material(x, n_parties, threshold);

        // Map to signer instances

        (0..n_parties)
            .map(|index| Signer {
                index,
                public: public.clone(),
                lagrange_constants: lagrange_constants.clone(),
                pre_signed: pre_signed[index].clone(),
                threshold,
            })
            .collect()
    }

    /// Pre-compute `l` set of pre sign material, for `n_parties` parties.
    ///
    /// NB: THIS IS ONLY A SIMULATION OF ACTUALLY RUNNING THE PRE-SIGN PROTOCOL. THIS IS NOT SECURE.
    /// Currently, this generates N * 6 presign material. It should really be N + K * (4N + 1), where K is maximum of expected rounds of MVBA protocol.
    /// Presign material cannot be reused, and such need to be discarded after use
    fn pre_sign_material(
        x: Scalar,
        n_parties: usize,
        threshold: usize,
    ) -> Vec<Vec<Vec<PreSignMaterial>>> {
        let mut rng = rand::thread_rng();

        let mut result = vec![vec![Vec::with_capacity(N_MATERIAL); n_parties + 1]; n_parties];

        for i in 0..n_parties {
            for j in 0..N_MATERIAL {
                let (k_set, sigma_set, R) =
                    Self::_generate_pre_sign(x, n_parties, threshold, &mut rng);
                for index in 0..n_parties {
                    result[index][i].push(PreSignMaterial {
                        id: j,
                        index: i,
                        k: k_set[index],
                        sigma: sigma_set[index],
                        R: R.clone(),
                    });
                }
            }
        }

        // Generate for MVBADone
        let (k_set, sigma_set, R) = Self::_generate_pre_sign(x, n_parties, threshold, &mut rng);

        for i in 0..n_parties {
            result[i][n_parties].push(PreSignMaterial {
                id: 0,
                index: n_parties,
                k: k_set[i],
                sigma: sigma_set[i],
                R: R.clone(),
            });
        }

        result
    }

    fn _generate_pre_sign(
        x: Scalar,
        n_parties: usize,
        threshold: usize,
        rng: &mut ThreadRng,
    ) -> (Vec<Scalar>, Vec<Scalar>, RistrettoPoint) {
        // generate shares of k

        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(rng)).collect();

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

        let mut coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(rng)).collect();

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

        let R = &constants::RISTRETTO_BASEPOINT_TABLE * &(k.invert());

        (k_set, sigma_set, R)
    }

    pub fn sign(&self, data: &[u8], identifier: &SignatureIdentifier) -> SignatureShare {
        let SignatureIdentifier { id, index } = identifier;
        let PreSignMaterial {
            id: _id,
            k,
            sigma,
            R,
            ..
        } = &self.pre_signed[*index][*id];

        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let r = Scalar::from_bytes_mod_order(hash1(*R));

        SignatureShare {
            id: *id,
            signer_index: self.index,
            inner: m * k + r * sigma,
        }
    }

    /// Produce signature share on data. Reuses pre-sign material, only for benchmark purposes.
    pub fn sign_reuse_pre_signed(&self, data: &[u8]) -> SignatureShare {
        let PreSignMaterial {
            id, k, sigma, R, ..
        } = &self.pre_signed[0][0];

        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let r = Scalar::from_bytes_mod_order(hash1(*R));

        SignatureShare {
            id: *id,
            signer_index: self.index,
            inner: m * k + r * sigma,
        }
    }

    pub fn combine_signatures(
        &self,
        shares: &BTreeMap<usize, SignatureShare>,
        identifier: &SignatureIdentifier,
    ) -> Signature {
        let SignatureIdentifier { id, index } = identifier;

        let lagrange_constants = Self::calculate_lagrange_constants_of_shares(&shares);

        let s = shares
            .iter()
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, ((_, share), constant)| {
                acc + (share.inner * constant)
            });

        let r = Scalar::from_bytes_mod_order(hash1(self.pre_signed[*index][*id].R));

        Signature { id: *id, s, r }
    }

    pub fn verify_signature(&self, sig: &Signature, data: &[u8]) -> bool {
        let m = Scalar::from_bytes_mod_order(hash_sha256(data));
        let w = sig.s.invert();

        let r1 = &constants::RISTRETTO_BASEPOINT_TABLE * &(m * w) + &*self.public * &(sig.r * w);

        sig.r == Scalar::from_bytes_mod_order(hash1(r1))
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return `n_parties` lagrange constants, evaluated for polynomial of degree `threshold`
    fn calculate_lagrange_constants(threshold: usize) -> Vec<Scalar> {
        let indexes = 0..threshold;
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

    /// Return `n_parties` lagrange constants, evaluated for polynomial of degree `threshold`
    fn calculate_lagrange_constants_of_shares(
        shares: &BTreeMap<usize, SignatureShare>,
    ) -> Vec<Scalar> {
        let indexes: Vec<_> = shares.values().map(|s| s.signer_index).collect();

        // Interpolate over the points, get coefficients
        shares
            .values()
            .map(|share| {
                // S = subset of Zq (Set of scalars). i = 0. j is the index of the share.

                let mut numerator = Scalar::one();
                let mut denumerator = Scalar::one();

                for index in &indexes {
                    if index != &share.signer_index {
                        numerator *= Scalar::zero()
                            - Scalar::one() * Scalar::from(*index as u64)
                            - Scalar::one();
                        denumerator *= Scalar::one() * Scalar::from(share.signer_index as u64)
                            - Scalar::one() * Scalar::from(*index as u64);
                    }
                }

                numerator * denumerator.invert()
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncodedSigner {
    index: usize,
    public: [u8; 32],
    lagrange_constants: Vec<[u8; 32]>,
    pre_signed: Vec<Vec<PreSignMaterial>>,
    threshold: usize,
}

impl From<Signer> for EncodedSigner {
    fn from(signer: Signer) -> Self {
        let Signer {
            public,
            lagrange_constants,
            pre_signed,
            threshold,
            index,
        } = signer;

        let public = public.basepoint().compress().to_bytes();

        let lagrange_constants = lagrange_constants
            .into_iter()
            .map(|s| s.to_bytes())
            .collect();

        EncodedSigner {
            public,
            lagrange_constants,
            pre_signed,
            threshold,
            index,
        }
    }
}

impl From<EncodedSigner> for Signer {
    fn from(encoded: EncodedSigner) -> Self {
        let EncodedSigner {
            public,
            lagrange_constants,
            pre_signed,
            threshold,
            index,
        } = encoded;

        let public = Box::new(RistrettoBasepointTable::create(
            &CompressedRistretto::decompress(&CompressedRistretto::from_slice(&public))
                .expect("Could not decode encoded point as ristretto point"),
        ));

        let lagrange_constants = lagrange_constants
            .into_iter()
            .map(|bytes| Scalar::from_bytes_mod_order(bytes))
            .collect();

        Signer {
            public,
            lagrange_constants,
            pre_signed,
            threshold,
            index,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PreSignMaterial {
    id: usize,
    index: usize,
    k: Scalar,
    sigma: Scalar,
    R: RistrettoPoint,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignatureShare {
    pub id: usize,
    pub signer_index: usize,
    inner: Scalar,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Signature {
    id: usize,
    r: Scalar,
    s: Scalar,
}

#[cfg(test)]
mod tests {

    use crate::crypto::SignatureIdentifier;

    use super::*;

    const N: usize = T * 4;
    const T: usize = 2;

    #[test]
    fn test_signer_n() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 0 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        dbg!(&shares);

        let signatures: Vec<_> = signers
            .iter()
            .map(|s| s.combine_signatures(&shares, &identifier))
            .collect();

        dbg!(&signatures);

        for (i, sig) in signatures.iter().enumerate() {
            assert!(signers[i].verify_signature(&sig, &data));
        }
    }

    #[test]
    fn test_signer_t() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 0 };

        dbg!(signers.len());

        let shares = signers
            .iter()
            .take(T)
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        dbg!(&shares);

        let signatures: Vec<_> = signers
            .iter()
            .map(|s| s.combine_signatures(&shares, &identifier))
            .collect();

        dbg!(&signatures);

        for (i, sig) in signatures.iter().enumerate() {
            assert!(signers[i].verify_signature(&sig, &data));
        }
    }

    #[test]
    fn test_signer_t_different_shares() {
        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 0 };

        dbg!(signers.len());

        let shares1 = signers
            .iter()
            .take(T)
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        dbg!(&shares1);

        let shares2 = signers
            .iter()
            .enumerate()
            .rev()
            .take(T)
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        dbg!(&shares2);

        let signatures1: Vec<_> = signers
            .iter()
            .map(|s| s.combine_signatures(&shares1, &identifier))
            .collect();

        let signatures2: Vec<_> = signers
            .iter()
            .map(|s| s.combine_signatures(&shares2, &identifier))
            .collect();

        dbg!(&signatures1);

        for (i, sig) in signatures1.iter().enumerate() {
            assert!(signers[i].verify_signature(&sig, &data));
        }

        dbg!(&signatures2);

        for (i, sig) in signatures2.iter().enumerate() {
            assert!(signers[i].verify_signature(&sig, &data));
        }
    }

    #[test]
    #[should_panic]
    fn test_signer_invalid_share() {
        let mut rng = rand::thread_rng();

        let data = "Hello world".as_bytes();
        let signers = Signer::generate_signers(N, T);
        let identifier = SignatureIdentifier { id: 0, index: 1 };

        dbg!(signers.len());

        let mut shares: BTreeMap<_, _> = signers
            .iter()
            .take(T)
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        shares.insert(
            0,
            SignatureShare {
                id: 1,
                signer_index: 0,
                inner: Scalar::random(&mut rng),
            },
        );

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

        let shares: BTreeMap<_, _> = signers
            .iter()
            .take(T)
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
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
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
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
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
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
            .enumerate()
            .map(|(i, signer)| (i, signer.sign(data, &identifier)))
            .collect();

        let sig = signers[0].combine_signatures(&shares, &identifier);

        assert!(signers[0].verify_signature(&sig, &data));

        let data = "Another thing to sign...".as_bytes();

        let _ = signers[0].sign(data, &identifier);
    }

    #[test]
    fn test_lagrange() {
        let mut rng = rand::thread_rng();

        let lagrange_constants = Signer::calculate_lagrange_constants(T);

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

        let k_set = k_set.iter().take(T).clone();

        let lagrange_constants = lagrange_constants.iter().take(T).clone();

        let k1 = k_set
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, (share, coeff)| acc + (share * coeff));

        assert_eq!(k, k1);
    }

    //#[test]
    fn _test_lagrange_reversed() {
        let mut rng = rand::thread_rng();

        let lagrange_constants = Signer::calculate_lagrange_constants(T);

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

        let k_set = k_set.iter().rev().take(T).clone();

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

        let lagrange_constants = Signer::calculate_lagrange_constants(T);

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

        let lagrange_constants = Signer::calculate_lagrange_constants(T);
        let lagrange_constants = lagrange_constants.iter().take(T).clone();

        let sigma1 = sigma_set
            .zip(lagrange_constants)
            .fold(Scalar::zero(), |acc, (share, coeff)| acc + (share * coeff));

        assert_eq!(sigma1, k * x);
    }
}
