use super::hash::commoncoin_dalek::{hash_1, hash_2, hash_3};
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{constants, traits::Identity};
use serde::{Deserialize, Serialize};
// TODO: Look into if OsRng can be switched out for ThreadRNG or other PRNGS. Problem with rand vs rand_core trait contracts in p256...
use rand::thread_rng;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{ops::Deref, str};

#[derive(Clone)]
struct VerifyK {
    elements: Vec<RistrettoBasepointTable>,
}
#[derive(Clone, Copy)]
struct SecretK {
    secret_scalar: Scalar,
}

pub struct Coin {
    pub index: usize,
    verify: VerifyK,
    secret: SecretK,
}

impl Coin {
    pub fn generate_coins(n_parties: usize, threshold: usize) -> Vec<Coin> {
        // Should generate the keyset, to be used in a trusted setup environment.

        assert!(threshold > 0);
        assert!(n_parties >= threshold);

        let mut rng = thread_rng();

        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

        let secrets: Vec<Scalar> = (0..n_parties + 1)
            .map(|i| {
                let mut sum = Scalar::zero();
                let mut factor = Scalar::one();
                let index = Scalar::from(i as u64);

                for coeff in &coefficients {
                    sum = sum + (coeff.deref() * &factor);
                    factor = factor * index;
                }
                sum
            })
            .collect();

        let publics: Vec<RistrettoBasepointTable> = secrets
            .iter()
            .skip(1)
            .map(|secret| {
                RistrettoBasepointTable::create(&(&constants::RISTRETTO_BASEPOINT_TABLE * &secret))
            })
            .collect();

        let verify = VerifyK { elements: publics };

        let secrets: Vec<_> = secrets
            .into_iter()
            .skip(1)
            .map(|secret_scalar| SecretK { secret_scalar })
            .collect();

        (0..n_parties)
            .map(|index| Coin {
                index,
                verify: verify.clone(),
                secret: secrets[index],
            })
            .collect()
    }

    pub fn generate_share(&self, data: &[u8]) -> CoinShare {
        let g1 = hash_1(data);
        let gg1 = g1 * self.secret.secret_scalar;
        let proof = self.generate_proof(&g1, &gg1);

        CoinShare {
            index: self.index,
            gg1,
            proof,
        }
    }

    pub fn verify_share(&self, data: &[u8], share: &CoinShare) -> bool {
        let g1 = hash_1(data);

        let CoinShare {
            index,
            gg1,
            proof: ValidationProof { c, z },
        } = share;

        let h = &constants::RISTRETTO_BASEPOINT_TABLE * z - &self.verify.elements[*index] * c;
        let h1 = g1 * z - *gg1 * c;

        c == &hash_2(
            constants::RISTRETTO_BASEPOINT_POINT,
            self.verify.elements[*index].basepoint(),
            h,
            g1,
            *gg1,
            h1,
        )
    }

    pub fn combine_shares(&self, shares: &Vec<CoinShare>, range: u32) -> u32 {
        let coefficients = self.calculate_lagrange_coefficients(&shares);

        let result = shares
            .iter()
            .zip(coefficients)
            .fold(RistrettoPoint::identity(), |acc, (share, coeff)| {
                acc + share.gg1 * coeff
            });

        let hash = hash_3(result);

        // provide hash into prng, generate number < n_parties.

        StdRng::from_seed(hash).gen_range(0, range)
    }

    fn generate_proof(&self, g1: &RistrettoPoint, gg1: &RistrettoPoint) -> ValidationProof {
        let mut rng = thread_rng();
        let s = Scalar::random(&mut rng);

        let h = &constants::RISTRETTO_BASEPOINT_TABLE * &s;
        let h1 = *g1 * s;

        let c = hash_2(
            constants::RISTRETTO_BASEPOINT_POINT,
            self.verify.elements[self.index].basepoint(),
            h,
            *g1,
            *gg1,
            h1,
        );
        let z = s + &(c * self.secret.secret_scalar);

        ValidationProof { c, z }
    }

    fn calculate_lagrange_coefficients(&self, shares: &Vec<CoinShare>) -> Vec<Scalar> {
        let index_set: Vec<_> = shares.iter().map(|share| share.index).collect();

        // Interpolate over the points, get coefficients
        shares
            .iter()
            .map(|share| {
                // S = subset of Zq (Set of scalars). i = 0. j is the index of the share.

                let numerator = index_set.iter().fold(Scalar::one(), |acc, index| {
                    acc * match index {
                        index if index == &share.index => Scalar::one(),
                        _ => {
                            Scalar::zero()
                                - Scalar::one() * Scalar::from(*index as u64)
                                - Scalar::one()
                        }
                    }
                });

                let denumerator = index_set.iter().fold(Scalar::one(), |acc, index| {
                    acc * match index {
                        index if index == &share.index => Scalar::one(),
                        _ => {
                            Scalar::one() * Scalar::from(share.index as u64)
                                - Scalar::one() * Scalar::from(*index as u64)
                        }
                    }
                });

                numerator * denumerator.invert()
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncodedCoin {
    index: usize,
    elements: Vec<[u8; 32]>,
    secret_scalar: [u8; 32],
}

impl From<Coin> for EncodedCoin {
    fn from(coin: Coin) -> Self {
        let Coin {
            index,
            verify: VerifyK { elements },
            secret: SecretK { secret_scalar },
        } = coin;

        let elements = elements
            .into_iter()
            .map(|ele| ele.basepoint().compress().to_bytes())
            .collect();

        let secret_scalar = secret_scalar.to_bytes();

        Self {
            index,
            elements,
            secret_scalar,
        }
    }
}

impl From<EncodedCoin> for Coin {
    fn from(encoded: EncodedCoin) -> Self {
        let EncodedCoin {
            index,
            elements,
            secret_scalar,
        } = encoded;

        let elements = elements
            .into_iter()
            .map(|ele| {
                RistrettoBasepointTable::create(
                    &CompressedRistretto::decompress(&CompressedRistretto::from_slice(&ele))
                        .expect("Could not decode encoded point as ristretto point"),
                )
            })
            .collect();

        let secret_scalar = Scalar::from_bytes_mod_order(secret_scalar);

        Self {
            index,
            verify: VerifyK { elements },
            secret: SecretK { secret_scalar },
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct CoinShare {
    pub index: usize,
    gg1: RistrettoPoint,
    proof: ValidationProof,
}

#[derive(PartialEq, Debug, Clone)]
struct ValidationProof {
    c: Scalar,
    z: Scalar,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncodedCoinShare {
    pub index: usize,
    gg1: [u8; 32],
    c: [u8; 32],
    z: [u8; 32],
}

impl From<CoinShare> for EncodedCoinShare {
    fn from(share: CoinShare) -> Self {
        let CoinShare { index, gg1, proof } = share;

        let gg1 = gg1.compress().to_bytes();

        let c = proof.c.to_bytes();

        let z = proof.z.to_bytes();

        Self { index, gg1, c, z }
    }
}

impl From<EncodedCoinShare> for CoinShare {
    fn from(share: EncodedCoinShare) -> Self {
        let EncodedCoinShare { index, gg1, c, z } = share;

        let gg1 = CompressedRistretto::decompress(&CompressedRistretto::from_slice(&gg1))
            .expect("Could not decode encoded point as ristretto point");

        let c = Scalar::from_bytes_mod_order(c);
        let z = Scalar::from_bytes_mod_order(z);

        Self {
            index,
            gg1,
            proof: ValidationProof { c, z },
        }
    }
}

#[cfg(test)]
mod test_commoncoin {
    use super::*;

    const N_PARTIES_MULTIPLE: usize = 5;
    const THRESHOLD_MULTIPLE: usize = 2;

    #[test]
    fn test_single_actor_threshold_1() {
        commoncoin_scenario(1, 1)
    }

    #[test]
    fn test_multiple_actor_multiple_threshold() {
        commoncoin_scenario(N_PARTIES_MULTIPLE, THRESHOLD_MULTIPLE)
    }

    #[test]
    fn test_multiple_actor_threshold_equals_num_actors() {
        commoncoin_scenario(N_PARTIES_MULTIPLE, N_PARTIES_MULTIPLE)
    }

    fn commoncoin_scenario(n_parties: usize, threshold: usize) {
        let actors = Coin::generate_coins(n_parties, threshold);

        let coin_name = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(coin_name.as_bytes());

        let shares: Vec<_> = actors
            .iter()
            .map(|actor| actor.generate_share(&data))
            .collect();

        for share in &shares {
            for actor in &actors {
                if share.index != actor.index {
                    assert!(
                        actor.verify_share(&data, &share),
                        "Actor {} could not verify share from actor {}",
                        actor.index,
                        share.index
                    )
                }
            }
        }

        let results: Vec<u32> = actors
            .iter()
            .map(|actor| actor.combine_shares(&shares, 11))
            .collect();

        let result = &results[0];

        for other in &results {
            assert_eq!(result, other);
        }
    }

    #[test]
    fn test_encoding() {
        let actors = Coin::generate_coins(3, 1);

        let coin_name = "Hello world! Hello world! Hello!";

        let mut data = [0u8; 32];

        data.copy_from_slice(coin_name.as_bytes());

        let share = actors[0].generate_share(&data);

        // encode

        let encoded_share: EncodedCoinShare = share.clone().into();

        let decoded_share: CoinShare = encoded_share.into();

        assert_eq!(share, decoded_share);
    }
}
