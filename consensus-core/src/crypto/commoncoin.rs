use super::hash::commoncoin::{hash_1, hash_2, hash_3};
use p256::{
    elliptic_curve::{group::ScalarMul, sec1::FromEncodedPoint},
    AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
};
use serde::{Deserialize, Serialize};
// TODO: Look into if OsRng can be switched out for ThreadRNG or other PRNGS. Problem with rand vs rand_core trait contracts in p256...
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::OsRng;
use std::{collections::HashSet, ops::Deref, str};

pub struct KeySet {
    public: PublicK,
    verify: VerifyK,
    secrets: Vec<SecretK>,
}

#[derive(Clone, Copy)]
struct PublicK {
    g: AffinePoint,
}
#[derive(Clone)]
struct VerifyK {
    elements: Vec<AffinePoint>,
}
#[derive(Clone, Copy)]
struct SecretK {
    secret_scalar: Scalar,
}

pub struct Coin {
    pub index: usize,
    public: PublicK,
    verify: VerifyK,
    secret: SecretK,
}

impl Coin {
    pub fn generate_coins(n_parties: usize, threshold: usize) -> Vec<Coin> {
        // Should generate the keyset, to be used in a trusted setup environment.

        assert!(threshold > 0);
        assert!(n_parties >= threshold);

        let g = AffinePoint::generator();

        let coefficients: Vec<NonZeroScalar> = (0..threshold)
            .map(|_| NonZeroScalar::random(&mut OsRng))
            .collect();

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

        let publics: Vec<AffinePoint> = secrets
            .iter()
            .skip(1)
            .map(|secret| (ProjectivePoint::generator() * secret).to_affine())
            .collect();

        let public = PublicK { g };

        let verify = VerifyK { elements: publics };

        let secrets: Vec<_> = secrets
            .into_iter()
            .skip(1)
            .map(|secret_scalar| SecretK { secret_scalar })
            .collect();

        (0..n_parties)
            .map(|index| Coin {
                index,
                public,
                verify: verify.clone(),
                secret: secrets[index],
            })
            .collect()
    }
    pub fn generate_share(&self, data: &[u8]) -> CoinShare {
        let g1 = hash_1(data);
        let gg1 = (ProjectivePoint::from(g1) * self.secret.secret_scalar).to_affine();
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

        let h = (ProjectivePoint::from(self.public.g) * z)
            - (ProjectivePoint::from(self.verify.elements[*index]) * c);
        let h1 = (ProjectivePoint::from(g1) * z) - (ProjectivePoint::from(*gg1) * c);

        c == &hash_2(
            self.public.g,
            self.verify.elements[*index],
            h.to_affine(),
            g1,
            *gg1,
            h1.to_affine(),
        )
    }

    pub fn combine_shares(&self, shares: &Vec<CoinShare>, range: usize) -> usize {
        let coefficients = self.calculate_lagrange_coefficients(&shares);

        let result = shares
            .iter()
            .zip(coefficients)
            .fold(ProjectivePoint::identity(), |acc, (share, coeff)| {
                acc + (ProjectivePoint::from(share.gg1) * coeff)
            });

        let hash = hash_3(result.to_affine());

        // provide hash into prng, generate number < n_parties.

        StdRng::from_seed(hash).gen_range(0, range)
    }

    fn generate_proof(&self, g1: &AffinePoint, gg1: &AffinePoint) -> ValidationProof {
        let s = NonZeroScalar::random(&mut OsRng);

        let h = self.public.g * s;
        let h1 = *g1 * s;

        let c = hash_2(
            self.public.g,
            self.verify.elements[self.index],
            h,
            *g1,
            *gg1,
            h1,
        );
        let z = *s + &(c * self.secret.secret_scalar);

        ValidationProof { c, z }
    }

    fn calculate_lagrange_coefficients(&self, shares: &Vec<CoinShare>) -> Vec<Scalar> {
        let index_set: HashSet<_> = shares.iter().map(|share| share.index).collect();

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

                assert_ne!(
                    denumerator,
                    Scalar::zero(),
                    "Expect denumerator to not be zero"
                );
                // TODO: Ensure Denumerator is always  invertible, e.g. not zero.
                numerator * denumerator.invert().unwrap()
            })
            .collect()
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct CoinShare {
    pub index: usize,
    gg1: AffinePoint,
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
    gg1: Vec<u8>,
    c: Vec<u8>,
    z: Vec<u8>,
}

impl From<CoinShare> for EncodedCoinShare {
    fn from(share: CoinShare) -> Self {
        let CoinShare { index, gg1, proof } = share;

        let gg1 = EncodedPoint::from(gg1).as_bytes().to_vec();

        let c = proof.c.to_bytes().as_slice().to_vec();

        let z = proof.z.to_bytes().as_slice().to_vec();

        Self { index, gg1, c, z }
    }
}

impl From<EncodedCoinShare> for CoinShare {
    fn from(share: EncodedCoinShare) -> Self {
        let EncodedCoinShare { index, gg1, c, z } = share;

        let gg1 = AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(gg1)
                .expect("Could not deserialize Sec1 encoded string to encoded point"),
        )
        .expect("Could not decode encoded point as affine point");

        let c = Scalar::from_bytes_reduced(FieldBytes::from_slice(&c));

        let z = Scalar::from_bytes_reduced(FieldBytes::from_slice(&z));

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

        let results: Vec<usize> = actors
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
