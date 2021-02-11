use super::hash::commoncoin::{hash_1, hash_2, hash_3};
use p256::{elliptic_curve::group::ScalarMul, AffinePoint, NonZeroScalar, ProjectivePoint, Scalar};
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
pub struct Dealer {}

impl Dealer {
    pub fn generate_keys(n_actors: usize, threshold: usize) -> KeySet {
        // Should generate the keyset, to be used in a trusted setup environment.

        assert!(threshold > 0);
        assert!(n_actors >= threshold);

        let g = AffinePoint::generator();

        let coefficients: Vec<NonZeroScalar> = (0..threshold)
            .map(|_| NonZeroScalar::random(&mut OsRng))
            .collect();

        let secrets: Vec<Scalar> = (0..n_actors + 1)
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
            .map(|secret| (ProjectivePoint::generator() * secret).to_affine())
            .collect();

        let public = PublicK { g };

        let verify = VerifyK { elements: publics };

        let secrets: Vec<_> = secrets
            .into_iter()
            .skip(1)
            .map(|secret_scalar| SecretK { secret_scalar })
            .collect();

        KeySet {
            public,
            verify,
            secrets,
        }
    }
}

pub struct Actor {
    index: usize,
    public: PublicK,
    verify: VerifyK,
    secret: SecretK,
}

impl Actor {
    pub fn generate_share(&self, coin: &[u8]) -> CoinShare {
        let g1 = hash_1(coin);
        let gg1 = (ProjectivePoint::from(g1) * self.secret.secret_scalar).to_affine();
        let proof = self.generate_proof(&g1, &gg1);

        CoinShare {
            index: self.index,
            gg1,
            proof,
        }
    }

    pub fn verify_share(&self, coin: &[u8], share: &CoinShare) -> bool {
        let g1 = hash_1(coin);

        let CoinShare {
            index,
            gg1,
            proof: ValidationProof { c, z },
        } = share;

        let h = (ProjectivePoint::from(self.public.g) * z)
            - ProjectivePoint::from(self.verify.elements[*index]) * c;
        let h1 = (ProjectivePoint::from(g1) * z) - ProjectivePoint::from(*gg1) * c;

        c == &hash_2(
            self.public.g,
            self.verify.elements[self.index],
            h.to_affine(),
            g1,
            *gg1,
            h1.to_affine(),
        )
    }

    pub fn combine_shares(&self, shares: &Vec<CoinShare>) -> bool {
        let coefficients = self.calculate_lagrange_coefficients(&shares);

        let result = shares
            .iter()
            .zip(coefficients)
            .fold(ProjectivePoint::identity(), |acc, (share, coeff)| {
                acc + (ProjectivePoint::from(share.gg1) * coeff)
            });

        hash_3(result.to_affine())
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

pub struct CoinShare {
    index: usize,
    gg1: AffinePoint,
    proof: ValidationProof,
}

struct ValidationProof {
    c: Scalar,
    z: Scalar,
}

#[cfg(test)]
mod test_commoncoin {
    use super::*;

    #[test]
    fn test_single_actor_threshold_1() {
        let keyset = Dealer::generate_keys(1, 1);

        let actors: Vec<Actor> = (0..1)
            .into_iter()
            .map(|index| Actor {
                index,
                public: keyset.public,
                verify: keyset.verify.clone(),
                secret: keyset.secrets[index],
            })
            .collect();

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
                    assert!(actor.verify_share(&data, &share))
                }
            }
        }

        let results: Vec<bool> = actors
            .iter()
            .map(|actor| actor.combine_shares(&shares))
            .collect();

        let result = &results[0];

        for other in &results {
            assert_eq!(result, other);
        }
    }
}
