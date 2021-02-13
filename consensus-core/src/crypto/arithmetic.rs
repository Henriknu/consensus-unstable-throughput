use std::convert::TryInto;

use p256::{
    elliptic_curve::{ff::PrimeField, subtle::ConstantTimeEq, Field},
    FieldBytes, Scalar,
};

use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable};
/*
pub(crate) fn sqrt(scalar: Scalar) -> Option<Scalar> {
    let zero = Scalar::zero();

    if scalar.ct_eq(&zero).unwrap_u8() == 1u8 {
        return Some(zero);
    }

    if is_sqrt(scalar).unwrap_u8() == 0u8 {
        return None;
    }

    let (one, two, seven) = (Scalar::one(), Scalar::from(2), Scalar::from(7));

    // precomputed factorisation p - 1 = q * 2**s
    let q: Scalar = Scalar::from_str(
        "7237005575647265547668590434337973345624809701508485021401391191316782002773",
    )
    .unwrap();
    let s: Scalar = Scalar::from(4);

    //let qq = FieldBytes::

    // Select a z which is a quadratic non resudue modulo p.
    // We pre-computed it so we know that 6 isn't QR.
    let mut c = seven.pow_vartime(q.to_bytes());

    // Search for a solution.
    let mut x = scalar.pow(&(q + one).half_without_mod());
    let mut t = scalar.pow(&q);
    let mut m = s;

    while t != one {
        // Find the lowest i such that t^(2^i) = 1.
        let mut i = zero;
        let mut e = FieldElement::from(2u8);
        let b;
        while i < m {
            i = i + one;
            if t.pow(&e).ct_eq(&one).unwrap_u8() == 1u8 {
                break;
            }
            e = e * two;
        }

        // Update values for next iter
        b = c.pow(&two.pow(&(m - i - one)));
        x = x * b;
        t = t * b.square();
        c = b.square();
        m = i;
    }

    todo!()
}
*/
pub(crate) fn is_sqrt(scalar: Scalar) -> Choice {
    let res = scalar.pow_vartime(&[
        8781145580357391016,
        16029293310611541826,
        9223372036854775807,
        9223372034707292160,
    ]);

    res.ct_eq(&(Scalar::zero() - Scalar::one())) ^ Choice::from(1u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt_works() {
        assert!(is_sqrt(Scalar::one()).unwrap_u8() == 1u8);
        assert!(!is_sqrt(Scalar::from(7)).unwrap_u8() == 1u8);
    }
}
