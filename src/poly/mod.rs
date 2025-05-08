use bitvec::prelude::*;
use field64::POLY_MUL_FIELD64;
use prio::field::{
    Field64, Field128, FieldElement, FieldElementWithInteger, FieldPrio2 as Field32,
};
use rand::prelude::*;
use std::{
    array::from_fn,
    ops::{Add, Mul, Neg},
};

use crate::poly::{field32::POLY_MUL_FIELD32, field128::POLY_MUL_FIELD128};

mod field128;
mod field32;
mod field64;

/// Polynomial ring for the ciphertext.
///
/// NOTE: SEAL uses a composite modulus for the ciphertext. It recommends safe defaults based on the
/// size of the plaintext modulus. It also allows the user to choose the modulus themselves. For
/// now, we're hardcoding a prime modulus for which we know how to implement NTT.
#[derive(Clone, Debug, PartialEq)]
pub struct PolyRing<F: FieldElement, const D: usize>(pub(crate) [F; D]);

impl<F: FieldElement + FieldElementWithInteger, const D: usize> PolyRing<F, D> {
    /// Return a polynomial with all-zero coefficients.
    pub fn zero() -> Self {
        Self([F::zero(); D])
    }

    /// XXX
    pub fn one() -> Self {
        let mut x = Self::zero();
        x.0[0] = F::one();
        x
    }

    // TODO Implement `Distribution<PolyRing<F,D>>` for `Standard` instead. This will require changes
    // upstream in `prio`.
    pub(crate) fn rand_long() -> Self {
        Self(prio::field::random_vector(D).try_into().unwrap())
    }

    /// Sample a polynomial with binomially distributed coefficients.
    //
    // TODO Pass an `Rng` here.
    pub(crate) fn rand_short() -> Self {
        const ETA: usize = 3;
        const BYTES_BUF_SIZE: usize = 256;

        let mut rng = thread_rng();
        let bits_sampled = 2 * ETA * D;
        let bytes_sampled = bits_sampled.div_ceil(8);
        debug_assert!(bytes_sampled <= BYTES_BUF_SIZE);
        let mut bytes = [0_u8; BYTES_BUF_SIZE];
        rng.fill(&mut bytes[..bytes_sampled]);

        let mut bits = bytes[..bytes_sampled].view_bits::<Msb0>().chunks(2);
        let mut sample = || {
            let chunk = bits.next().unwrap();
            let value = chunk.load_be::<usize>();
            F::from(F::Integer::try_from(value).unwrap())
        };

        Self(from_fn(|_| sample() - sample()))
    }
}

impl<F: FieldElement, const D: usize> Add for &PolyRing<F, D> {
    type Output = PolyRing<F, D>;
    fn add(self, rhs: Self) -> Self::Output {
        PolyRing(from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl<F: FieldElement, const D: usize> Mul<F> for &PolyRing<F, D> {
    type Output = PolyRing<F, D>;
    fn mul(self, rhs: F) -> PolyRing<F, D> {
        PolyRing(from_fn(|i| self.0[i] * rhs))
    }
}

impl Mul for &PolyRing<Field128, 256> {
    type Output = PolyRing<Field128, 256>;
    fn mul(self, rhs: Self) -> Self::Output {
        POLY_MUL_FIELD128.poly_mul(self, rhs)
    }
}

impl Mul for &PolyRing<Field64, 256> {
    type Output = PolyRing<Field64, 256>;
    fn mul(self, rhs: Self) -> Self::Output {
        POLY_MUL_FIELD64.poly_mul(self, rhs)
    }
}

impl Mul for &PolyRing<Field32, 256> {
    type Output = PolyRing<Field32, 256>;
    fn mul(self, rhs: Self) -> Self::Output {
        POLY_MUL_FIELD32.poly_mul(self, rhs)
    }
}

impl<F: FieldElement, const D: usize> Neg for &PolyRing<F, D> {
    type Output = PolyRing<F, D>;
    fn neg(self) -> Self::Output {
        PolyRing(from_fn(|i| -self.0[i]))
    }
}

// XXX Generalize D
pub(crate) struct NttParamD256<F: FieldElement> {
    num_levels: usize,
    ts: [F; 127],
    us: [F; 127],
    c: F,
}

impl<F: FieldElement> NttParamD256<F> {
    /// Multiply two polynomials `a` and `b` from `F[X]/(X^256 + 1)`.
    fn poly_mul(
        &self,
        PolyRing(a): &PolyRing<F, 256>,
        PolyRing(b): &PolyRing<F, 256>,
    ) -> PolyRing<F, 256> {
        fn level<F>(t: &[F], i: usize) -> &[F] {
            let level_start = (1 << i) - 1;
            let level_len = 1 << i;
            &t[level_start..level_start + level_len]
        }

        debug_assert_eq!(self.ts.len(), self.us.len());

        let (mut p, mut n) = (0, 1);
        let mut ntt_a = [*a, [F::zero(); 256]];
        let mut ntt_b = [*b, [F::zero(); 256]];

        for i in 0..self.num_levels {
            let t = level(&self.ts, i);
            let v = 1 << (8 - i); // width
            let w = v / 2; // split
            debug_assert_eq!(256 / v, t.len());
            for (j, z) in (0..256).step_by(v).zip(t.iter().copied()) {
                for k in j..j + w {
                    // a
                    let y = z * ntt_a[p][k + w];
                    ntt_a[n][k] = ntt_a[p][k] + y;
                    ntt_a[n][k + w] = ntt_a[p][k] - y;

                    // b
                    let y = z * ntt_b[p][k + w];
                    ntt_b[n][k] = ntt_b[p][k] + y;
                    ntt_b[n][k + w] = ntt_b[p][k] - y;
                }
            }
            (p, n) = (1 - p, 1 - n);
        }

        for i in 0..64 {
            let range = 4 * i..4 * i + 2;
            let ntt_x: [_; 2] = slow_poly_mul(
                ntt_a[p][range.clone()].try_into().unwrap(),
                ntt_b[p][range.clone()].try_into().unwrap(),
                level(&self.us, self.num_levels - 1)[i],
            );
            ntt_a[n][range.clone()].copy_from_slice(&ntt_x);

            let range = 4 * i + 2..4 * i + 4;
            let ntt_x: [_; 2] = slow_poly_mul(
                ntt_a[p][range.clone()].try_into().unwrap(),
                ntt_b[p][range.clone()].try_into().unwrap(),
                level(&self.ts, self.num_levels - 1)[i],
            );
            ntt_a[n][range.clone()].copy_from_slice(&ntt_x);
        }
        (p, n) = (1 - p, 1 - n);

        for i in (0..self.num_levels).rev() {
            let u = level(&self.us, i);
            let v = 1 << (8 - i); // width
            let w = v / 2; // split
            debug_assert_eq!(256 / v, u.len());
            for (j, z) in (0..256).step_by(v).zip(u.iter().copied().rev()) {
                for k in j..j + w {
                    // a
                    ntt_a[n][k] = ntt_a[p][k] + ntt_a[p][k + w];
                    ntt_a[n][k + w] = (ntt_a[p][k] - ntt_a[p][k + w]) * z;
                }
            }
            (p, n) = (1 - p, 1 - n);
        }

        // Multiply each element of the output by `2^-7`. See [Lyu24], bottom of Section 4.6.
        for i in 0..256 {
            ntt_a[p][i] *= self.c;
        }

        PolyRing(ntt_a[p])
    }
}

/// Multiply two polynomials `a` and `b` from `F[X]/(X^D + r)`.
///
/// This is the algorithm described in Section 4.1.1 of [Lyu24]. Matrix `m` is the transpose
/// of the matrix on the left hand side of Equation (43).
fn slow_poly_mul<F: FieldElement, const D: usize>(mut a: [F; D], b: [F; D], r: F) -> [F; D] {
    let m: Mat<F, D, D> = Mat(from_fn(|_| {
        let row = a;

        // Multiply `a` by `X` and reduce.
        //
        // Let `c` be the leading coefficient of `a`.
        let c = a[D - 1];

        // Multiply `a` by `X` in place by shifting everything over.
        for j in (1..D).rev() {
            a[j] = a[j - 1];
        }

        // Clear the first coefficient of `a` to complete the shift and subtract `c * F(X)` from `a`.
        a[0] = r * -c;

        row
    }));

    (&Mat([b]) * &m).0[0]
}

struct Mat<F, const ROWS: usize, const COLS: usize>([[F; COLS]; ROWS]);

#[allow(clippy::needless_range_loop)]
impl<F: FieldElement, const I: usize, const J: usize, const K: usize> Mul<&Mat<F, J, K>>
    for &Mat<F, I, J>
{
    type Output = Mat<F, I, K>;
    fn mul(self, rhs: &Mat<F, J, K>) -> Mat<F, I, K> {
        let mut out = [[F::zero(); K]; I];
        for i in 0..I {
            for j in 0..J {
                for k in 0..K {
                    out[i][k] += self.0[i][j] * rhs.0[j][k];
                }
            }
        }
        Mat(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slow_poly_mul() {
        assert_eq!(
            [Field128::from(0), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(99), Field128::from(99)],
                [Field128::from(0), Field128::from(0)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(1), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(1), Field128::from(0)],
                [Field128::from(1), Field128::from(0)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(0), Field128::from(1)],
            slow_poly_mul(
                [Field128::from(1), Field128::from(0)],
                [Field128::from(0), Field128::from(1)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(0), Field128::from(6)],
            slow_poly_mul(
                [Field128::from(2), Field128::from(0)],
                [Field128::from(0), Field128::from(3)],
                Field128::one(),
            )
        );

        assert_eq!(
            [-Field128::from(6), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(0), Field128::from(2)],
                [Field128::from(0), Field128::from(3)],
                Field128::one(),
            )
        );

        assert_eq!(
            [-Field128::from(12), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(0), Field128::from(2)],
                [Field128::from(0), Field128::from(3)],
                Field128::from(2),
            )
        );
    }
}
