use num_bigint::{BigInt, ToBigInt};
use prio::field::{Field128, FieldElement, FieldElementWithInteger, FieldPrio2 as Field32};
use std::{
    array::from_fn,
    ops::{Add, Mul},
};

use crate::poly::PolyRing;

pub mod poly;

pub trait PubEnc {
    type PublicKey;
    type SecretKey;
    type Plaintext;
    type Ciphertext;
    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(&self, pk: &Self::PublicKey, m: &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&self, sk: &Self::SecretKey, c: &Self::Ciphertext) -> Self::Plaintext;
}

pub trait SomewahtHomomorphic: PubEnc
where
    for<'a> &'a Self::Plaintext: Add<Output = Self::Plaintext>,
    for<'a> &'a Self::Plaintext: Mul<Output = Self::Plaintext>,
    for<'a> &'a Self::Ciphertext: Add<Output = Self::Ciphertext>,
    for<'a> &'a Self::Ciphertext: Mul<Output = Self::Ciphertext>,
    for<'a> &'a Self::Ciphertext: Mul<&'a Self::Plaintext, Output = Self::Ciphertext>,
{
    type RelinerizationKey;
    // XXX Reusable?
    fn relin_key_gen(&self, sk: &Self::SecretKey) -> Self::RelinerizationKey;
    fn relin(&self, rk: &Self::RelinerizationKey, c: &mut Self::Ciphertext);
}

/// The ciphertext ring.
pub type Rq = PolyRing<Field128, 256>;

/// The plaintext ring.
pub type Rt = PolyRing<Field32, 256>;

#[derive(Clone, Debug)]
pub struct Bfv {
    plaintext_modulus: BigInt,
    ciphertext_modulus: BigInt,
    delta: Field128,
}

impl Default for Bfv {
    fn default() -> Self {
        let plaintext_modulus = u128::from(Field32::modulus());
        let delta = Field128::modulus() / plaintext_modulus;
        Self {
            plaintext_modulus: plaintext_modulus.to_bigint().unwrap(), // always succeeds on u128
            ciphertext_modulus: Field128::modulus().to_bigint().unwrap(),
            delta: Field128::from(delta),
        }
    }
}

// Implement Optimization/Assumption 1 from [BFV12].
impl PubEnc for Bfv {
    type PublicKey = [Rq; 2];
    type SecretKey = Rq;
    type Plaintext = Rt;
    type Ciphertext = BfvCiphertext; // XXX remove wrapper

    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey) {
        let p1 = PolyRing::rand_long();
        let s = PolyRing::rand_short();
        let e = PolyRing::rand_short();
        let p0 = -&(&(&p1 * &s) + &e);
        ([p0, p1], s)
    }

    fn encrypt(&self, [p0, p1]: &Self::PublicKey, PolyRing(m): &Rt) -> Self::Ciphertext {
        let m = PolyRing(from_fn(|i| {
            let m = u32::from(m[i]);
            let m = u128::from(m);
            let m = Field128::from(m);
            m * self.delta
        }));
        let u = PolyRing::rand_short();
        let e0 = PolyRing::rand_short();
        let e1 = PolyRing::rand_short();
        let c0 = &(&(p0 * &u) + &e0) + &m;
        let c1 = &(p1 * &u) + &e1;
        BfvCiphertext(vec![c0, c1])
    }

    fn decrypt(&self, s: &Rq, BfvCiphertext(cs): &BfvCiphertext) -> Rt {
        debug_assert!(cs.len() > 1);
        let mut m: Rq = PolyRing::zero();
        let mut x = PolyRing::one();
        for c in cs {
            m = &m + &(c * &x);
            x = &x * s;
        }

        PolyRing(from_fn(|i| {
            let mut m = u128::from(m.0[i]).to_bigint().unwrap(); // always succeeds on u128
            m *= &self.plaintext_modulus;
            m += &self.ciphertext_modulus >> 1;
            m /= &self.ciphertext_modulus;
            let m = u32::try_from(m).unwrap();
            Field32::from(m)
        }))
    }
}

#[derive(Clone, Debug)]
pub struct BfvCiphertext(Vec<Rq>);

impl BfvCiphertext {
    pub fn empty() -> Self {
        Self(vec![PolyRing([Field128::zero(); 256]); 2])
    }
}

impl Add for &BfvCiphertext {
    type Output = BfvCiphertext;
    fn add(self, rhs: Self) -> BfvCiphertext {
        let mut out = vec![PolyRing::zero(); std::cmp::max(self.0.len(), rhs.0.len())];
        for (o, x) in out.iter_mut().zip(self.0.iter()) {
            *o = x.clone();
        }
        for (j, x) in rhs.0.iter().enumerate() {
            out[j] = &out[j] + x;
        }

        BfvCiphertext(out)
    }
}

impl Mul<&Rt> for &BfvCiphertext {
    type Output = BfvCiphertext;
    fn mul(self, PolyRing(m): &Rt) -> BfvCiphertext {
        let m = PolyRing(from_fn(|i| {
            let m = u32::from(m[i]);
            let m = u128::from(m);
            Field128::from(m)
        }));

        BfvCiphertext(self.0.iter().map(|x| x * &m).collect())
    }
}

impl Mul for &BfvCiphertext {
    type Output = BfvCiphertext;
    fn mul(self, rhs: &BfvCiphertext) -> BfvCiphertext {
        todo!()
    }
}

/*
impl Bfv {
    const T: u128 = 64_000_000;
    const SPLITS: usize = 5; // log_T(ciphertext_modulus)

    fn somewhat_mul_unlinearized(
        &self,
        BfvCiphertext(x1): &BfvCiphertext,
        BfvCiphertext(x2): &BfvCiphertext,
    ) -> [Rq; 3] {
        let y = [
            &x1[0] * &x2[0],
            &(&x1[0] * &x2[1]) + &(&x1[1] * &x2[0]),
            &x1[1] * &x2[1],
        ];
        from_fn(|j| {
            PolyRing(from_fn(|i| {
                let mut y = u128::from(y[j].0[i]).to_bigint().unwrap(); // always succeeds on u128
                y *= &self.plaintext_modulus;
                y += &self.ciphertext_modulus >> 1;
                y /= &self.ciphertext_modulus;
                Field128::from(u128::try_from(y).unwrap())
            }))
        })
    }
}

// XXX This is the version of relinearization that requires circular security. My understanding is
// that folks always implement the modulus switching version, which doesn't require extra
// assumptions. However, this version seems easier to implement. For now we just want to see if the
// somewhat homomorphic multiplication is good enough for our purposes.
impl SomewahtHomomorphic for Bfv {
    type RelinerizationKey = [[Rq; 2]; Bfv::SPLITS];

    fn relineraization_key_gen(
        &self,
        s: &Rq,
    ) -> [[Rq; 2]; Bfv::SPLITS] {
        let s_squared = s * s;
        let t = Field128::from(Bfv::T);
        let mut t_power = Field128::from(0);
        from_fn(|_| {
            let a = PolyRing::rand_long();
            let e = PolyRing::rand_short();
            let mut r0 = &(&a * s) + &e;
            r0 = -&r0;
            r0 = &r0 + &(&s_squared * t_power);
            t_power *= t;
            [r0, a]
        })
    }

    fn somewhat_mul(
        &self,
        _rk: &[[Rq; 2]; Bfv::SPLITS],
        x1: &BfvCiphertext,
        x2: &BfvCiphertext,
    ) -> BfvCiphertext {
        let [_y0, _y1, _y2] = self.somewhat_mul_unlinearized(x1, x2);
        todo!()
    }
}
*/

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    fn roundtrip_test<P>(pub_enc: &P, m: &P::Plaintext)
    where
        P: PubEnc,
        P::Plaintext: PartialEq + Debug,
    {
        let (pk, sk) = pub_enc.key_gen();
        assert_eq!(&pub_enc.decrypt(&sk, &pub_enc.encrypt(&pk, m)), m);
    }

    #[test]
    fn test_pub_enc() {
        let bfv = Bfv::default();
        let m = Rt::rand_long();
        roundtrip_test(&bfv, &m);
    }

    #[test]
    fn homomorphic_add() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let m1 = Rt::rand_long();
        let m2 = Rt::rand_long();
        let want = &m1 + &m2;

        let c1 = bfv.encrypt(&pk, &m1);
        let c2 = bfv.encrypt(&pk, &m2);
        let got = bfv.decrypt(&sk, &(&c1 + &c2));
        assert_eq!(got, want);
    }

    #[test]
    fn homomorphic_plain_mul() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let s = Rt::rand_long();
        let m = Rt::rand_long();
        let want = &s * &m;

        let c = bfv.encrypt(&pk, &m);
        let got = bfv.decrypt(&sk, &(&c * &s));
        assert_eq!(got, want);
    }

    #[test]
    fn homomorphic_somewhat_mul() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let m1 = PolyRing([Field32::from(0); 256]);
        let m2 = PolyRing([Field32::from(0); 256]);

        let c1 = bfv.encrypt(&pk, &m1);
        let c2 = bfv.encrypt(&pk, &m2);
        let r = &c1 * &c2;
    }
}
