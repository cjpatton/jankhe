//! Basic BGV as described by HomomorphicEncryption.org.

use std::{
    array::from_fn,
    ops::{Add, Mul},
};

use num_bigint::{BigInt, ToBigInt};
use prio::field::{Field128, FieldElementWithInteger, FieldPrio2 as Field32};

use crate::{PubEnc, poly::PolyRing};

pub trait SomewahtHomomorphic: PubEnc
where
    for<'a> &'a Self::Plaintext: Add<Output = Self::Plaintext>,
    for<'a> &'a Self::Plaintext: Mul<Output = Self::Plaintext>,
    for<'a> &'a Self::Ciphertext: Add<Output = Self::Ciphertext>,
    for<'a> &'a Self::Ciphertext: Mul<Output = Self::Ciphertext>,
    for<'a> &'a Self::Ciphertext: Mul<&'a Self::Plaintext, Output = Self::Ciphertext>,
{
}

// XXX Make these generic
pub type Rq = PolyRing<Field128, 256>;
pub type Rt = PolyRing<Field32, 256>;

pub struct BgvCiphertext(Vec<Rq>);

pub struct Bgv {
    p: Field128,
    plaintext_modulus: BigInt,
    ciphertext_modulus: BigInt,
    delta: Field128,
}

impl Default for Bgv {
    fn default() -> Bgv {
        let p = Field128::from(u128::from(Field32::modulus()));
        let plaintext_modulus = u128::from(Field32::modulus());
        let delta = Field128::modulus() / plaintext_modulus;
        Bgv {
            p,
            plaintext_modulus: plaintext_modulus.to_bigint().unwrap(),
            ciphertext_modulus: Field128::modulus().to_bigint().unwrap(),
            delta: Field128::from(delta),
        }
    }
}

const SPECIAL: u32 = 3694462535;

impl PubEnc for Bgv {
    type PublicKey = [Rq; 2];
    type SecretKey = Rq;
    type Ciphertext = BgvCiphertext;
    type Plaintext = Rt;

    fn key_gen(&self) -> ([Rq; 2], Rq) {
        let a = Rq::rand_long();
        let s = Rq::rand_short();
        let mut e = Rq::rand_short();
        e *= self.p;
        let pk0 = -&a;
        let pk1 = &(&a * &s) + &e;
        ([pk0, pk1], s)
    }

    fn encrypt(&self, [pk0, pk1]: &[Rq; 2], m: &Rt) -> BgvCiphertext {
        let m = PolyRing(from_fn(|i| {
            let m = Field128::from(u128::from(u32::from(m.0[i])));
            m //  * self.delta
        }));
        let u = Rq::rand_short();
        let mut e0 = Rq::rand_short();
        let mut e1 = Rq::rand_short();
        e0 *= self.p;
        e1 *= self.p;
        let c0 = &(pk0 * &u) + &e0;
        let c1 = &(&(pk1 * &u) + &e1) + &m;
        BgvCiphertext(vec![c0, c1])
    }

    fn decrypt(&self, s: &Rq, BgvCiphertext(c): &BgvCiphertext) -> Rt {
        let mut m = Rq::zero();
        let mut x = Rq::one();
        for c in c.iter().rev() {
            m += &(&x * c);
            x *= s;
        }

        PolyRing(from_fn(|i| {
            let m = u128::from(m.0[i]) % u128::from(self.p);
            let mut m = u32::try_from(m).unwrap();
            if m >= SPECIAL {
                m -= SPECIAL;
            }
            /*
            let mut m = u128::from(m.0[i]).to_bigint().unwrap();
            m *= &self.plaintext_modulus;
            m += &self.ciphertext_modulus >> 1;
            m /= &self.ciphertext_modulus;
            let m = u32::try_from(m).unwrap();
            */
            Field32::from(m)
        }))
    }
}

impl Add for &BgvCiphertext {
    type Output = BgvCiphertext;

    fn add(self, rhs: &BgvCiphertext) -> BgvCiphertext {
        todo!()
    }
}

impl Mul for &BgvCiphertext {
    type Output = BgvCiphertext;

    fn mul(self, rhs: &BgvCiphertext) -> BgvCiphertext {
        let mut out = vec![Rq::zero(); self.0.len() + rhs.0.len() - 1];
        for (i, x) in self.0.iter().enumerate() {
            for (j, y) in rhs.0.iter().enumerate() {
                out[i + j] += &(x * y);
            }
        }
        BgvCiphertext(out)
    }
}

impl Mul<&Rt> for &BgvCiphertext {
    type Output = BgvCiphertext;

    fn mul(self, rhs: &Rt) -> BgvCiphertext {
        todo!()
    }
}

impl SomewahtHomomorphic for Bgv {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::roundtrip_test;

    #[test]
    fn pub_enc() {
        roundtrip_test(&Bgv::default(), &Rt::one());
        roundtrip_test(&Bgv::default(), &Rt::rand_short());
    }

    #[test]
    fn mul() {
        let bgv = Bgv::default();

        let m1 = Rt::one();
        let mut m2 = Rt::zero();
        m2.0[1] = Field32::from(12);
        let want = &m1 * &m2;

        let (pk, sk) = bgv.key_gen();
        let c1 = bgv.encrypt(&pk, &m1);
        let c2 = bgv.encrypt(&pk, &m2);
        let got = bgv.decrypt(&sk, &(&c1 * &c2));
        assert_eq!(got, want);
    }
}
