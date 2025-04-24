use num_bigint::{BigInt, ToBigInt};
use prio::field::{Field128, FieldElementWithInteger, FieldPrio2};
use std::{
    array::from_fn,
    ops::{Add, Mul},
};

use crate::poly::Rq;

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
    for<'a> &'a Self::Plaintext: Mul<&'a Self::Ciphertext, Output = Self::Ciphertext>,
{
    // XXX I'm assuming pk has the relinearization key.
    fn somewhat_mul(
        &self,
        pk: Self::PublicKey,
        c1: Self::Ciphertext,
        c2: Self::Ciphertext,
    ) -> Self::Ciphertext;
}

#[derive(Debug)]
pub struct Bfv {
    plaintext_modulus: BigInt,
    ciphertext_modulus: BigInt,
    delta: Field128,
}

impl Default for Bfv {
    fn default() -> Self {
        let plaintext_modulus = u128::from(FieldPrio2::modulus());
        let delta = Field128::modulus() / plaintext_modulus;
        Self {
            plaintext_modulus: plaintext_modulus.to_bigint().unwrap(), // always succeeds on u128
            ciphertext_modulus: Field128::modulus().to_bigint().unwrap(),
            delta: Field128::from(delta),
        }
    }
}

impl PubEnc for Bfv {
    type PublicKey = [Rq<Field128, 256>; 2];
    type SecretKey = Rq<Field128, 256>;
    type Plaintext = BfvPlaintext;
    type Ciphertext = BfvCiphertext;

    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey) {
        let p1 = Rq::rand_long();
        let s = Rq::rand_short();
        let e = Rq::rand_short();
        let p0 = -&(&(&p1 * &s) + &e);
        ([p0, p1], s)
    }

    fn encrypt(
        &self,
        [p0, p1]: &Self::PublicKey,
        BfvPlaintext(Rq(m)): &Self::Plaintext,
    ) -> Self::Ciphertext {
        let m = Rq(from_fn(|i| {
            let m = u32::from(m[i]);
            let m = u128::from(m);
            let m = Field128::from(m);
            m * self.delta
        }));
        let u = Rq::rand_short();
        let e0 = Rq::rand_short();
        let e1 = Rq::rand_short();
        let c0 = &(&(p0 * &u) + &e0) + &m;
        let c1 = &(p1 * &u) + &e1;
        BfvCiphertext([c0, c1])
    }

    fn decrypt(
        &self,
        s: &Self::SecretKey,
        BfvCiphertext([c0, c1]): &Self::Ciphertext,
    ) -> Self::Plaintext {
        let Rq(m) = c0 + &(c1 * s);
        BfvPlaintext(Rq(from_fn(|i| {
            let mut m = u128::from(m[i]).to_bigint().unwrap(); // always succeeds on u128
            m *= &self.plaintext_modulus;
            m += &self.ciphertext_modulus >> 1;
            m /= &self.ciphertext_modulus;
            let m = u32::try_from(m).unwrap();
            FieldPrio2::from(m)
        })))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BfvPlaintext(Rq<FieldPrio2, 256>); // XXX Avoid hardcoding D

#[derive(Debug)]
pub struct BfvCiphertext([Rq<Field128, 256>; 2]);

impl Add for &BfvPlaintext {
    type Output = BfvPlaintext;
    fn add(self, rhs: Self) -> BfvPlaintext {
        BfvPlaintext(&self.0 + &rhs.0)
    }
}

impl Mul for &BfvPlaintext {
    type Output = BfvPlaintext;
    fn mul(self, rhs: Self) -> BfvPlaintext {
        BfvPlaintext(&self.0 * &rhs.0)
    }
}

impl Add for &BfvCiphertext {
    type Output = BfvCiphertext;
    fn add(self, rhs: Self) -> BfvCiphertext {
        BfvCiphertext(from_fn(|j| &self.0[j] + &rhs.0[j]))
    }
}

impl Mul<&BfvCiphertext> for &BfvPlaintext {
    type Output = BfvCiphertext;
    fn mul(self, BfvCiphertext(rhs): &BfvCiphertext) -> BfvCiphertext {
        let s = Rq(from_fn(|i| {
            let s = u32::from(self.0.0[i]);
            let s = u128::from(s);
            Field128::from(s)
        }));
        BfvCiphertext(from_fn(|j| &s * &rhs[j]))
    }
}

impl SomewahtHomomorphic for Bfv {
    fn somewhat_mul(
        &self,
        _pk: Self::PublicKey,
        _c1: Self::Ciphertext,
        _c2: Self::Ciphertext,
    ) -> Self::Ciphertext {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use prio::field::{FieldPrio2, random_vector};

    use super::*;

    fn random_plaintext() -> BfvPlaintext {
        BfvPlaintext(Rq(random_vector::<FieldPrio2>(256).try_into().unwrap()))
    }

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
        let m = random_plaintext();
        roundtrip_test(&bfv, &m);
    }

    #[test]
    fn homomorphic_add() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let m1 = random_plaintext();
        let m2 = random_plaintext();
        let want = &m1 + &m2;

        let c1 = bfv.encrypt(&pk, &m1);
        let c2 = bfv.encrypt(&pk, &m2);
        let got = bfv.decrypt(&sk, &(&c1 + &c2));
        assert_eq!(got, want);
    }

    #[test]
    fn homomorphic_plain_poly_mul() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let s = random_plaintext();
        let m = random_plaintext();
        let want = &s * &m;

        let c = bfv.encrypt(&pk, &m);
        let got = bfv.decrypt(&sk, &(&s * &c));
        assert_eq!(got, want);
    }
}
