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
    Self::Ciphertext: Add,
    Self::Plaintext: Mul<Self::Ciphertext, Output = Self::Ciphertext>,
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

impl Bfv {
    pub fn new(plaintext_modulus: u32) -> Self {
        let plaintext_modulus = u128::from(plaintext_modulus);
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
            m %= &self.plaintext_modulus;
            let m = u32::try_from(m).unwrap();
            let m = FieldPrio2::from(m);
            m
        })))
    }
}

#[derive(Debug, PartialEq)]
pub struct BfvPlaintext(Rq<FieldPrio2, 256>); // XXX Avoid hardcoding D

pub struct BfvCiphertext([Rq<Field128, 256>; 2]);

impl Add for BfvCiphertext {
    type Output = BfvPlaintext;
    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl Mul<BfvCiphertext> for BfvPlaintext {
    type Output = BfvCiphertext;
    fn mul(self, _rhs: BfvCiphertext) -> Self::Output {
        todo!()
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
        let pub_enc = Bfv::new(u32::from(FieldPrio2::modulus()));
        let m = BfvPlaintext(Rq(random_vector::<FieldPrio2>(256).try_into().unwrap()));
        roundtrip_test(&pub_enc, &m);
    }
}
