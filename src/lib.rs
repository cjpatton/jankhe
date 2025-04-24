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
{
    /// Multiply ciphertexts `c1` and `c2`. This operation depends on the public key for
    /// relinearization. The result contains a significant amount of error that can only be removed
    /// by boostrapping.
    //
    // XXX I'm assuming pk has the relinearization key.
    fn somewhat_mul(
        &self,
        pk: &Self::PublicKey,
        c1: &Self::Ciphertext,
        c2: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    /// Multiply a ciphertext `c` by a plaintext polynomial `m`.
    fn plain_poly_mul(&self, m: &Self::Plaintext, c: &Self::Ciphertext) -> Self::Ciphertext;

    /// Multiply a cipheretxt `c` by a plaintext polynomial `m` element-wise. That is, the `i`th
    /// coefficient of the output is equal to `c[i]*m[i]` where `c[i]` is the `i`th coefficient of
    /// `c` (likewise for `m[i]`).
    //
    // XXX Is this a good name for this?
    fn plain_conv_mul(&self, m: &Self::Plaintext, c: &Self::Ciphertext) -> Self::Ciphertext;
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

// Implement Optimization/Assumption 1 from [BFV12].
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

impl SomewahtHomomorphic for Bfv {
    fn somewhat_mul(
        &self,
        _pk: &Self::PublicKey,
        _c1: &Self::Ciphertext,
        _c2: &Self::Ciphertext,
    ) -> Self::Ciphertext {
        todo!()
    }

    fn plain_poly_mul(
        &self,
        BfvPlaintext(Rq(m)): &BfvPlaintext,
        BfvCiphertext(c): &BfvCiphertext,
    ) -> BfvCiphertext {
        let m = Rq(from_fn(|i| {
            let m = u32::from(m[i]);
            let m = u128::from(m);
            Field128::from(m)
        }));
        BfvCiphertext(from_fn(|j| &m * &c[j]))
    }

    fn plain_conv_mul(
        &self,
        BfvPlaintext(Rq(m)): &Self::Plaintext,
        BfvCiphertext(c): &BfvCiphertext,
    ) -> Self::Ciphertext {
        let m: [_; 256] = from_fn(|i| {
            let m = u32::from(m[i]);
            let m = u128::from(m);
            Field128::from(m)
        });
        BfvCiphertext(from_fn(|j| Rq(from_fn(|i| m[i] * c[j].0[i]))))
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
        let bfv = Bfv::default();
        let m = BfvPlaintext(Rq::rand_long());
        roundtrip_test(&bfv, &m);
    }

    #[test]
    fn homomorphic_add() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let m1 = BfvPlaintext(Rq::rand_long());
        let m2 = BfvPlaintext(Rq::rand_long());
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

        let s = BfvPlaintext(Rq::rand_long());
        let m = BfvPlaintext(Rq::rand_long());
        let want = &s * &m;

        let c = bfv.encrypt(&pk, &m);
        let got = bfv.decrypt(&sk, &bfv.plain_poly_mul(&s, &c));
        assert_eq!(got, want);
    }

    #[test]
    fn homomorphic_plain_conv_mul() {
        let bfv = Bfv::default();
        let (pk, sk) = bfv.key_gen();

        let s = BfvPlaintext(Rq([random_vector(1)[0]; 256]));
        // XXX None of the following work!
        //
        //let s = BfvPlaintext(Rq::rand_long());
        //let s = BfvPlaintext(Rq::rand_short());
        //s.0.0[23] = 23.into();
        let m = BfvPlaintext(Rq::rand_long());
        let want = BfvPlaintext(Rq(from_fn(|i| s.0.0[i] * m.0.0[i])));

        let c = bfv.encrypt(&pk, &m);
        let got = bfv.decrypt(&sk, &bfv.plain_conv_mul(&s, &c));
        assert_eq!(got, want);
    }
}
