use std::ops::{Add, Mul};

pub trait PubEnc {
    type PublicKey;
    type SecretKey;
    type Plaintext;
    type Ciphertext;
    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(&self, m: &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&self, c: &Self::Ciphertext) -> Self::Plaintext;
}

pub trait SomewahtHomomorphic: PubEnc
where
    Self::Ciphertext: Add + Mul,
    Self::Plaintext: Mul<Self::Ciphertext, Output = Self::Ciphertext>,
{
}

pub struct Bfv;
pub struct BfvPlaintext;
pub struct BfvCiphertext;

impl PubEnc for Bfv {
    type PublicKey = ();
    type SecretKey = ();
    type Plaintext = BfvPlaintext;
    type Ciphertext = BfvCiphertext;
    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey) {
        todo!()
    }
    fn encrypt(&self, _m: &Self::Plaintext) -> Self::Ciphertext {
        todo!()
    }
    fn decrypt(&self, _c: &Self::Ciphertext) -> Self::Plaintext {
        todo!()
    }
}

impl Add for BfvCiphertext {
    type Output = BfvPlaintext;
    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

// XXX this needs the relinearization key I believe.
impl Mul for BfvCiphertext {
    type Output = BfvCiphertext;
    fn mul(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl Mul<BfvCiphertext> for BfvPlaintext {
    type Output = BfvCiphertext;
    fn mul(self, _rhs: BfvCiphertext) -> Self::Output {
        todo!()
    }
}
