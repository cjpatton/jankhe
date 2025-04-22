#![allow(dead_code)] // XXX Remove me

use std::ops::{Add, Mul};

use prio::field::NttFriendlyFieldElement;

// Polynomial ring for the ciphertext.
//
// NOTE: SEAL uses a composite modulus for the ciphertext. It recommends safe defaults based on the
// size of the plaintext modulus. It also allows the user to choose the modulus themselves. For
// now, we're hardcoding a prime modulus for which we know how to implement NTT.
struct Cr<F: NttFriendlyFieldElement, const D: usize>(pub(crate) [F; D]);

impl<F: NttFriendlyFieldElement, const D: usize> Add for Cr<F, D> {
    type Output = Cr<F, D>;
    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<F: NttFriendlyFieldElement, const D: usize> Mul for Cr<F, D> {
    type Output = Cr<F, D>;
    fn mul(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}
