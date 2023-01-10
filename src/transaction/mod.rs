// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

pub mod error;
pub mod input;
pub mod output;

// re-export deps used in our public API
pub use bls_bulletproofs::{self, blstrs, group, rand};
#[cfg(feature = "serde")]
pub use serde;

use bls_bulletproofs::{
    blstrs::{G1Projective, Scalar},
    group::{ff::Field, Group},
    rand::RngCore,
    PedersenGens,
};

pub use error::Error;
pub use input::{DecoyInput, MlsagMaterial, MlsagSignature, TrueInput};
pub use output::{Output, RingCtMaterial};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct RevealedCommitment {
    pub value: u64,
    pub blinding: Scalar,
}

impl RevealedCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.value.to_le_bytes());
        v.extend(self.blinding.to_bytes_le());
        v
    }

    /// Construct a revealed commitment from a value, generating a blinding randomly
    pub fn from_value(value: u64, mut rng: impl RngCore) -> Self {
        Self {
            value,
            blinding: Scalar::random(&mut rng),
        }
    }

    pub fn commit(&self, pc_gens: &PedersenGens) -> G1Projective {
        pc_gens.commit(Scalar::from(self.value), self.blinding)
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding(&self) -> Scalar {
        self.blinding
    }
}

/// Hashes a point to another point on the G1 curve
pub fn hash_to_curve(p: G1Projective) -> G1Projective {
    const DOMAIN: &[u8; 25] = b"blst-ringct-hash-to-curve";
    G1Projective::hash_to_curve(&p.to_compressed(), DOMAIN, &[])
}

pub fn public_key<S: Into<Scalar>>(secret_key: S) -> G1Projective {
    G1Projective::generator() * secret_key.into()
}

/// returns KeyImage for the given public/secret key pair
/// A key image is defined to be I = x * Hp(P)
pub fn key_image<S: Into<Scalar>>(secret_key: S) -> G1Projective {
    let sk = secret_key.into();
    hash_to_curve(public_key(sk)) * sk
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
