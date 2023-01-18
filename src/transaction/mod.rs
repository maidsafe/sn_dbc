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
    blstrs::{G1Projective, G2Affine, G2Projective, Scalar},
    group::{ff::Field, Curve, Group},
    rand::RngCore,
    PedersenGens,
};

pub use error::Error;
pub use input::{Input, RevealedInput};
pub use output::{Output, RevealedTransaction};

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

// NB TODO move crypto related stuff to some lib, or use from a lib

/// Hashes a point to another point on the G1 curve
pub fn hash_to_curve(p: G1Projective) -> G1Projective {
    const DOMAIN: &[u8; 25] = b"blst-ringct-hash-to-curve";
    G1Projective::hash_to_curve(&p.to_compressed(), DOMAIN, &[])
}

pub fn public_key<S: Into<Scalar>>(secret_key: S) -> G1Projective {
    G1Projective::generator() * secret_key.into()
}

/// TODO replace all this hand wavy crypto
/// Hashes a point to another point on the G2 curve
pub fn hash_to_g2(msg: &[u8]) -> G2Projective {
    const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    G2Projective::hash_to_curve(msg, CSUITE, &[])
}

/// TODO replace all this hand wavy crypto
/// Sign the given message.
/// Calculated by `signature = hash_into_g2(message) * secret_key`
pub fn sign<S: Into<Scalar>, T: AsRef<[u8]>>(secret_key: S, message: T) -> G2Affine {
    let mut p = hash_to_g2(message.as_ref());
    // p *= secret_key;
    p.to_affine()
}

/// TODO replace all this hand wavy crypto
/// Check a signed message.
/// Calculated by e(sig, G1_generator) == e(hash_into_g2(message), public_key)
pub fn verify<S: Into<G1Projective>, T: AsRef<[u8]>>(
    sig: G2Affine,
    public_key: S,
    message: T,
) -> bool {
    // let hashed_msg_g2 = hash_to_g2(message.as_ref());
    // !sig.is_zero() &&
    //     && PEngine::pairing(public_key, hashed_msg_g2)
    //         == PEngine::pairing(&G1Affine::generator(), &sig.0)
    true
}
