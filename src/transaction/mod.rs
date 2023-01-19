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

use crate::{BlindingFactor, Commitment};

use bls_bulletproofs::{
    group::{ff::Field, Curve},
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
    pub blinding: BlindingFactor,
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
            blinding: BlindingFactor::random(&mut rng),
        }
    }

    pub fn commit(&self, pc_gens: &PedersenGens) -> Commitment {
        pc_gens
            .commit(BlindingFactor::from(self.value), self.blinding)
            .to_affine()
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding(&self) -> BlindingFactor {
        self.blinding
    }
}
