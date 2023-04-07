// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use crate::{rand::RngCore, BlindedAmount, BlindingFactor, DerivedKey, Error, Result};

use blsttc::{rand::CryptoRng, Ciphertext, PublicKey};
use bulletproofs::PedersenGens;
use std::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const AMT_SIZE: usize = std::mem::size_of::<u64>(); // Amount size: 8 bytes (u64)
const BF_SIZE: usize = std::mem::size_of::<BlindingFactor>(); // Blinding factor size: 32 bytes (BlindingFactor)

/// Represents a Dbc's value.
pub type Amount = u64;

/// A RevealedAmount is a plain text value and a
/// blinding factor, which together can create a `BlindedAmount`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct RevealedAmount {
    pub value: Amount,
    pub blinding_factor: BlindingFactor,
}

impl RevealedAmount {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.value.to_le_bytes());
        v.extend(self.blinding_factor.to_bytes());
        v
    }

    /// Construct a RevealedAmount instance from an amount, generating a random blinding factor.
    pub fn from_amount(amount: Amount, mut rng: impl RngCore + CryptoRng) -> Self {
        Self {
            value: amount,
            blinding_factor: BlindingFactor::random(&mut rng),
        }
    }

    pub fn blinded_amount(&self, pc_gens: &PedersenGens) -> BlindedAmount {
        pc_gens.commit(BlindingFactor::from(self.value), self.blinding_factor)
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding_factor(&self) -> BlindingFactor {
        self.blinding_factor
    }

    /// Encrypt this instance to given public key, producing `Ciphertext`.
    pub fn encrypt(&self, public_key: &PublicKey) -> Ciphertext {
        public_key.encrypt(self.to_bytes())
    }

    /// Build RevealedAmount from fixed size byte array.
    pub fn from_bytes(bytes: [u8; AMT_SIZE + BF_SIZE]) -> Self {
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let mut b = [0u8; BF_SIZE];
        let blinding_factor = BlindingFactor::from_bytes_mod_order({
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });

        Self {
            value: amount,
            blinding_factor,
        }
    }

    /// Build RevealedAmount from byte array reference.
    pub fn from_bytes_ref(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AMT_SIZE + BF_SIZE {
            return Err(Error::InvalidRevealedAmountBytes);
        }
        let amount = Amount::from_le_bytes({
            let mut b = [0u8; AMT_SIZE];
            b.copy_from_slice(&bytes[0..AMT_SIZE]);
            b
        });
        let mut b = [0u8; BF_SIZE];
        let blinding_factor = BlindingFactor::from_bytes_mod_order({
            b.copy_from_slice(&bytes[AMT_SIZE..]);
            b
        });

        Ok(Self {
            value: amount,
            blinding_factor,
        })
    }
}

impl From<(Amount, BlindingFactor)> for RevealedAmount {
    /// Create RevealedAmount from an amount and a randomly generated blinding factor.
    fn from(params: (Amount, BlindingFactor)) -> Self {
        let (amount, blinding_factor) = params;

        Self {
            value: amount,
            blinding_factor,
        }
    }
}

impl TryFrom<(&DerivedKey, &Ciphertext)> for RevealedAmount {
    type Error = Error;

    /// Decrypt RevealedAmount ciphertext using a DerivedKey.
    fn try_from(params: (&DerivedKey, &Ciphertext)) -> Result<Self> {
        let (derived_key, ciphertext) = params;
        derived_key.decrypt(ciphertext)
    }
}
