// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use blsttc::PublicKey;
use bulletproofs::RangeProof;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::rand::{CryptoRng, RngCore};
use crate::{Amount, BlindedAmount, RevealedAmount};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Output {
    pub public_key: PublicKey,
    pub amount: Amount,
}

impl Output {
    pub fn new<G: Into<PublicKey>>(public_key: G, amount: Amount) -> Self {
        Self {
            public_key: public_key.into(),
            amount,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    /// Generate a revealed amount, with random blinding factor, which will be used for an input in a tx.
    pub fn revealed_amount(&self, rng: impl RngCore + CryptoRng) -> RevealedAmount {
        RevealedAmount::from_amount(self.amount, rng)
    }
}

/// An output with a revealed amount.
/// As this is meant to be blinded, it has the
/// blinding factor included (in the revealed amount instance).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevealedOutput {
    pub public_key: PublicKey,
    pub revealed_amount: RevealedAmount,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct BlindedOutput {
    pub(super) public_key: PublicKey,
    pub(super) range_proof: RangeProof,
    pub(super) blinded_amount: BlindedAmount,
}

impl BlindedOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.public_key.to_bytes().as_ref());
        v.extend(&self.range_proof.to_bytes());
        v.extend(self.blinded_amount.compress().as_bytes());
        v
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    pub fn blinded_amount(&self) -> BlindedAmount {
        self.blinded_amount
    }
}
