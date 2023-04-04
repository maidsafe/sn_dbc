// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use bulletproofs::RangeProof;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::rand::{CryptoRng, RngCore};
use crate::{
    RevealedAmount, {Amount, BlindedAmount, DbcId},
};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Output {
    pub dbc_id: DbcId,
    pub amount: Amount,
}

impl Output {
    pub fn new(dbc_id: DbcId, amount: Amount) -> Self {
        Self { dbc_id, amount }
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
    pub dbc_id: DbcId,
    pub revealed_amount: RevealedAmount,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct BlindedOutput {
    pub(super) dbc_id: DbcId,
    pub(super) range_proof: RangeProof,
    pub(super) blinded_amount: BlindedAmount,
}

impl BlindedOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.dbc_id.to_bytes().as_ref());
        v.extend(&self.range_proof.to_bytes());
        v.extend(self.blinded_amount.compress().as_bytes());
        v
    }

    pub fn dbc_id(&self) -> &DbcId {
        &self.dbc_id
    }

    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    pub fn blinded_amount(&self) -> BlindedAmount {
        self.blinded_amount
    }
}
