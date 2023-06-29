// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use crate::{DbcId, SignedSpend, Token};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet};
use tiny_keccak::{Hasher, Sha3};

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Input {
    pub dbc_id: DbcId,
    pub token: Token,
}

impl Input {
    pub fn new(dbc_id: DbcId, amount: u64) -> Self {
        Self {
            dbc_id,
            token: Token::from_nano(amount),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.dbc_id.to_bytes().as_ref());
        v.extend(self.token.to_bytes());
        v
    }

    pub fn dbc_id(&self) -> DbcId {
        self.dbc_id
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Output {
    pub dbc_id: DbcId,
    pub token: Token,
}

impl Output {
    pub fn new(dbc_id: DbcId, amount: u64) -> Self {
        Self {
            dbc_id,
            token: Token::from_nano(amount),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(self.dbc_id.to_bytes().as_ref());
        v.extend(self.token.to_bytes());
        v
    }

    pub fn dbc_id(&self) -> &DbcId {
        &self.dbc_id
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct DbcTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl PartialEq for DbcTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

impl Eq for DbcTransaction {}

impl PartialOrd for DbcTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DbcTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash().cmp(&other.hash())
    }
}

impl DbcTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend("inputs".as_bytes());
        for m in self.inputs.iter() {
            v.extend(&m.to_bytes());
        }
        v.extend("outputs".as_bytes());
        for o in self.outputs.iter() {
            v.extend(&o.to_bytes());
        }
        v.extend("end".as_bytes());
        v
    }

    pub fn hash(&self) -> crate::Hash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.to_bytes());
        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        crate::Hash::from(hash)
    }

    /// Check if every input has the signature over this very tx,
    /// and that each public key of the inputs was the signer.
    pub fn verify(&self) -> Result<()> {
        // Verify that the tx has at least one input
        if self.inputs.is_empty() {
            return Err(Error::MissingTxInputs);
        }

        // Verify that each dbc id is unique.
        let id_count = self.inputs.len();
        let unique_ids: BTreeSet<_> = self.inputs.iter().map(|input| input.dbc_id).collect();
        if unique_ids.len() != id_count {
            return Err(Error::DbcIdNotUniqueAcrossInputs);
        }

        // Check that the input and output tokens are equal.
        let input_sum: u64 = self
            .inputs
            .iter()
            .map(|i| i.token)
            .try_fold(0, |acc: u64, i| {
                acc.checked_add(i.as_nano()).ok_or(Error::NumericOverflow)
            })?;
        let output_sum: u64 = self
            .outputs
            .iter()
            .map(|o| o.token)
            .try_fold(0, |acc: u64, o| {
                acc.checked_add(o.as_nano()).ok_or(Error::NumericOverflow)
            })?;

        if input_sum != output_sum {
            Err(Error::InconsistentDbcTransaction)
        } else {
            Ok(())
        }
    }

    /// Verifies a transaction including signed spends.
    ///
    /// This function relies/assumes that the caller (wallet/client) obtains
    /// the DbcTransaction (held by every input spend's close group) in a
    /// trustless/verified way. I.e., the caller should not simply obtain a
    /// spend from a single peer, but must get the same spend from all in the close group.
    pub fn verify_against_inputs_spent(&self, signed_spends: &BTreeSet<SignedSpend>) -> Result<()> {
        if signed_spends.is_empty() {
            return Err(Error::MissingTxInputs)?;
        }

        if signed_spends.len() != self.inputs.len() {
            return Err(Error::SignedSpendInputLenMismatch {
                current: signed_spends.len(),
                expected: self.inputs.len(),
            });
        }

        let spent_tx_hash = self.hash();

        // Verify that each pubkey is unique in this transaction.
        let unique_dbc_ids: BTreeSet<DbcId> = self.outputs.iter().map(|o| (*o.dbc_id())).collect();
        if unique_dbc_ids.len() != self.outputs.len() {
            return Err(Error::DbcIdNotUniqueAcrossOutputs);
        }

        // Verify that each input has a corresponding signed spend.
        for signed_spend in signed_spends.iter() {
            if !self
                .inputs
                .iter()
                .any(|m| m.dbc_id == *signed_spend.dbc_id())
            {
                return Err(Error::SignedSpendInputIdMismatch);
            }
        }

        // Verify that each signed spend is valid
        for signed_spend in signed_spends.iter() {
            signed_spend.verify(spent_tx_hash)?;
        }

        // We must get the signed spends into the same order as inputs
        // so that resulting amounts will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut signed_spends_found: Vec<(usize, &SignedSpend)> = signed_spends
            .iter()
            .filter_map(|s| {
                self.inputs
                    .iter()
                    .position(|m| m.dbc_id == *s.dbc_id())
                    .map(|idx| (idx, s))
            })
            .collect();

        signed_spends_found.sort_by_key(|s| s.0);

        self.verify()
    }
}
