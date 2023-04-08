// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{BlindedAmount, DbcId, Error, Hash, Result, Signature};

use custom_debug::Debug;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// SignedSpend's are constructed when a DBC is logged to the spentbook.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialOrd, Ord)]
pub struct SignedSpend {
    /// The Spend, which together with signature over it, constitutes the SignedSpend.
    pub spend: Spend,
    /// The DerivedKey's signature over (the hash of) Spend, confirming that the Dbc was intended to be spent.
    pub derived_key_sig: Signature,
}

impl SignedSpend {
    /// Get public key of input Dbc.
    pub fn dbc_id(&self) -> &DbcId {
        &self.spend.dbc_id
    }

    /// Get transaction hash.
    pub fn tx_hash(&self) -> Hash {
        self.spend.tx_hash
    }

    /// Get blinded amount.
    pub fn blinded_amount(&self) -> &BlindedAmount {
        &self.spend.blinded_amount
    }

    /// Get reason.
    pub fn reason(&self) -> Hash {
        self.spend.reason
    }

    /// Represent this SignedSpend as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();
        bytes.extend(self.spend.to_bytes());
        bytes.extend(self.derived_key_sig.to_bytes());
        bytes
    }

    /// Verify this SignedSpend
    ///
    /// Checks that the input transaction hash matches the tx_hash that was
    /// signed by the DerivedKey and verifies that signature is
    /// valid for this SignedSpend.
    pub fn verify(&self, tx_hash: Hash) -> Result<()> {
        // Verify that input tx_hash matches our tx_hash which was signed by the DerivedKey of the input.
        if tx_hash != self.spend.tx_hash {
            return Err(Error::InvalidTransactionHash);
        }

        // The spend is signed by the DerivedKey
        // corresponding to the DbcId of the Dbc being spent.
        if self
            .spend
            .dbc_id
            .verify(&self.derived_key_sig, self.spend.to_bytes())
        {
            Ok(())
        } else {
            Err(Error::InvalidSpendSignature(*self.dbc_id()))
        }
    }
}

// Impl manually to avoid clippy complaint about Hash conflict.
impl PartialEq for SignedSpend {
    fn eq(&self, other: &Self) -> bool {
        self.spend == other.spend && self.derived_key_sig == other.derived_key_sig
    }
}

impl Eq for SignedSpend {}

impl std::hash::Hash for SignedSpend {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = self.to_bytes();
        bytes.hash(state);
    }
}

/// Represents the data to be signed by the DerivedKey of the Dbc being spent.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spend {
    /// DbcId of input Dbc that this SignedSpend is proving to be spent.
    pub dbc_id: DbcId,
    /// Hash of transaction that the input Dbc is being spent in.
    pub tx_hash: Hash,
    /// Reason why this Dbc was spent.
    pub reason: Hash,
    #[debug(skip)]
    /// The amount of the input Dbc.
    pub blinded_amount: BlindedAmount,
}

impl Spend {
    /// Represent this Spend as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();
        bytes.extend(self.dbc_id.to_bytes());
        bytes.extend(self.tx_hash.as_ref());
        bytes.extend(self.reason.as_ref());
        bytes.extend(self.blinded_amount.compress().to_bytes());
        bytes
    }

    /// represent this Spend as a Hash
    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}

impl PartialOrd for Spend {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Spend {
    fn cmp(&self, other: &Self) -> Ordering {
        self.dbc_id.cmp(&other.dbc_id)
    }
}
