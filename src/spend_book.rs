// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// # SpendBook and Forced One-Time-Keys
//
// The SpendBook logs each spent DBC along with the reissue transaction it was spent in.
// To reissue a DBC, the reissue transaction must be signed with a one-time-key called
// the `Spend Key`.
//
// The Spend Key is calculated from the DBC owner by deriving a child key using the DBC hash
// as the derivation index.
//
// ```
// spend_key = dbc_owner_key.derive_child(dbc.hash())
// ```
//
// The SpendBook is a mapping from a DBC's Spend Key to the reissue transaction that this DBC
// was spent in.
//
// The mint does not have direct control over the dbc's owner and so we can not enforce globally
// unique owners for each DBC that is minted. Instead we enforce globally unique spend keys by
// choosing an unpredictable but deterministic index: the dbc hash.
// Thus, the spend key derivation algorithm gives us a globally unique one-time-key that we
// use to uniquely reference a DBC, as well as giving DBC owners a mechanism to prove ownership
// of the DBC by demonstrating control of the spend key.

use std::collections::BTreeMap;
use std::{error, fmt};

use serde::{Deserialize, Serialize};

use crate::{DbcTransaction, PublicKey};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpendKey(pub PublicKey);

// Display Hash value as hex in Debug output.  consolidates 36 lines to 3 for pretty output
// and the hex value is the same as sn_dbc_mint display of DBC IDs.
impl fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SpendKey")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
use rand::distributions::{Distribution, Standard};
#[cfg(test)]
use rand::Rng;

/// used when fuzzing DBC's in testing.
#[cfg(test)]
impl Distribution<SpendKey> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpendKey {
        SpendKey(
            crate::genesis_dbc_input()
                .0
                .derive_child(&rng.gen::<[u8; 32]>()),
        )
    }
}

/// The SpendBook logs all spent DBC's.
pub trait SpendBook: fmt::Debug + Clone {
    type Error: error::Error;

    fn lookup(&self, spend_key: &SpendKey) -> Result<Option<&DbcTransaction>, Self::Error>;
    fn log(&mut self, spend_key: SpendKey, transaction: DbcTransaction) -> Result<(), Self::Error>;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimpleSpendBook {
    pub transactions: BTreeMap<SpendKey, DbcTransaction>,
}

impl SpendBook for SimpleSpendBook {
    type Error = std::convert::Infallible;

    fn lookup(&self, spend_key: &SpendKey) -> Result<Option<&DbcTransaction>, Self::Error> {
        Ok(self.transactions.get(spend_key))
    }

    fn log(&mut self, spend_key: SpendKey, transaction: DbcTransaction) -> Result<(), Self::Error> {
        self.transactions.insert(spend_key, transaction);
        Ok(())
    }
}

impl IntoIterator for SimpleSpendBook {
    type Item = (SpendKey, DbcTransaction);
    type IntoIter = std::collections::btree_map::IntoIter<SpendKey, DbcTransaction>;

    fn into_iter(self) -> Self::IntoIter {
        self.transactions.into_iter()
    }
}

impl SimpleSpendBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<SpendKey, DbcTransaction> {
        self.transactions.iter()
    }
}
