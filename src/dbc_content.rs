// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use threshold_crypto::PublicKey;
use tiny_keccak::{Hasher, Sha3};

use crate::{DbcContentHash, Error, Hash};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct BlindedOwner(Hash);

impl BlindedOwner {
    pub fn new(
        owner: &PublicKey,
        parents: &BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u8,
    ) -> Self {
        let mut sha3 = Sha3::v256();

        for parent in parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&amount.to_be_bytes());
        sha3.update(&output_number.to_be_bytes());
        sha3.update(&owner.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Self(Hash(hash))
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Parent DBC's, acts as a nonce
    pub amount: u64,
    pub output_number: u8,
    pub owner: BlindedOwner,
}

impl DbcContent {
    // Create a new DbcContent for signing. TODO: blind the owner from the mint
    pub fn new(
        parents: BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u8,
        owner_key: PublicKey,
    ) -> Self {
        let owner = BlindedOwner::new(&owner_key, &parents, amount, output_number);
        DbcContent {
            parents,
            amount,
            output_number,
            owner,
        }
    }

    pub fn validate_unblinding(&self, owner_key: &PublicKey) -> Result<(), Error> {
        let blinded = BlindedOwner::new(owner_key, &self.parents, self.amount, self.output_number);
        if blinded == self.owner {
            Ok(())
        } else {
            Err(Error::FailedUnblinding)
        }
    }

    pub fn hash(&self) -> DbcContentHash {
        let mut sha3 = Sha3::v256();

        for parent in self.parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&self.amount.to_be_bytes());
        sha3.update(&self.output_number.to_be_bytes());
        sha3.update(&self.owner.0);

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }
}
