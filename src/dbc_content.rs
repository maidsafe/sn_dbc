// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use threshold_crypto::PublicKeySet;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::DbcContentHash;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Parent DBC's, acts as a nonce
    pub amount: u64,
    pub output_number: u8,
    pub owner: PublicKeySet, // TAI: should this be threshold_crypto::PublicKey? (PublicKeySet::public_key())
}

impl DbcContent {
    // Create a new DbcContent for signing. TODO: blind the owner from the mint
    pub fn new(
        parents: BTreeSet<DbcContentHash>,
        amount: u64,
        output_number: u8,
        owner: PublicKeySet,
    ) -> Self {
        // let mut owner = owner;
        // for _ in 0..amount % 1000 {
        //     owner = sha3_256(&owner); // owner not visible to mint, until out_dbc is minted.
        // }
        DbcContent {
            parents,
            amount,
            output_number,
            owner,
        }
    }

    pub fn hash(&self) -> DbcContentHash {
        // let data = serde_json::to_string(&self)?; // use the sha3 256 of the json string repr for x platform use
        // Ok(sha3_256(data.as_ref()))

        let mut sha3 = Sha3::v256();

        for parent in self.parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&self.amount.to_be_bytes());
        sha3.update(&self.output_number.to_be_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }
}
