// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::{sha3_256, DbcContentHash, Error, Result, VecSet};

#[derive(Serialize, Deserialize)]
pub struct DbcContent {
    pub parents: BTreeSet<DbcContentHash>, // Hash of parent DbcContent. Also used as a nonce
    // TODO: pub owner: PubKey
    pub amount: u64,
}

impl DbcContent {
    // Create a new DbcContent for signing. TODO: blind the owner from the mint
    pub fn new(parents: BTreeSet<DbcContentHash>, amount: u64) -> Self {
        // let mut owner = owner;
        // for _ in 0..amount % 1000 {
        //     owner = sha3_256(&owner); // owner not visible to mint, until out_dbc is minted.
        // }
        DbcContent { parents, amount }
    }

    pub fn hash(&self) -> DbcContentHash {
        // let data = serde_json::to_string(&self)?; // use the sha3 256 of the json string repr for x platform use
        // Ok(sha3_256(data.as_ref()))

        let mut sha3 = Sha3::v256();

        for parent in self.parents.iter() {
            sha3.update(parent);
        }

        sha3.update(&self.amount.to_be_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }
}
