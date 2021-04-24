// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{sha3_256, DbcContentHash, Error, PubKey, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DbcContent {
    pub parent: DbcContentHash, // Hash of parent DbcContent. Also used as a nonce
    pub owner: PubKey,          // Will be blinded
    pub amount: u64,
}

impl DbcContent {
    // Create a new DbcContent for signing, blind the owner from the mint
    pub fn new(parent: DbcContentHash, owner: PubKey, amount: u64) -> Self {
        let mut owner = owner;
        for _ in 0..amount % 1000 {
            owner = sha3_256(&owner); // owner not visible to mint, until out_dbc is minted.
        }
        DbcContent {
            parent,
            owner,
            amount,
        }
    }

    fn hash(&self) -> Result<DbcContentHash> {
        let data = serde_json::to_string(&self).map_err(Error::JsonSerialisation)?; // use the sha3 256 of the json string repr for x platform use
        Ok(sha3_256(data.as_ref()))
    }
}
