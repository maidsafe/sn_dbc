use serde_json::Error;

use crate::{sha3_256, DbcContentHash};

#[derive(Serialize, Deserialize)]
struct DbcContent {
    parent: DbcContentHash, // Hash of parent DbcContent. Also used as a nonce
    owner: PubKey,          // Will be blinded
    amount: u64,
}

impl DbcContent {
    // Create a new DbcContent for signing, blind the owner from the mint
    pub fn new(parent: DbcContentHash, owner: &PubKey, amount: u64) -> Self {
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
    fn hash(&self) -> Result<DbcContentHash, Error> {
        let data = serde_json::to_string(&self); // use the sha3 256 of the json string repr for x platform use
        Ok(sha3_256(&data))
    }
}
