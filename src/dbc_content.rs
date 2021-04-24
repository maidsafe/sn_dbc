#[derive(Serialize, Deserialize)]
struct DbcContent {
    parent: DbcContentHash, // Hash of parent DbcContent. Also used as a nonce
    owner: PubKey,          // Will be blinded by using Hash(Hash(PubKey + self.parent))
    amount: u64,
}

impl DbcContent {
    // Create a new DbcContent for signing, blind the owner from the mint
    pub fn new(parent: DbcContentHash, owner: PubKey, amount: u64) -> Self {
        let mut owner = owner;
        for _ in 0..amount {
            owner = sha3_256(&owner); // owner not visible to mint.
        }
        DbcContent {
            parent,
            owner,
            amount,
        }
    }
    fn hash(&self) -> DbcContentHash {
        let data = serde_json::to_string(&self); // use the sha3 256 of the json string repr for x platform use
        sha3_256(&data)
    }
}
