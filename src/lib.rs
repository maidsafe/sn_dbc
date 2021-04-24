use serde::{Deserialize, Serialize};
use serde_json::Result;
use tiny_keccak::{Hasher, Sha3};
/// These typdefs are to simplify algorithm for now and will be removed for production.
pub(crate) type Hash = [u8; 32];
pub(crate) type PubKey = [u8; 32]; // tmp
pub(crate) type DbcContentHash = [u8; 32];
pub(crate) type DbcSpentHash = [u8; 32];
mod dbc;

fn sha3_256(input: &[u8]) -> Hash {
    let mut sha3 = Sha3::v256();
    let mut output = [0; 32];
    sha3.update(input);
    sha3.finalize(&mut output);
    output
}

/// This is the content of a DBC, it is unique as the parent hash is included
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

/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
struct DbcSpent {
    input: DbcContentHash,
    output: Vec<DbcContentHash>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash() {
        let data = b"hello world";
        let expected = b"\
    \x64\x4b\xcc\x7e\x56\x43\x73\x04\x09\x99\xaa\xc8\x9e\x76\x22\xf3\
    \xca\x71\xfb\xa1\xd9\x72\xfd\x94\xa3\x1c\x3b\xfb\xf2\x4e\x39\x38\
";
        assert_eq!(sha3_256(data), *expected);
    }
}
