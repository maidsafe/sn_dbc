// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use tiny_keccak::{Hasher, Sha3};
/// These typdefs are to simplify algorithm for now and will be removed for production.
pub(crate) type Hash = [u8; 32];
pub(crate) type PubKey = [u8; 32]; // tmp
pub(crate) type Signature = [u8; 32]; // tmp
pub(crate) type DbcContentHash = [u8; 32];
pub(crate) type DbcSpentHash = [u8; 32];
mod dbc;
mod dbc_content;
mod dbc_transaction;
mod error;
mod mint;
mod threshold_crypto;
mod vecmap;
mod vecset;

pub use crate::{
    dbc::Dbc,
    dbc_content::DbcContent,
    dbc_transaction::DbcTransaction,
    error::{Error, Result},
    vecmap::VecMap,
    vecset::VecSet,
};

fn sha3_256(input: &[u8]) -> Hash {
    let mut sha3 = Sha3::v256();
    let mut output = [0; 32];
    sha3.update(input);
    sha3.finalize(&mut output);
    output
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

    #[test]
    fn create_dbc() {
        let parent = [0; 32];
        let owner = [0; 32];
        let amount = 1000;
        let content = DbcContent::new(parent, owner, amount);
        let transaction = DbcTransaction {
            inputs: vec![[0; 32]].into_iter().collect(),
            outputs: vec![[0; 32]].into_iter().collect(),
        };
        // let dbc = Dbc {
        //     content,
        //     transaction,
        //     mint_key: [0; 32],
        //     mint_sig: [0; 32],
        // };
    }
}
