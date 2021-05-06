// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeSet;

use tiny_keccak::{Hasher, Sha3};

use crate::{DbcContentHash, Hash};

/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbcTransaction {
    pub inputs: BTreeSet<DbcContentHash>,
    pub outputs: BTreeSet<DbcContentHash>,
}

impl DbcTransaction {
    pub fn new(inputs: BTreeSet<DbcContentHash>, outputs: BTreeSet<DbcContentHash>) -> Self {
        Self { inputs, outputs }
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();
        for input in self.inputs.iter() {
            sha3.update(input);
        }

        for output in self.outputs.iter() {
            sha3.update(output);
        }

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }
}

// 1. test that adding inputs / outputs in different order produces the same hash

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    use crate::sha3_256;

    #[quickcheck]
    fn prop_hash_is_independent_of_order(inputs: Vec<u64>, outputs: Vec<u64>) {
        // This test is here to protect us in the case that someone swaps out the BTreeSet for inputs/outputs for something else
        let input_hashes: Vec<DbcContentHash> =
            inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();
        let output_hashes: Vec<DbcContentHash> =
            outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

        let forward_hash = DbcTransaction::new(
            input_hashes.iter().cloned().collect(),
            output_hashes.iter().cloned().collect(),
        )
        .hash();

        let reverse_hash = DbcTransaction::new(
            input_hashes.into_iter().rev().collect(),
            output_hashes.into_iter().rev().collect(),
        )
        .hash();

        assert_eq!(forward_hash, reverse_hash);
    }
}
