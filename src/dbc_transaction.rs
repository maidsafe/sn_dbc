// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Hash, PublicKey, SpendKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tiny_keccak::{Hasher, Sha3};

/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct DbcTransaction {
    pub inputs: BTreeSet<SpendKey>,
    pub outputs: BTreeSet<PublicKey>,
}

impl DbcTransaction {
    pub fn new(inputs: BTreeSet<SpendKey>, outputs: BTreeSet<PublicKey>) -> Self {
        Self { inputs, outputs }
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();
        for input in self.inputs.iter() {
            sha3.update(&input.0.to_bytes());
        }

        for output in self.outputs.iter() {
            sha3.update(&output.to_bytes());
        }

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }
}

// 1. test that adding inputs / outputs in different order produces the same hash

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnerKey;
    use quickcheck_macros::quickcheck;
    use std::iter::FromIterator;

    #[quickcheck]
    fn prop_hash_is_independent_of_order(inputs: Vec<u64>, outputs: Vec<u64>) {
        // This test is here to protect us in the case that someone swaps out the BTreeSet for inputs/outputs for something else
        let input_keys = Vec::from_iter(inputs.iter().map(|_| rand::random::<SpendKey>()));
        let output_keys = Vec::from_iter(outputs.iter().map(|_| rand::random::<OwnerKey>().0));

        let forward_hash = DbcTransaction::new(
            input_keys.iter().cloned().collect(),
            output_keys.iter().cloned().collect(),
        )
        .hash();

        let reverse_hash = DbcTransaction::new(
            input_keys.into_iter().rev().collect(),
            output_keys.into_iter().rev().collect(),
        )
        .hash();

        assert_eq!(forward_hash, reverse_hash);
    }
}
