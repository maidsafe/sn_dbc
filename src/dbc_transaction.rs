// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Denomination, Hash, Result, SpendKey};
use blsbs::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use tiny_keccak::{Hasher, Sha3};

/// A DbcEnvelope can be thought of as an Envelope
/// with an amount written on the outside specifying
/// the desired amount.  This tells the mint
/// which key to sign with.  The amount for each
/// DbcEnvelope is constrained/checked by reissue rule:
///  sum(inputs) must equal sum(outputs)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbcEnvelope {
    pub envelope: Envelope,
    pub denomination: Denomination,
}

impl DbcEnvelope {
    pub fn amount(&self) -> crate::Amount {
        self.denomination.amount()
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.envelope.to_bytes());
        sha3.update(&self.denomination.to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b: Vec<u8> = vec![];
        b.extend(self.envelope.to_bytes());
        b.extend(self.denomination.to_bytes());
        b
    }

    pub fn from_bytes(bytes: [u8; 98]) -> Result<Self> {
        let mut e: [u8; 96] = [0; 96];
        e.copy_from_slice(&bytes[0..96]);
        let envelope = Envelope::from(e);

        let denomination = Denomination::from_bytes(&bytes[96..])?;

        Ok(Self {
            envelope,
            denomination,
        })
    }
}

/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DbcTransaction {
    pub inputs: BTreeSet<SpendKey>,
    pub outputs: HashSet<DbcEnvelope>,
}

impl DbcTransaction {
    pub fn new(inputs: BTreeSet<SpendKey>, outputs: HashSet<DbcEnvelope>) -> Self {
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
/*
#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use std::iter::FromIterator;

    #[quickcheck]
    fn prop_hash_is_independent_of_order(inputs: Vec<u64>, outputs: Vec<u64>) {
        // This test is here to protect us in the case that someone swaps out the BTreeSet for inputs/outputs for something else
        let input_keys = Vec::from_iter(inputs.iter().map(|_| rand::random::<SpendKey>()));
        let output_keys = Vec::from_iter(outputs.iter().map(|_| rand::random::<SpendKey>().0));

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
*/
