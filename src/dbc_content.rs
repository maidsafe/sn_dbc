// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// use blsttc::PublicKey;
use blstrs::group::GroupEncoding;
use blstrs::G1Affine;
use serde::{Deserialize, Serialize};
// use tiny_keccak::{Hasher, Sha3};

use crate::Hash;

// note: Amount should move into blst_ringct crate.
// (or else blst_ringct::RevealedCommitment should be made generic over Amount type)

pub type Amount = u64;
pub type OwnerPublicKey = G1Affine;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    // pub owner: PublicKey,
    pub owner: OwnerPublicKey, // Todo: what should this type be?
}

/// Represents the content of a DBC.
impl From<OwnerPublicKey> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(owner: OwnerPublicKey) -> Self {
        Self { owner }
    }
}

impl DbcContent {
    pub fn hash(&self) -> Hash {
        Hash::hash(self.owner.to_bytes().as_ref())
    }
}
