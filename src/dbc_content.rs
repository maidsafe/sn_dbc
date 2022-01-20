// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blstrs::group::GroupEncoding;
use blstrs::G1Affine;
use blsttc::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{BlsHelper, Hash};

// note: Amount should move into blst_ringct crate.
// (or else blst_ringct::RevealedCommitment should be made generic over Amount type)

pub type Amount = u64;
pub type OwnerPublicKey = G1Affine;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct DbcContent {
    pub owner: OwnerPublicKey, // Todo: what should this type be?
}

/// Represents the content of a DBC.
impl From<OwnerPublicKey> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(owner: OwnerPublicKey) -> Self {
        Self { owner }
    }
}

impl From<PublicKey> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(pubkey: PublicKey) -> Self {
        let owner = BlsHelper::blsttc_to_blstrs_pubkey(&pubkey);
        Self { owner }
    }
}

// impl From<(OwnerPublicKey, AmountSecrets)> for DbcContent {
//     // Create a new DbcContent for signing.
//     fn from(params: (OwnerPublicKey, AmountSecrets)) -> Self {
//         let (owner, amount_secrets) = params;
//         let pubkey = BlsHelper::blstrs_to_blsttc_pubkey(&owner);
//         let amount_secrets_cipher = pubkey.encrypt(&amount_secrets.to_bytes());

//         Self {
//             owner,
//             amount_secrets_cipher,
//         }
//     }
// }

// impl From<(PublicKey, AmountSecrets)> for DbcContent {
//     // Create a new DbcContent for signing.
//     fn from(params: (PublicKey, AmountSecrets)) -> Self {
//         let (pubkey, amount_secrets) = params;
//         let amount_secrets_cipher = pubkey.encrypt(&amount_secrets.to_bytes());
//         let owner = BlsHelper::blsttc_to_blstrs_pubkey(&pubkey);

//         Self {
//             owner,
//             amount_secrets_cipher,
//         }
//     }
// }

impl DbcContent {
    pub fn hash(&self) -> Hash {
        Hash::hash(self.owner.to_bytes().as_ref())
    }
}
