// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{AmountSecrets, DerivationIndex, OwnerBase};
use blstrs::G1Affine;
use blsttc::{Ciphertext, PublicKey, SecretKey};
// use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

use crate::{Error, Hash, Result};

// note: Amount should move into blst_ringct crate.
// (or else blst_ringct::RevealedCommitment should be made generic over Amount type)

pub type Amount = u64;
pub type OwnerPublicKey = G1Affine;

// #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DbcContent {
    pub owner: OwnerBase,
    pub owner_derivation_cipher: Ciphertext,
    pub amount_secrets_cipher: Ciphertext,
}

/// Represents the content of a DBC.
impl From<(OwnerBase, Ciphertext, Ciphertext)> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(params: (OwnerBase, Ciphertext, Ciphertext)) -> Self {
        let (owner, owner_derivation_cipher, amount_secrets_cipher) = params;
        Self {
            owner,
            owner_derivation_cipher,
            amount_secrets_cipher,
        }
    }
}

/// Represents the content of a DBC.
impl From<(OwnerBase, DerivationIndex, AmountSecrets)> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(params: (OwnerBase, DerivationIndex, AmountSecrets)) -> Self {
        let (owner, derivation_index, amount_secrets) = params;

        let owner_derivation_cipher = owner.base_public_key().encrypt(&derivation_index);
        let amount_secrets_cipher = owner
            .derive_public_key(&derivation_index)
            .encrypt(&amount_secrets.to_bytes());

        Self {
            owner,
            owner_derivation_cipher,
            amount_secrets_cipher,
        }
    }
}

impl DbcContent {
    pub fn derive_owner(&self, base_sk: &SecretKey) -> Result<PublicKey> {
        let bytes = base_sk
            .decrypt(&self.owner_derivation_cipher)
            .ok_or(Error::DecryptionBySecretKeyFailed)?;

        assert_eq!(bytes.len(), 32);

        let mut idx = [0u8; 32];
        idx.copy_from_slice(&bytes[0..32]);
        Ok(self.owner.derive_public_key(&idx))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(&self.owner.to_bytes());
        bytes.extend(&self.owner_derivation_cipher.to_bytes());
        bytes.extend(&self.amount_secrets_cipher.to_bytes());

        bytes
    }

    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.to_bytes());

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        Hash::hash(&hash)
    }
}
