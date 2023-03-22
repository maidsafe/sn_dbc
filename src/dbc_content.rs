// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blsttc::{Ciphertext, SecretKey};
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{DerivationIndex, Owner, RevealedAmount};
use crate::{Error, Hash, Result};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DbcContent {
    /// This is the owner's well-known key.  owner_base.public_key() may be published
    /// and multiple payments sent to this key by various parties.  It is useful for
    /// accepting donations, for example.
    ///
    /// The SecretKey may or not be present.  If it is present, then the Dbc is considered
    /// ownerless (aka bearer) and may be spent by anyone in possession of it.
    ///
    /// When the SecretKey is not present, then the Dbc can only be spent by the party
    /// holding the SecretKey, ie the Dbc recipient that generated the PublicKey.
    ///
    /// This key is only a client/wallet concept. It is NOT actually used in the transaction
    /// and never seen by the Spentbook.
    ///
    /// The "real" key used in the transaction is derived from this key using a random
    /// derivation index, which is stored (encrypted) in owner_derivation_cipher.
    pub owner_base: Owner,

    /// This indicates which index to use when deriving the publicly visible owner key of the
    /// Dbc, from the hidden owner key, i.e. the owner base.
    ///
    /// This index is stored in encrypted form, and is encrypted to `owner_base.public_key()`.
    /// So the true owner is unknown to anyone not in posession of `owner_base.secret_key()`.
    pub owner_derivation_cipher: Ciphertext,

    /// This is the RevealedAmount encypted to the derived public key,
    /// which can be obtained via:
    ///   self.owner_base.derive(
    ///     self.owner_base.secret_key().decrypt(self.owner_derivation.cipher()
    ///   ).public_key()
    pub revealed_amount_cipher: Ciphertext,
}

/// Represents the content of a DBC.
impl From<(Owner, Ciphertext, Ciphertext)> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(params: (Owner, Ciphertext, Ciphertext)) -> Self {
        let (owner_base, owner_derivation_cipher, revealed_amount_cipher) = params;
        Self {
            owner_base,
            owner_derivation_cipher,
            revealed_amount_cipher,
        }
    }
}

/// Represents the content of a DBC.
impl From<(Owner, DerivationIndex, RevealedAmount)> for DbcContent {
    // Create a new DbcContent for signing.
    fn from(params: (Owner, DerivationIndex, RevealedAmount)) -> Self {
        let (owner_base, derivation_index, revealed_amount) = params;

        let owner_derivation_cipher = owner_base.public_key().encrypt(derivation_index);
        let revealed_amount_cipher = owner_base
            .derive(&derivation_index)
            .public_key()
            .encrypt(revealed_amount.to_bytes());

        Self {
            owner_base,
            owner_derivation_cipher,
            revealed_amount_cipher,
        }
    }
}

impl DbcContent {
    pub(crate) fn derivation_index(&self, base_sk: &SecretKey) -> Result<DerivationIndex> {
        let bytes = base_sk
            .decrypt(&self.owner_derivation_cipher)
            .ok_or(Error::DecryptionBySecretKeyFailed)?;

        assert_eq!(bytes.len(), 32);

        let mut idx = [0u8; 32];
        idx.copy_from_slice(&bytes[0..32]);
        Ok(idx)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(&self.owner_base.to_bytes());
        bytes.extend(&self.owner_derivation_cipher.to_bytes());
        bytes.extend(&self.revealed_amount_cipher.to_bytes());

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
