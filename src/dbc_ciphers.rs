// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{dbc_id::PublicAddress, DerivationIndex, Hash};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DbcSecrets {
    /// This is the PublicAddress to which tokens are send. The PublicAddress may be published
    /// and multiple payments sent to this address by various parties.  It is useful for
    /// accepting donations, for example.
    ///
    /// The Dbc can only be spent by the party holding the MainKey that corresponds to the
    /// PublicAddress, ie the Dbc recipient.
    ///
    /// This PublicAddress is only a client/wallet concept. It is NOT actually used in the transaction
    /// and never seen by the spentbook nodes.
    ///
    /// The DbcId used in the transaction is derived from this PublicAddress using a random
    /// derivation index, which is stored in derivation_index.
    pub public_address: PublicAddress,

    /// This indicates which index to use when deriving the DbcId of the
    /// Dbc, from the PublicAddress.
    pub derivation_index: DerivationIndex,
}

/// Represents the Secrets of a Dbc.
impl From<(PublicAddress, DerivationIndex)> for DbcSecrets {
    // Create a new DbcSecrets for signing.
    fn from(params: (PublicAddress, DerivationIndex)) -> Self {
        let (public_address, derivation_index) = params;
        Self {
            public_address,
            derivation_index,
        }
    }
}

/// Represents the Secrets of a Dbc.
impl From<(&PublicAddress, &DerivationIndex)> for DbcSecrets {
    // Create a new DbcSecrets for signing.
    fn from(params: (&PublicAddress, &DerivationIndex)) -> Self {
        let (public_address, derivation_index) = params;

        Self {
            public_address: *public_address,
            derivation_index: *derivation_index,
        }
    }
}

impl DbcSecrets {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();
        bytes.extend(&self.public_address.to_bytes());
        bytes.extend(&self.derivation_index);
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
