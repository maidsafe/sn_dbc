// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, PublicKey, Result};
use blsttc::SecretKey;
// use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use rand::distributions::Standard;
use rand::Rng;

pub type DerivationIndex = [u8; 32];

// #[derive(Clone, Deserialize, Serialize)]
#[derive(Clone)]
pub enum OwnerBase {
    SecretKey(SecretKey),
    PublicKey(PublicKey),
}

impl fmt::Debug for OwnerBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("");

        match self {
            Self::SecretKey(sk) => f.field(sk),
            Self::PublicKey(pk) => f.field(pk),
        };

        f.finish()
    }
}

impl From<SecretKey> for OwnerBase {
    fn from(s: SecretKey) -> Self {
        Self::SecretKey(s)
    }
}

impl From<PublicKey> for OwnerBase {
    fn from(p: PublicKey) -> Self {
        Self::PublicKey(p)
    }
}

impl PartialEq for OwnerBase {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SecretKey(a), Self::SecretKey(b)) => a == b,
            (Self::PublicKey(a), Self::PublicKey(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for OwnerBase {}

impl OwnerBase {
    pub fn base_public_key(&self) -> PublicKey {
        match self {
            Self::SecretKey(sk) => sk.public_key(),
            Self::PublicKey(pk) => *pk,
        }
    }

    pub fn base_secret_key(&self) -> Result<SecretKey> {
        match self {
            Self::SecretKey(sk) => Ok(sk.clone()),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn derive_public_key(&self, i: &DerivationIndex) -> PublicKey {
        match self {
            Self::SecretKey(sk) => sk.derive_child(i).public_key(),
            Self::PublicKey(pk) => pk.derive_child(i),
        }
    }

    pub fn derive_secret_key(&self, i: &DerivationIndex) -> Result<SecretKey> {
        match self {
            Self::SecretKey(sk) => Ok(sk.derive_child(i)),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::SecretKey(sk) => sk.to_bytes().to_vec(),
            Self::PublicKey(pk) => pk.to_bytes().to_vec(),
        }
    }

    pub fn has_secret_key(&self) -> bool {
        match self {
            Self::SecretKey(_) => true,
            Self::PublicKey(_) => false,
        }
    }

    pub fn from_random_secret_key(mut rng: impl rand::RngCore) -> Self {
        let sk: SecretKey = rng.sample(Standard);
        Self::SecretKey(sk)
    }
}

// #[derive(Clone, Debug, Deserialize, Serialize)]
#[derive(Clone, Debug)]
pub struct DerivedOwner {
    pub owner_base: OwnerBase,
    pub derivation_index: DerivationIndex,
}

impl DerivedOwner {
    pub fn base_public_key(&self) -> PublicKey {
        self.owner_base.base_public_key()
    }

    pub fn base_secret_key(&self) -> Result<SecretKey> {
        self.owner_base.base_secret_key()
    }

    pub fn derive_public_key(&self) -> PublicKey {
        self.owner_base.derive_public_key(&self.derivation_index)
    }

    pub fn derive_secret_key(&self) -> Result<SecretKey> {
        self.owner_base.derive_secret_key(&self.derivation_index)
    }

    pub fn from_owner_base(owner_base: OwnerBase, mut rng: impl rand8::RngCore) -> Self {
        Self {
            owner_base,
            derivation_index: Self::random_derivation_index(&mut rng),
        }
    }

    // generates a random derivation index
    pub(crate) fn random_derivation_index(mut rng: impl rand8::RngCore) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}
