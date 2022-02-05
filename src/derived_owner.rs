// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{BlsHelper, Error, PublicKey, PublicKeyBlst, Result, SecretKeyBlst};
use blsttc::{serde_impl::SerdeSecret, SecretKey};
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use rand::distributions::Standard;
use rand::Rng;

pub type DerivationIndex = [u8; 32];

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub enum Owner {
    SecretKey(SerdeSecret<SecretKey>),
    PublicKey(PublicKey),
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("");

        match self {
            Self::SecretKey(sk) => f.field(sk),
            Self::PublicKey(pk) => f.field(pk),
        };

        f.finish()
    }
}

impl From<SecretKey> for Owner {
    fn from(s: SecretKey) -> Self {
        Self::SecretKey(SerdeSecret(s))
    }
}

impl From<PublicKey> for Owner {
    fn from(p: PublicKey) -> Self {
        Self::PublicKey(p)
    }
}

impl PartialEq for Owner {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SecretKey(a), Self::SecretKey(b)) => a == b,
            (Self::PublicKey(a), Self::PublicKey(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Owner {}

impl Owner {
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::SecretKey(sk) => sk.public_key(),
            Self::PublicKey(pk) => *pk,
        }
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        match self {
            Self::SecretKey(sk) => Ok(sk.inner().clone()),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn derive(&self, i: &DerivationIndex) -> Self {
        match self {
            Self::SecretKey(sk) => Self::from(sk.inner().derive_child(i)),
            Self::PublicKey(pk) => Self::from(pk.derive_child(i)),
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
        Self::from(sk)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct DerivedOwner {
    pub owner_base: Owner,
    pub derivation_index: DerivationIndex,
}

impl DerivedOwner {
    pub fn derive(&self) -> Owner {
        self.owner_base.derive(&self.derivation_index)
    }

    pub fn base_public_key(&self) -> PublicKey {
        self.owner_base.public_key()
    }

    pub fn base_secret_key(&self) -> Result<SecretKey> {
        self.owner_base.secret_key()
    }

    pub fn derive_public_key(&self) -> PublicKey {
        self.owner_base.derive(&self.derivation_index).public_key()
    }

    pub fn derive_secret_key(&self) -> Result<SecretKey> {
        self.owner_base.derive(&self.derivation_index).secret_key()
    }

    /// returns owner BLST PublicKey derived from owner base PublicKey
    // note: can go away once blsttc integrated with blst_ringct.
    pub fn derive_public_key_blst(&self) -> PublicKeyBlst {
        BlsHelper::blsttc_to_blstrs_public_key(&self.derive_public_key())
    }

    /// returns owner BLST SecretKey derived from owner base SecretKey, if available.
    // note: can go away once blsttc integrated with blst_ringct.
    pub fn derive_secret_key_blst(&self) -> Result<SecretKeyBlst> {
        Ok(BlsHelper::blsttc_to_blstrs_secret_key(
            self.derive_secret_key()?,
        ))
    }

    pub fn from_owner_base(owner_base: Owner, mut rng: impl rand8::RngCore) -> Self {
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
