// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, PublicKey, Result};
use blsttc::{serde_impl::SerdeSecret, SecretKey};
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use rand::distributions::Standard;
use rand::Rng;

pub type DerivationIndex = [u8; 32];

/// Represents a Dbc owner.
///
/// If the type is SecretKey, the Dbc is considered
/// to be bearer (anyone in possession can spend).
///
/// If the type is PublicKey, the Dbc is considered
/// to be owned (by whoever holds the SecretKey).
///
/// Dbc's have both a base Owner and a one-time-use Owner.
///
/// The base Owner public key is given out to other people
/// in order to receive payments from them. It is never
/// seen by the SpentBook.
///
/// The one-time-use Owner public key is not normally given
/// to 3rd parties. It is used by SpentBook exactly
/// once, when spending the associated Dbc.
///
/// See OwnerOnce which relates the two.
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
    /// returns PublicKey
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::SecretKey(sk) => sk.public_key(),
            Self::PublicKey(pk) => *pk,
        }
    }

    /// returns SecretKey
    pub fn secret_key(&self) -> Result<SecretKey> {
        match self {
            Self::SecretKey(sk) => Ok(sk.inner().clone()),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    /// derives new Owner from provided DerivationIndex
    pub fn derive(&self, i: &DerivationIndex) -> Self {
        match self {
            Self::SecretKey(sk) => Self::from(sk.inner().derive_child(i)),
            Self::PublicKey(pk) => Self::from(pk.derive_child(i)),
        }
    }

    /// convert Owner to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::SecretKey(sk) => sk.to_bytes().to_vec(),
            Self::PublicKey(pk) => pk.to_bytes().to_vec(),
        }
    }

    /// returns true if secret key is available
    pub fn has_secret_key(&self) -> bool {
        match self {
            Self::SecretKey(_) => true,
            Self::PublicKey(_) => false,
        }
    }

    /// create Owner from a randomly generated SecretKey
    pub fn from_random_secret_key(rng: &mut impl rand::RngCore) -> Self {
        let sk: SecretKey = rng.sample(Standard);
        Self::from(sk)
    }
}

impl From<OwnerOnce> for Owner {
    fn from(o: OwnerOnce) -> Self {
        o.as_owner()
    }
}

/// Represents a one-time-use Owner key(pair).
///
/// The one-time-use Owner key(pair) is derived from a reusable
/// base Owner key(pair) using the DerivationIndex.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct OwnerOnce {
    pub owner_base: Owner,
    pub derivation_index: DerivationIndex,
}

impl OwnerOnce {
    /// returns the base Owner
    pub fn owner_base(&self) -> &Owner {
        &self.owner_base
    }

    /// derives a one-time-user Owner from base Owner
    pub fn as_owner(&self) -> Owner {
        self.owner_base.derive(&self.derivation_index)
    }

    /// create OwnerOnce from a base Owner
    pub fn from_owner_base(owner_base: Owner, rng: &mut impl rand::RngCore) -> Self {
        Self {
            owner_base,
            derivation_index: Self::random_derivation_index(rng),
        }
    }

    // generates a random derivation index
    pub(crate) fn random_derivation_index(rng: &mut impl rand::RngCore) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}
