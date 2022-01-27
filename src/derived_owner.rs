// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, PublicKey, Result};
use blsttc::{PublicKeySet, SecretKey, SecretKeySet};
// use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use rand::distributions::Standard;
use rand::Rng;

pub type DerivationIndex = [u8; 32];

// #[derive(Clone, Deserialize, Serialize)]
#[derive(Clone)]
pub enum OwnerBase {
    // #[serde(serialize_with = "serialize_sks", deserialize_with = "deserialize_sks")]
    SecretKeySet(SecretKeySet),
    SecretKey(SecretKey),
    PublicKeySet(PublicKeySet),
    PublicKey(PublicKey),
}

impl fmt::Debug for OwnerBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("");

        match self {
            Self::SecretKeySet(sks) => f.field(&sks.poly()),
            Self::SecretKey(sk) => f.field(sk),
            Self::PublicKeySet(pks) => f.field(pks),
            Self::PublicKey(pk) => f.field(pk),
        };

        f.finish()
    }
}

impl From<SecretKeySet> for OwnerBase {
    fn from(s: SecretKeySet) -> Self {
        Self::SecretKeySet(s)
    }
}

impl From<SecretKey> for OwnerBase {
    fn from(s: SecretKey) -> Self {
        Self::SecretKey(s)
    }
}

impl From<PublicKeySet> for OwnerBase {
    fn from(p: PublicKeySet) -> Self {
        Self::PublicKeySet(p)
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
            (Self::SecretKeySet(a), Self::SecretKeySet(b)) => a == b,
            (Self::SecretKey(a), Self::SecretKey(b)) => a == b,
            (Self::PublicKeySet(a), Self::PublicKeySet(b)) => a == b,
            (Self::PublicKey(a), Self::PublicKey(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for OwnerBase {}

impl OwnerBase {
    pub fn base_public_key(&self) -> PublicKey {
        match self {
            Self::SecretKeySet(sks) => sks.public_keys().public_key(),
            Self::SecretKey(sk) => sk.public_key(),
            Self::PublicKeySet(pks) => pks.public_key(),
            Self::PublicKey(pk) => *pk,
        }
    }

    pub fn base_public_key_set(&self) -> Result<PublicKeySet> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.public_keys()),
            Self::SecretKey(_sk) => Err(Error::SecretKeyUnavailable),
            Self::PublicKeySet(pks) => Ok(pks.clone()),
            Self::PublicKey(_) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn base_secret_key_set(&self) -> Result<SecretKeySet> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.clone()),
            Self::SecretKey(_sk) => Err(Error::SecretKeyUnavailable),
            Self::PublicKeySet(_sks) => Err(Error::SecretKeyUnavailable),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn base_secret_key(&self) -> Result<SecretKey> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.secret_key()),
            Self::SecretKey(sk) => Ok(sk.clone()),
            Self::PublicKeySet(_sks) => Err(Error::SecretKeyUnavailable),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn derive_public_key(&self, i: &DerivationIndex) -> PublicKey {
        match self {
            Self::SecretKeySet(sks) => sks.derive_child(i).public_keys().public_key(),
            Self::SecretKey(sk) => sk.derive_child(i).public_key(),
            Self::PublicKeySet(pks) => pks.derive_child(i).public_key(),
            Self::PublicKey(pk) => pk.derive_child(i),
        }
    }

    pub fn derive_public_key_set(&self, i: &DerivationIndex) -> Result<PublicKeySet> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.derive_child(i).public_keys()),
            Self::SecretKey(_) => Err(Error::SecretKeyUnavailable),
            Self::PublicKeySet(pks) => Ok(pks.derive_child(i)),
            Self::PublicKey(_) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn derive_secret_key_set(&self, i: &DerivationIndex) -> Result<SecretKeySet> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.derive_child(i)),
            Self::SecretKey(_sk) => Err(Error::SecretKeyUnavailable),
            Self::PublicKeySet(_sks) => Err(Error::SecretKeyUnavailable),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn derive_secret_key(&self, i: &DerivationIndex) -> Result<SecretKey> {
        match self {
            Self::SecretKeySet(sks) => Ok(sks.derive_child(i).secret_key()),
            Self::SecretKey(sk) => Ok(sk.derive_child(i)),
            Self::PublicKeySet(_sks) => Err(Error::SecretKeyUnavailable),
            Self::PublicKey(_pk) => Err(Error::SecretKeyUnavailable),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::SecretKeySet(sks) => sks.to_bytes(),
            Self::SecretKey(sk) => sk.to_bytes().to_vec(),
            Self::PublicKeySet(pks) => pks.to_bytes(),
            Self::PublicKey(pk) => pk.to_bytes().to_vec(),
        }
    }

    pub fn has_secret_key(&self) -> bool {
        match self {
            Self::SecretKeySet(_) => true,
            Self::SecretKey(_) => true,
            Self::PublicKeySet(_) => false,
            Self::PublicKey(_) => false,
        }
    }

    pub fn is_multisig(&self) -> bool {
        match self {
            Self::SecretKeySet(_) => true,
            Self::SecretKey(_) => false,
            Self::PublicKeySet(_) => true,
            Self::PublicKey(_) => false,
        }
    }

    pub fn from_random_secret_key(mut rng: impl rand::RngCore) -> Self {
        let sk: SecretKey = rng.sample(Standard);
        Self::SecretKey(sk)
    }
}

/*
// Serializes an Result<SecretKeySet>
// fn serialize_sks<S>(input: &Result<SecretKeySet>, s: S) -> Result<S::Ok, S::Error>
fn serialize_sks<S>(input: &SecretKeySet, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let w = SecretKeySetWrapper(input.clone());
    w.serialize(s)
    // let o = input.as_ref().map(|sks| SecretKeySetWrapper(sks.clone()));
    // o.serialize(s)
}

// Deserializes an Result<SecretKeySet>
// fn deserialize_option_sks<'de, D>(deserializer: D) -> Result<Result<SecretKeySet>, D::Error>
fn deserialize_sks<'de, D>(deserializer: D) -> Result<SecretKeySet, D::Error>
where
    D: Deserializer<'de>,
{
    let w = SecretKeySetWrapper::deserialize(deserializer)?;
    Ok(w.0)
    // let o = Result::deserialize(deserializer)?;
    // Ok(o.map(|SecretKeySetWrapper(sks)| sks))
}

// A wrapper struct for (de)-serializing a SecretKeySet
#[derive(Serialize, Deserialize)]
struct SecretKeySetWrapper(
    #[serde(
        serialize_with = "SecretKeySetWrapper::serialize_sks",
        deserialize_with = "SecretKeySetWrapper::deserialize_sks"
    )]
    SecretKeySet,
);

impl SecretKeySetWrapper {
    // serialize a SecretKeySet
    fn serialize_sks<S>(sks: &SecretKeySet, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(&sks.to_bytes())
    }

    // deserialize a SecretKeySet
    fn deserialize_sks<'de, D>(deserializer: D) -> Result<SecretKeySet, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        let vbytes = Vec::<u8>::deserialize(deserializer)?;
        let sks = SecretKeySet::from_bytes(vbytes).map_err(|e| Error::custom(e.to_string()))?;
        Ok(sks)
    }
}
*/

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
