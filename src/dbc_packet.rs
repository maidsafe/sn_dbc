// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{BlsHelper, Dbc, Error, PublicKey, Result};
use blsttc::SecretKeySet;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::Into;

/// Represents a public key and optional
/// secret key, plus a random derivation index.
#[derive(Clone, Deserialize, Serialize)]
pub struct DerivedKeySet {
    public_key: PublicKey,
    derivation_index: [u8; 32], // Todo: make this an Fr with new blsttc.

    #[serde(
        serialize_with = "serialize_option_sks",
        deserialize_with = "deserialize_option_sks"
    )]
    secret_key_set: Option<SecretKeySet>,
}

impl DerivedKeySet {
    /// public_key getter
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// derivation_index getter
    pub fn derivation_index(&self) -> &[u8; 32] {
        &self.derivation_index
    }

    /// secret_key_set getter
    pub fn secret_key_set(&self) -> &Option<SecretKeySet> {
        &self.secret_key_set
    }

    /// derives a public key
    pub fn derived_public_key(&self) -> PublicKey {
        self.public_key.derive_child(&self.derivation_index)
    }

    // generates a random derivation index
    fn random_derivation_index() -> [u8; 32] {
        rand::thread_rng().gen()
    }
}

impl From<PublicKey> for DerivedKeySet {
    /// construct a DerivedKeySet with random derivation index from a PublicKey
    fn from(public_key: PublicKey) -> Self {
        let derivation_index = Self::random_derivation_index();
        Self {
            public_key,
            derivation_index,
            secret_key_set: None,
        }
    }
}

impl From<SecretKeySet> for DerivedKeySet {
    /// construct a DerivedKeySet with random derivation index from a SecretKeySet
    fn from(secret_key_set: SecretKeySet) -> Self {
        Self {
            public_key: secret_key_set.public_keys().public_key(),
            derivation_index: Self::random_derivation_index(),
            secret_key_set: Some(secret_key_set),
        }
    }
}

/// Represents a DBC plus some metadata that is useful
/// for transporting DBCs between individuals, but is not
/// necessary for Mint operations.  As such, this is a
/// client-only struct that the payment sender would
/// create before passing to the recipient.
///
/// The MintNodes never use it.
///
/// When creating a DBC, the sender should start with
/// a well-known public_use_key provided by the recipient.
///
/// The sender then obtains DBC owner key via:
///   DerivedKeySet::from(well_known).derived_public_key().
///
/// The owner key is then passed into DbcContent::new().
///
/// After reissue, the client constructs the Dbc and then
/// puts it into a DbcPacket along with the DerivedKeySet
///
// #[derive(Clone, Deserialize, Serialize)]
#[derive(Clone)]
pub struct DbcPacket {
    dbc: Dbc,
    owner_keyset: DerivedKeySet,
}

impl DbcPacket {
    /// Create a new DbcPacket.
    /// validates that the DerivedKeySet matches the Dbc owner
    pub fn new(dbc: Dbc, owner_keyset: DerivedKeySet) -> Result<Self> {
        let dp = DbcPacket { dbc, owner_keyset };
        dp.verify_owner_derivation_index()?;
        Ok(dp)
    }

    fn verify_owner_derivation_index(&self) -> Result<()> {
        let derived_pk =
            BlsHelper::blsttc_to_blstrs_pubkey(&self.owner_keyset.derived_public_key());
        match self.dbc.owner() == derived_pk {
            true => Ok(()),
            false => Err(Error::DerivedOwnerKeyDoesNotMatch),
        }
    }

    /// dbc getter
    pub fn dbc(&self) -> &Dbc {
        &self.dbc
    }

    /// owner_keyset getter
    ///
    /// returns the DerivedKeySet representing the owner's
    /// reusable well-known key and a random (one-time)
    /// derivation index.
    pub fn owner_keyset(&self) -> &DerivedKeySet {
        &self.owner_keyset
    }
}

#[allow(clippy::from_over_into)]
impl Into<Dbc> for DbcPacket {
    fn into(self) -> Dbc {
        self.dbc
    }
}

// Serializes an Option<SecretKeySet>
fn serialize_option_sks<S>(input: &Option<SecretKeySet>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let o = input.as_ref().map(|sks| SecretKeySetWrapper(sks.clone()));
    o.serialize(s)
}

// Deserializes an Option<SecretKeySet>
fn deserialize_option_sks<'de, D>(deserializer: D) -> Result<Option<SecretKeySet>, D::Error>
where
    D: Deserializer<'de>,
{
    let o = Option::deserialize(deserializer)?;
    Ok(o.map(|SecretKeySetWrapper(sks)| sks))
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
