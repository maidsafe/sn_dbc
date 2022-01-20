// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{AmountSecrets, BlsHelper, Dbc, Error, PublicKey, Result};
use blsttc::{PublicKeySet, SecretKeySet};
use rand8::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::Into;
use std::fmt;

/// Represents a base secret key_set, plus a random derivation index.
#[derive(Clone, Deserialize, Serialize)]
pub struct DerivedSecretKeySet {
    #[serde(serialize_with = "serialize_sks", deserialize_with = "deserialize_sks")]
    secret_key_set: SecretKeySet,
    derivation_index: [u8; 32], // Todo: make this an Fr with new blsttc.
}

impl fmt::Debug for DerivedSecretKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.secret_key_set.poly())
            .field(&self.derivation_index)
            .finish()
    }
}

impl DerivedSecretKeySet {
    /// base public_key
    pub fn base_public_key(&self) -> PublicKey {
        self.secret_key_set.public_keys().public_key()
    }

    /// base secret_key_set getter
    pub fn base_secret_key_set(&self) -> &SecretKeySet {
        &self.secret_key_set
    }

    pub fn derive(&self) -> SecretKeySet {
        self.secret_key_set.derive_child(&self.derivation_index)
    }

    /// derivation_index getter
    pub fn derivation_index(&self) -> &[u8; 32] {
        &self.derivation_index
    }

    // generates a random derivation index
    fn random_derivation_index(mut rng: impl RngCore) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// construct a DerivedKeySet with random derivation index from a SecretKeySet
    pub fn from_secret_key_set(secret_key_set: SecretKeySet, mut rng: impl RngCore) -> Self {
        Self {
            secret_key_set,
            derivation_index: Self::random_derivation_index(&mut rng),
        }
    }
}

/// Represents a base secret key_set, plus a random derivation index.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DerivedPublicKeySet {
    public_key_set: PublicKeySet,
    derivation_index: [u8; 32], // Todo: make this an Fr with new blsttc.
}

impl DerivedPublicKeySet {
    /// base public_key
    pub fn base_public_key(&self) -> PublicKey {
        self.public_key_set.public_key()
    }

    /// base public_key set
    pub fn base_public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    pub fn derive(&self) -> PublicKeySet {
        self.public_key_set.derive_child(&self.derivation_index)
    }

    /// derivation_index getter
    pub fn derivation_index(&self) -> &[u8; 32] {
        &self.derivation_index
    }

    // generates a random derivation index
    fn random_derivation_index(mut rng: impl RngCore) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// construct a DerivedKeySet with random derivation index from a SecretKeySet
    pub fn from_public_key_set(public_key_set: PublicKeySet, mut rng: impl RngCore) -> Self {
        Self {
            public_key_set,
            derivation_index: Self::random_derivation_index(&mut rng),
        }
    }
}

/// Represents a public key and optional
/// secret key, plus a random derivation index.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DerivedPublicKey {
    public_key: PublicKey,
    derivation_index: [u8; 32], // Todo: make this an Fr with new blsttc.
}

impl DerivedPublicKey {
    /// base public_key getter
    pub fn base_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn derive(&self) -> PublicKey {
        self.public_key.derive_child(&self.derivation_index)
    }

    /// derivation_index getter
    pub fn derivation_index(&self) -> &[u8; 32] {
        &self.derivation_index
    }

    // generates a random derivation index
    fn random_derivation_index(mut rng: impl RngCore) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// construct a DerivedKeySet with random derivation index from a PublicKey
    pub fn from_public_key(public_key: PublicKey, mut rng: impl RngCore) -> Self {
        let derivation_index = Self::random_derivation_index(&mut rng);
        Self {
            public_key,
            derivation_index,
        }
    }
}

#[derive(Clone, Debug)]
pub enum DerivedOwner {
    SecretKeySet(DerivedSecretKeySet),
    PublicKeySet(DerivedPublicKeySet),
    PublicKey(DerivedPublicKey),
}

impl From<DerivedSecretKeySet> for DerivedOwner {
    fn from(d: DerivedSecretKeySet) -> Self {
        Self::SecretKeySet(d)
    }
}

impl From<DerivedPublicKeySet> for DerivedOwner {
    fn from(d: DerivedPublicKeySet) -> Self {
        Self::PublicKeySet(d)
    }
}

impl From<DerivedPublicKey> for DerivedOwner {
    fn from(d: DerivedPublicKey) -> Self {
        Self::PublicKey(d)
    }
}

impl DerivedOwner {
    pub fn derive_public_key(&self) -> PublicKey {
        match self {
            Self::SecretKeySet(sks) => sks.derive().public_keys().public_key(),
            Self::PublicKeySet(pks) => pks.derive().public_key(),
            Self::PublicKey(pk) => pk.derive(),
        }
    }

    pub fn derive_public_key_set(&self) -> Option<PublicKeySet> {
        match self {
            Self::SecretKeySet(sks) => Some(sks.derive().public_keys()),
            Self::PublicKeySet(pks) => Some(pks.derive()),
            Self::PublicKey(_) => None,
        }
    }

    pub fn derive_secret_key_set(&self) -> Option<SecretKeySet> {
        match self {
            Self::SecretKeySet(sks) => Some(sks.derive()),
            Self::PublicKeySet(_sks) => None,
            Self::PublicKey(_pk) => None,
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
///   DerivedKeySet::from(well_known).derive_public_key().
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
    derived_owner: DerivedOwner,
    amount_secrets: AmountSecrets,
}

impl DbcPacket {
    /// Create a new DbcPacket.
    /// validates that the DerivedKeySet matches the Dbc owner
    // pub fn new(dbc: Dbc, owner_keyset: DerivedKeySet, amount_secrets_cipher: Ciphertext) -> Result<Self> {
    //     let dp = DbcPacket { dbc, owner_keyset, amount_secrets_cipher };
    //     dp.verify_owner_derivation_index()?;
    //     Ok(dp)
    // }

    pub fn verify_owner_derivation_index(&self) -> Result<()> {
        let derived_pk =
            BlsHelper::blsttc_to_blstrs_pubkey(&self.derived_owner.derive_public_key());
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
    pub fn derived_owner(&self) -> &DerivedOwner {
        &self.derived_owner
    }

    /// amount_secrets_cipher getter
    pub fn amount_secrets(&self) -> &AmountSecrets {
        &self.amount_secrets
    }

    // pub fn from_secrets(dbc: Dbc, owner: impl Into<DerivedOwner>, amount_secrets: AmountSecrets) -> Self {
    //     Self {
    //         dbc,
    //         derived_owner: owner.into(),
    //         amount_secrets,
    //     }
    // }
}

impl From<(Dbc, DerivedOwner, AmountSecrets)> for DbcPacket {
    fn from(params: (Dbc, DerivedOwner, AmountSecrets)) -> Self {
        let (dbc, derived_owner, amount_secrets) = params;
        Self {
            dbc,
            derived_owner,
            amount_secrets,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Dbc> for DbcPacket {
    fn into(self) -> Dbc {
        self.dbc
    }
}

#[allow(clippy::from_over_into)]
impl Into<AmountSecrets> for DbcPacket {
    fn into(self) -> AmountSecrets {
        self.amount_secrets
    }
}

// Serializes an Option<SecretKeySet>
// fn serialize_sks<S>(input: &Option<SecretKeySet>, s: S) -> Result<S::Ok, S::Error>
fn serialize_sks<S>(input: &SecretKeySet, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let w = SecretKeySetWrapper(input.clone());
    w.serialize(s)
    // let o = input.as_ref().map(|sks| SecretKeySetWrapper(sks.clone()));
    // o.serialize(s)
}

// Deserializes an Option<SecretKeySet>
// fn deserialize_option_sks<'de, D>(deserializer: D) -> Result<Option<SecretKeySet>, D::Error>
fn deserialize_sks<'de, D>(deserializer: D) -> Result<SecretKeySet, D::Error>
where
    D: Deserializer<'de>,
{
    let w = SecretKeySetWrapper::deserialize(deserializer)?;
    Ok(w.0)
    // let o = Option::deserialize(deserializer)?;
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
