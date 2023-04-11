// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, PublicKey, Result, RevealedAmount};
use blsttc::{serde_impl::SerdeSecret, Ciphertext, SecretKey, PK_SIZE};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::rand::{distributions::Standard, Rng, RngCore};

/// This is used to generate a new DbcId
/// from a PublicAddress, and the corresponding
/// DerivedKey from the MainKey of that PublicAddress.
pub type DerivationIndex = [u8; 32];

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DbcId(PublicKey);

impl DbcId {
    pub fn new<G: Into<PublicKey>>(public_key: G) -> Self {
        Self(public_key.into())
    }

    pub fn to_bytes(&self) -> [u8; blsttc::PK_SIZE] {
        self.0.to_bytes()
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &blsttc::Signature, msg: M) -> bool {
        self.0.verify(sig, msg)
    }

    pub fn encrypt(&self, revealed_amount: RevealedAmount) -> Ciphertext {
        self.0.encrypt(revealed_amount.to_bytes())
    }
}

/// This is the key that unlocks the value of a Dbc.
/// Holding this key gives you access to the tokens of the
/// Dbc with the corresponding DbcId.
/// Like with the keys to your house or a safe, this is not something you share publicly.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DerivedKey(SerdeSecret<SecretKey>);

impl DerivedKey {
    pub fn new<S: Into<SecretKey>>(secret_key: S) -> Self {
        Self(SerdeSecret(secret_key.into()))
    }

    /// This is the unique identifier of the Dbc that
    /// this instance of Dbc secret key unlocks.
    /// The Dbc does not exist until someone has sent tokens to it.
    pub fn dbc_id(&self) -> DbcId {
        DbcId(self.0.public_key())
    }

    pub(crate) fn decrypt(&self, ciphertext: &Ciphertext) -> Result<RevealedAmount> {
        let bytes = self
            .0
            .decrypt(ciphertext)
            .ok_or(Error::DecryptionBySecretKeyFailed)?;
        RevealedAmount::from_bytes_ref(&bytes)
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> blsttc::Signature {
        self.0.sign(msg)
    }
}

/// This is a source that a specific DbcId can be derived from,
/// since it contains a PublicAddress, and a specific derivation
/// index. This struct is also used as source of the derivation
/// index when encrypting the ciphers in the created Dbc.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone)]
pub struct DbcIdSource {
    ///
    pub public_address: PublicAddress,
    ///
    pub derivation_index: DerivationIndex,
}

impl DbcIdSource {
    /// The id of a new Dbc that is sent to the PublicAddress.
    /// The DbcId has a corresponding DerivedKey, which unlocks
    /// the value of the Dbc with that DbcId.
    pub fn dbc_id(&self) -> DbcId {
        self.public_address.new_dbc_id(&self.derivation_index)
    }
}

/// This is a public address to which tokens can be sent.
/// The tokens will be sent via a unique Dbc.
///
/// When someone wants to send tokens to this PublicAddress,
/// they generate the id of the Dbc - the DbcId - that shall hold the tokens.
/// The DbcId is generated from this PublicAddress, and only the sender
/// will at this point know that the DbcId is related to this PublicAddress.
/// When creating the Dbc using that DbcId, the sender will also encrypt the
/// DerivationIndex that was used to generate the DbcId, so that the recipient behind
/// the PublicAddress can also see that the DbcId is related to this PublicAddress.
/// The recipient can then use the received DerivationIndex to generate the DerivedKey
/// corresponding to that DbcId, and thus unlock the value of the Dbc by using that DerivedKey.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub struct PublicAddress(PublicKey);

impl PublicAddress {
    pub fn new(public_key: PublicKey) -> Self {
        Self(public_key)
    }

    /// A random derivation index and the public address.
    /// The random index will be used to derive a DbcId out of the public address.
    pub fn random_dbc_id_src(&self, rng: &mut impl RngCore) -> DbcIdSource {
        DbcIdSource {
            public_address: *self,
            derivation_index: random_derivation_index(rng),
        }
    }

    /// Generate a new DbcId from provided DerivationIndex.
    /// This is supposed to be a unique identifier of a Dbc.
    /// A new Dbc id is generated by someone who wants to send tokens to the PublicAddress.
    /// When they create the new Dbc they will use this id, but that only works if this id was never used before.
    pub fn new_dbc_id(&self, index: &DerivationIndex) -> DbcId {
        DbcId(self.0.derive_child(index))
    }

    /// To send tokens to this address, a derivation index is encrypted
    pub fn encrypt(&self, derivation_index: &DerivationIndex) -> Ciphertext {
        self.0.encrypt(derivation_index)
    }

    pub fn to_bytes(self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

/// A Dbc MainKey is held by anyone who wants to
/// send or receive tokens using Dbcs. It is held privately
/// and not shared with anyone.
///
/// The secret MainKey has a static PublicAddress, which
/// is shared with others in order to receive payments.
/// With this MainKey, new DerivedKey:DbcId pairs can be generated.
pub struct MainKey(SerdeSecret<SecretKey>);

impl MainKey {
    ///
    pub fn new(secret_key: SecretKey) -> Self {
        Self(SerdeSecret(secret_key))
    }

    /// This is the static public address which is shared with others, and
    /// to which payments can be made by getting a new unique identifier for a Dbc to be created.
    pub fn public_address(&self) -> PublicAddress {
        PublicAddress(self.0.public_key())
    }

    /// A random derivation index and the public address.
    /// The random index will be used to derive a DbcId out of the public address.
    pub fn random_dbc_id_src(&self, rng: &mut impl RngCore) -> DbcIdSource {
        DbcIdSource {
            public_address: self.public_address(),
            derivation_index: random_derivation_index(rng),
        }
    }

    /// Sign a message with the main key.
    pub fn sign(&self, msg: &[u8]) -> blsttc::Signature {
        self.0.sign(msg)
    }

    /// When someone wants to send tokens to the PublicAddress of this MainKey,
    /// they generate the id of the Dbc - the DbcId - that shall hold the tokens.
    /// The created Dbc contains the encrypted derivation index, that is decrypted using
    /// this MainKey instance.
    /// The index is then used to derive the key - the DerivedKey - corresponding to the DbcId of the
    /// Dbc sent to you. With that DerivedKey you will have access to the tokens in the Dbc.
    pub fn decrypt_index(&self, derivation_index_cipher: &Ciphertext) -> Result<DerivationIndex> {
        let bytes = self
            .0
            .decrypt(derivation_index_cipher)
            .ok_or(Error::DecryptionBySecretKeyFailed)?;

        let mut index = [0u8; 32];
        index.copy_from_slice(&bytes[0..32]);

        Ok(index)
    }

    /// Derive the key - the DerivedKey - corresponding to a DbcId
    /// which was also derived using the same DerivationIndex.
    ///
    /// When someone wants to send tokens to the PublicAddress of this MainKey,
    /// they generate the id of the Dbc - the DbcId - that shall hold the tokens.
    /// The recipient of the tokens, is the person/entity that holds this MainKey.
    ///
    /// The created Dbc contains the _encrypted_ form of the derivation index that was used to
    /// generate that very DbcId. The sender encrypted it so that no-one but the recipient of the
    /// tokens in the Dbc (and the sender itself of course) shall be able to see which index was used.
    /// This encrypted index is then decrypted by the recipient, using this MainKey instance (see `fn decrypt_index` above).
    ///
    /// When passing the resulting decrypted derivation index to this function (`fn derive_key`),
    /// a DerivedKey is generated corresponding to the DbcId. This DerivedKey can unlock the Dbc of that
    /// DbcId, thus giving access to the tokens it holds.
    /// By that, the recipient has received the tokens from the sender.
    pub fn derive_key(&self, index: &DerivationIndex) -> DerivedKey {
        DerivedKey::new(self.0.inner().derive_child(index))
    }

    /// Represent as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn random() -> Self {
        Self::new(blsttc::SecretKey::random())
    }

    /// Create a randomly generated MainKey.
    pub fn random_from_rng(rng: &mut impl RngCore) -> Self {
        let sk: SecretKey = rng.sample(Standard);
        Self::new(sk)
    }

    pub fn random_derived_key(&self, rng: &mut impl RngCore) -> DerivedKey {
        self.derive_key(&random_derivation_index(rng))
    }
}

// generates a random derivation index
pub fn random_derivation_index(rng: &mut impl RngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
