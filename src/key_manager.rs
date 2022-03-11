// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Hash, Result};
use blsttc::{serde_impl::SerdeSecret, SecretKeyShare, SignatureShare};
pub use blsttc::{PublicKey, PublicKeySet, Signature};
use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct IndexedSignatureShare {
    index: u64,
    signature_share: SignatureShare,
}

impl IndexedSignatureShare {
    pub fn new(index: u64, signature_share: SignatureShare) -> Self {
        Self {
            index,
            signature_share,
        }
    }

    pub fn threshold_crypto(&self) -> (u64, &SignatureShare) {
        (self.index, &self.signature_share)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.index.to_le_bytes().to_vec();
        bytes.extend(&self.signature_share.to_bytes());
        bytes
    }
}

pub trait KeyManager {
    type Error: std::error::Error;
    fn add_known_key(&mut self, key: PublicKey) -> Result<(), Self::Error>;
    fn sign_with_child_key(
        &self,
        idx: &[u8],
        tx_hash: &Hash,
    ) -> Result<IndexedSignatureShare, Self::Error>;
    fn sign(&self, msg_hash: &Hash) -> Result<IndexedSignatureShare, Self::Error>;
    fn public_key_set(&self) -> Result<PublicKeySet, Self::Error>;
    fn verify(
        &self,
        msg_hash: &Hash,
        key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Self::Error>;
    fn verify_known_key(&self, key: &PublicKey) -> Result<(), Self::Error>;
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SimpleSigner {
    public_key_set: PublicKeySet,
    secret_key_share: (u64, SerdeSecret<SecretKeyShare>),
}

#[cfg(feature = "dkg")]
impl From<bls_dkg::outcome::Outcome> for SimpleSigner {
    fn from(outcome: bls_dkg::outcome::Outcome) -> Self {
        Self {
            public_key_set: outcome.public_key_set,
            secret_key_share: (outcome.index as u64, SerdeSecret(outcome.secret_key_share)),
        }
    }
}

impl SimpleSigner {
    pub fn new(public_key_set: PublicKeySet, secret_key_share: (u64, SecretKeyShare)) -> Self {
        Self {
            public_key_set,
            secret_key_share: (secret_key_share.0, SerdeSecret(secret_key_share.1)),
        }
    }

    fn index(&self) -> u64 {
        self.secret_key_share.0
    }

    fn public_key_set(&self) -> PublicKeySet {
        self.public_key_set.clone()
    }

    fn sign<M: AsRef<[u8]>>(&self, msg: M) -> blsttc::SignatureShare {
        self.secret_key_share.1.sign(msg)
    }

    fn derive_child(&self, index: &[u8]) -> Self {
        let child_pks = self.public_key_set.derive_child(index);
        let child_secret_index = self.secret_key_share.0;
        let child_secret_share = self.secret_key_share.1.derive_child(index);

        Self::new(child_pks, (child_secret_index, child_secret_share))
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SimpleKeyManager {
    signer: SimpleSigner,
    cache: Keys,
}

impl From<SimpleSigner> for SimpleKeyManager {
    fn from(signer: SimpleSigner) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = Keys::default();
        cache.add_known_key(public_key_set.public_key());
        Self { signer, cache }
    }
}

impl KeyManager for SimpleKeyManager {
    type Error = crate::Error;

    fn add_known_key(&mut self, key: PublicKey) -> Result<()> {
        self.cache.add_known_key(key);
        Ok(())
    }

    fn public_key_set(&self) -> Result<PublicKeySet> {
        Ok(self.signer.public_key_set())
    }

    fn sign_with_child_key(&self, index: &[u8], tx_hash: &Hash) -> Result<IndexedSignatureShare> {
        let child_signer = self.signer.derive_child(index);
        Ok(IndexedSignatureShare::new(
            child_signer.index(),
            child_signer.sign(tx_hash),
        ))
    }

    fn sign(&self, msg_hash: &Hash) -> Result<IndexedSignatureShare> {
        Ok(IndexedSignatureShare::new(
            self.signer.index(),
            self.signer.sign(msg_hash),
        ))
    }

    fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify(msg_hash, key, signature)
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        self.cache.verify_known_key(key)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone)]
struct Keys(HashSet<PublicKey>);

impl From<Vec<PublicKey>> for Keys {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self(keys.into_iter().collect())
    }
}

impl Keys {
    pub fn add_known_key(&mut self, key: PublicKey) {
        self.0.insert(key);
    }

    fn verify(&self, msg: &Hash, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        if key.verify(sig, msg) {
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        if self.0.contains(key) {
            Ok(())
        } else {
            Err(Error::UnrecognisedAuthority)
        }
    }
}
