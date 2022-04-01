// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Hash, IndexedSignatureShare, Result};
use blsttc::{serde_impl::SerdeSecret, SecretKeyShare};
pub use blsttc::{PublicKey, PublicKeySet, Signature};
use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Signer {
    public_key_set: PublicKeySet,
    secret_key_share: (u64, SerdeSecret<SecretKeyShare>),
}

impl From<(PublicKeySet, SecretKeyShare, usize)> for Signer {
    fn from(outcome: (PublicKeySet, SecretKeyShare, usize)) -> Self {
        Self {
            public_key_set: outcome.0,
            secret_key_share: (outcome.2 as u64, SerdeSecret(outcome.1)),
        }
    }
}

impl Signer {
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
pub struct KeyManager {
    signer: Signer,
    cache: Keys,
}

impl From<Signer> for KeyManager {
    fn from(signer: Signer) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = Keys::default();
        cache.add_known_key(public_key_set.public_key());
        Self { signer, cache }
    }
}

impl crate::KeyManager for KeyManager {
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
