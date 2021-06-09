// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Hash, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
pub use threshold_crypto::{PublicKey, PublicKeySet, Signature};
use threshold_crypto::{SecretKeyShare, SignatureShare};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeSignature(u64, SignatureShare);

impl NodeSignature {
    pub fn threshold_crypto(&self) -> (u64, &SignatureShare) {
        (self.0, &self.1)
    }
}

#[derive(Debug, Default, Clone)]
pub struct KeyCache(HashSet<PublicKey>);

impl KeyCache {
    pub fn verify(&self, msg: &Hash, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        if key.verify(&sig, msg) {
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    pub fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        if self.0.contains(key) {
            Ok(())
        } else {
            Err(Error::UnrecognisedAuthority)
        }
    }

    pub fn add_known_key(&mut self, key: PublicKey) {
        self.0.insert(key);
    }
}

impl From<Vec<PublicKey>> for KeyCache {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self(keys.into_iter().collect())
    }
}

pub trait Signer {
    fn index(&self) -> u64;
    fn public_key_set(&self) -> PublicKeySet;
    fn sign<M: AsRef<[u8]>>(&self, msg: M) -> SignatureShare;
}

pub struct ExposedSigner {
    index: u64,
    public_key_set: PublicKeySet,
    secret_key_share: SecretKeyShare,
}

impl ExposedSigner {
    pub fn new(index: u64, public_key_set: PublicKeySet, secret_key_share: SecretKeyShare) -> Self {
        Self {
            index,
            public_key_set,
            secret_key_share,
        }
    }
}

impl Signer for ExposedSigner {
    fn index(&self) -> u64 {
        self.index
    }

    fn public_key_set(&self) -> PublicKeySet {
        self.public_key_set.clone()
    }

    fn sign<M: AsRef<[u8]>>(&self, msg: M) -> threshold_crypto::SignatureShare {
        self.secret_key_share.sign(msg)
    }
}

#[derive(Debug, Clone)]
pub struct KeyManager<S: Signer> {
    signer: S,
    genesis_key: PublicKey,
    cache: KeyCache,
}

impl<S: Signer> KeyManager<S> {
    pub fn new(signer: S, genesis_key: PublicKey) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = KeyCache::default();
        cache.add_known_key(genesis_key);
        cache.add_known_key(public_key_set.public_key());
        Self {
            signer,
            genesis_key,
            cache,
        }
    }

    pub fn verify_we_are_a_genesis_node(&self) -> Result<()> {
        if self.signer.public_key_set().public_key() == self.genesis_key {
            Ok(())
        } else {
            Err(Error::NotGenesisNode)
        }
    }

    pub fn key_cache(&self) -> &KeyCache {
        &self.cache
    }

    pub fn public_key_set(&self) -> PublicKeySet {
        self.signer.public_key_set()
    }

    pub fn sign(&self, msg_hash: &Hash) -> NodeSignature {
        NodeSignature(self.signer.index(), self.signer.sign(msg_hash))
    }

    pub fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        // NB: this can fail if self.signer changes keys..
        // then cache needs to be kept in sync with signer view of its current key
        self.cache.verify(msg_hash, key, signature)
    }
}
