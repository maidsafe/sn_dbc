// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Hash, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use threshold_crypto::{serde_impl::SerdeSecret, SecretKeyShare, SignatureShare};
pub use threshold_crypto::{PublicKey, PublicKeySet, Signature};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeSignature(u64, SignatureShare);

impl NodeSignature {
    pub fn threshold_crypto(&self) -> (u64, &SignatureShare) {
        (self.0, &self.1)
    }
}

pub trait KeyManager {
    fn sign(&self, msg_hash: &Hash) -> NodeSignature;
    fn verify_we_are_a_genesis_node(&self) -> Result<()>;
    fn public_key_set(&self) -> PublicKeySet;
    fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()>;
    fn verify_known_key(&self, key: &PublicKey) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct Verifier<K: KeyManager> {
    key_manager: Arc<K>,
}

impl<K: KeyManager> Verifier<K> {
    pub fn new(key_manager: Arc<K>) -> Self {
        Self { key_manager }
    }

    pub fn verify(&self, msg: &Hash, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.key_manager.verify(msg, key, sig)
    }

    pub fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        self.key_manager.verify_known_key(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSigner {
    public_key_set: PublicKeySet,
    secret_key_share: (u64, SerdeSecret<SecretKeyShare>),
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

    fn sign<M: AsRef<[u8]>>(&self, msg: M) -> threshold_crypto::SignatureShare {
        self.secret_key_share.1.sign(msg)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleKeyManager {
    signer: SimpleSigner,
    genesis_key: PublicKey,
    cache: Keys,
}

impl SimpleKeyManager {
    pub fn new(signer: SimpleSigner, genesis_key: PublicKey) -> Self {
        let public_key_set = signer.public_key_set();
        let mut cache = Keys::default();
        cache.add_known_key(genesis_key);
        cache.add_known_key(public_key_set.public_key());
        Self {
            signer,
            genesis_key,
            cache,
        }
    }
}

impl KeyManager for SimpleKeyManager {
    fn verify_we_are_a_genesis_node(&self) -> Result<()> {
        if self.signer.public_key_set().public_key() == self.genesis_key {
            Ok(())
        } else {
            Err(Error::NotGenesisNode)
        }
    }

    fn public_key_set(&self) -> PublicKeySet {
        self.signer.public_key_set()
    }

    fn sign(&self, msg_hash: &Hash) -> NodeSignature {
        NodeSignature(self.signer.index(), self.signer.sign(msg_hash))
    }

    fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify(msg_hash, key, signature)
    }

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        self.cache.verify_known_key(key)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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
        if key.verify(&sig, msg) {
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
