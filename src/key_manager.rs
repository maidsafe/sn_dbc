// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Hash, Result};
use async_trait::async_trait;
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

#[async_trait]
pub trait Signer {
    async fn index(&self) -> Result<u64>;
    async fn public_key_set(&self) -> Result<PublicKeySet>;
    async fn sign<M: AsRef<[u8]> + Send>(&self, msg: M) -> Result<SignatureShare>;
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

#[async_trait]
impl Signer for ExposedSigner {
    async fn index(&self) -> Result<u64> {
        Ok(self.index)
    }

    async fn public_key_set(&self) -> Result<PublicKeySet> {
        Ok(self.public_key_set.clone())
    }

    async fn sign<M: AsRef<[u8]> + Send>(
        &self,
        msg: M,
    ) -> Result<threshold_crypto::SignatureShare> {
        Ok(self.secret_key_share.sign(msg))
    }
}

#[derive(Debug, Clone)]
pub struct KeyManager<S: Signer> {
    signer: S,
    genesis_key: PublicKey,
    cache: KeyCache,
}

impl<S: Signer> KeyManager<S> {
    pub async fn new(signer: S, genesis_key: PublicKey) -> Result<Self> {
        let public_key_set = signer.public_key_set().await?;
        let mut cache = KeyCache::default();
        cache.add_known_key(genesis_key);
        cache.add_known_key(public_key_set.public_key());
        Ok(Self {
            signer,
            genesis_key,
            cache,
        })
    }

    pub async fn verify_we_are_a_genesis_node(&self) -> Result<()> {
        if self.signer.public_key_set().await?.public_key() == self.genesis_key {
            Ok(())
        } else {
            Err(Error::NotGenesisNode)
        }
    }

    pub fn key_cache(&self) -> &KeyCache {
        &self.cache
    }

    pub async fn public_key_set(&self) -> Result<PublicKeySet> {
        self.signer.public_key_set().await
    }

    #[allow(clippy::eval_order_dependence)]
    pub async fn sign(&self, msg_hash: &Hash) -> Result<NodeSignature> {
        Ok(NodeSignature(
            self.signer.index().await?,
            self.signer.sign(msg_hash).await?,
        ))
    }

    pub fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        // NB: this can fail if self.signer changes keys..
        // then cache needs to be kept in sync with signer view of its current key
        self.cache.verify(msg_hash, key, signature)
    }
}
