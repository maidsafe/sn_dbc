use std::collections::HashSet;

use threshold_crypto::{SecretKeyShare, SignatureShare};

use crate::{Error, Hash, Result};

pub use threshold_crypto::{PublicKey, Signature};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSignature(usize, SignatureShare);

impl NodeSignature {
    pub fn threshold_crypto(&self) -> (usize, &SignatureShare) {
        (self.0, &self.1)
    }
}

#[derive(Debug, Default)]
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

#[derive(Debug)]
pub struct KeyManager {
    public_key: PublicKey,
    node_secret_key_share: (usize, SecretKeyShare),
    genesis: PublicKey,
    cache: KeyCache,
}

impl KeyManager {
    pub fn new(
        public_key: PublicKey,
        node_secret_key_share: (usize, SecretKeyShare),
        genesis: PublicKey,
    ) -> Self {
        let mut cache = KeyCache::default();
        cache.add_known_key(genesis);
        cache.add_known_key(public_key);
        Self {
            public_key,
            node_secret_key_share,
            genesis,
            cache,
        }
    }

    pub fn verify_we_are_a_genesis_node(&self) -> Result<()> {
        if self.public_key == self.genesis {
            Ok(())
        } else {
            Err(Error::NotGenesisNode)
        }
    }

    pub fn key_cache(&self) -> &KeyCache {
        &self.cache
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn sign(&self, msg_hash: &Hash) -> NodeSignature {
        NodeSignature(
            self.node_secret_key_share.0,
            self.node_secret_key_share.1.sign(msg_hash),
        )
    }

    pub fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify(msg_hash, key, signature)
    }
}
