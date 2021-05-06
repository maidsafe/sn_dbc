use std::collections::HashSet;

use ed25519::{Keypair, PublicKey as EdPublicKey, Signature as EdSignature, Signer, Verifier};
use tiny_keccak::{Hasher, Sha3};

use crate::{Error, Hash, Result};

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(pub(crate) EdPublicKey);

#[derive(Debug, Clone, Copy)]
pub struct Signature(pub(crate) EdSignature);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for Signature {}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state)
    }
}

impl PublicKey {
    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.ed().to_bytes());

        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        hash
    }

    pub fn ed(&self) -> EdPublicKey {
        self.0
    }
}

impl Signature {
    pub fn ed(&self) -> EdSignature {
        self.0
    }
}

pub fn ed25519_keypair() -> Keypair {
    Keypair::generate(&mut rand::thread_rng())
}

#[derive(Default)]
pub struct KeyCache(HashSet<PublicKey>);

impl KeyCache {
    pub fn verify(&self, msg: &Hash, key: &PublicKey, sig: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        key.0.verify(msg, &sig.0)?;
        Ok(())
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

#[derive(Debug, Clone)]
pub struct ChainNode {
    mint_key: PublicKey,
    prev_mint_sig: Signature,
}

pub struct KeyManager {
    keypair: Keypair,
    genesis: PublicKey,
    chain: Vec<ChainNode>,
    cache: KeyCache,
}

impl KeyManager {
    pub fn new(keypair: Keypair, genesis: PublicKey) -> Self {
        let mut cache = KeyCache::default();
        cache.add_known_key(genesis);
        Self {
            keypair,
            genesis,
            chain: Vec::default(),
            cache,
        }
    }

    pub fn generate(genesis: PublicKey) -> Self {
        Self::new(ed25519_keypair(), genesis)
    }

    pub fn new_genesis() -> Self {
        let keypair = ed25519_keypair();
        let genesis = PublicKey(keypair.public);
        Self::new(keypair, genesis)
    }

    pub fn key_cache(&self) -> &KeyCache {
        &self.cache
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.keypair.public)
    }

    pub fn sign(&self, msg_hash: &Hash) -> Signature {
        Signature(self.keypair.sign(msg_hash))
    }

    pub fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.cache.verify_known_key(key)?;
        key.ed().verify(msg_hash, &signature.ed())?;
        Ok(())
    }

    pub fn prove_authority(&self) -> &[ChainNode] {
        &self.chain
    }

    pub fn process_chain(&mut self, chain: &[ChainNode]) -> Result<()> {
        let adjacent_pairs = std::iter::once(&self.genesis)
            .chain(chain.iter().map(|n| &n.mint_key))
            .zip(chain.iter());

        for (prev_mint_key, successor_mint) in adjacent_pairs {
            prev_mint_key.ed().verify(
                &successor_mint.mint_key.hash(),
                &successor_mint.prev_mint_sig.ed(),
            )?;
            self.cache.add_known_key(successor_mint.mint_key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck_macros::quickcheck;

    #[test]
    fn test_empty_chain_processing() {
        let mut genesis_key_mgr = KeyManager::new_genesis();
        assert!(genesis_key_mgr.process_chain(&[]).is_ok());
    }

    #[quickcheck]
    #[ignore]
    fn prop_processing_chain_makes_chain_keys_known() {
        todo!();
    }
}
