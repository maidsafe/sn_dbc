use std::collections::HashSet;

use ed25519::{Keypair, PublicKey as EdPublicKey, Signature as EdSignature, Signer, Verifier};
use tiny_keccak::{Hasher, Sha3};

use crate::{Error, Hash, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(EdPublicKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(EdSignature);

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state)
    }
}

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

pub type KeyCache = HashSet<PublicKey>;

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
        Self {
            keypair,
            genesis,
            chain: Vec::new(),
            cache: KeyCache::new(),
        }
    }

    pub fn new_genesis() -> Self {
        let keypair = ed25519_keypair();
        let genesis = PublicKey(keypair.public);
        Self::new(keypair, genesis)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.keypair.public)
    }

    pub fn sign(&self, msg_hash: &Hash) -> Signature {
        Signature(self.keypair.sign(msg_hash))
    }

    pub fn verify(&self, msg_hash: &Hash, key: &PublicKey, signature: &Signature) -> Result<()> {
        self.verify_known_key(key)?;
        key.ed().verify(msg_hash, &signature.ed())?;
        Ok(())
    }

    pub fn prove_authority(&self) -> &[ChainNode] {
        &self.chain
    }

    pub fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        if self.cache.contains(key) {
            Ok(())
        } else {
            Err(Error::UnrecognisedAuthority)
        }
    }

    pub fn verify_and_cache_chain(&mut self, chain: &[ChainNode]) -> Result<()> {
        let adjacent_pairs = std::iter::once(&self.genesis)
            .chain(chain.iter().map(|n| &n.mint_key))
            .zip(chain.iter());

        for (prev_mint_key, successor_mint) in adjacent_pairs {
            prev_mint_key.ed().verify(
                &successor_mint.mint_key.hash(),
                &successor_mint.prev_mint_sig.ed(),
            )?;
            self.cache.insert(successor_mint.mint_key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck_macros::quickcheck;
    use std::collections::BTreeSet;

    #[test]
    fn test_empty_chain_processing() {
        let genesis_key_mgr = KeyManager::new_genesis();
        assert!(genesis_key_mgr.process_chain(&[]).is_ok());
    }

    #[quickcheck]
    fn prop_after_processing_chain_all_keys_are_known() {
        todo!();
    }
}
