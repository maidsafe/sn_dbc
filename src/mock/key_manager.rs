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
    cache: HashSet<PublicKey>,
}

impl From<Signer> for KeyManager {
    fn from(signer: Signer) -> Self {
        let public_key_set = signer.public_key_set();
        let cache = HashSet::default();
        let mut key_manager = Self { signer, cache };
        key_manager.add_known_key(public_key_set.public_key());

        key_manager
    }
}

impl crate::SpentProofKeyVerifier for KeyManager {
    type Error = crate::Error;

    fn verify_known_key(&self, key: &PublicKey) -> Result<()> {
        if self.cache.contains(key) {
            Ok(())
        } else {
            Err(Error::UnrecognisedAuthority)
        }
    }
}

impl KeyManager {
    pub fn add_known_key(&mut self, key: PublicKey) {
        self.cache.insert(key);
    }

    pub fn public_key_set(&self) -> PublicKeySet {
        self.signer.public_key_set()
    }

    pub fn sign_with_child_key(&self, index: &[u8], tx_hash: &Hash) -> IndexedSignatureShare {
        let child_signer = self.signer.derive_child(index);
        IndexedSignatureShare::new(child_signer.index(), child_signer.sign(tx_hash))
    }

    pub fn sign(&self, msg_hash: &Hash) -> IndexedSignatureShare {
        IndexedSignatureShare::new(self.signer.index(), self.signer.sign(msg_hash))
    }
}
