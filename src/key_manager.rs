// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Hash, Result};
use blsttc::SignatureShare;
pub use blsttc::{PublicKey, PublicKeySet, Signature};

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
