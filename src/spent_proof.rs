// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    Commitment, Error, Hash, KeyImage, KeyManager, NodeSignature, PublicKey, PublicKeySet, Result,
    Signature,
};

use std::cmp::Ordering;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents the data to be signed by the SpentBook in a SpentProof.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentProofContent {
    /// KeyImage of input Dbc that this SpentProof is proving to be spent.
    pub key_image: KeyImage,

    /// Hash of transaction that input Dbc is being spent in.
    pub transaction_hash: Hash,

    /// public commitments for the transaction
    pub public_commitments: Vec<Commitment>,
}

impl SpentProofContent {
    /// represent this SpentProofContent as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(&self.key_image.to_bytes());
        bytes.extend(self.transaction_hash.as_ref());
        for pc in self.public_commitments.iter() {
            bytes.extend(&pc.to_compressed());
        }
        bytes
    }

    /// represent this SpentProofContent as a Hash
    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}

impl PartialOrd for SpentProofContent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SpentProofContent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_image.cmp(&other.key_image)
    }
}

/// A share of a SpentProof, combine enough of these to form a
/// SpentProof.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SpentProofShare {
    /// data to be signed
    pub content: SpentProofContent,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pks: PublicKeySet,
    pub spentbook_sig_share: NodeSignature,
}

// impl manually to avoid clippy complaint about Hash conflict.
impl PartialEq for SpentProofShare {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content
            && self.spentbook_pks == other.spentbook_pks
            && self.spentbook_sig_share == other.spentbook_sig_share
    }
}

impl Eq for SpentProofShare {}

impl std::hash::Hash for SpentProofShare {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = self.to_bytes();
        bytes.hash(state);
    }
}

impl SpentProofShare {
    /// get KeyImage of input Dbc
    pub fn key_image(&self) -> &KeyImage {
        &self.content.key_image
    }

    /// get transaction hash
    pub fn transaction_hash(&self) -> Hash {
        self.content.transaction_hash
    }

    /// get public commitments
    pub fn public_commitments(&self) -> &Vec<Commitment> {
        &self.content.public_commitments
    }

    /// get spentbook's signature share
    pub fn spentbook_sig_share(&self) -> &NodeSignature {
        &self.spentbook_sig_share
    }

    /// get spentbook's PublicKeySet
    pub fn spentbook_pks(&self) -> &PublicKeySet {
        &self.spentbook_pks
    }

    /// represent this SpentProofContent as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.content.to_bytes();

        bytes.extend(&self.spentbook_pks.to_bytes());
        bytes.extend(self.spentbook_sig_share.to_bytes());
        bytes
    }
}

/// SpentProof's are constructed when a DBC is logged to the spentbook.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpentProof {
    /// data to be signed
    pub content: SpentProofContent,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pub_key: PublicKey,

    /// The Spentbook's signature notarizing the DBC was spent.
    /// signing over SpentProofContent. (KeyImage, RingCtTransaction, and public_commitments).
    pub spentbook_sig: Signature,
}

impl SpentProof {
    /// get KeyImage of input Dbc
    pub fn key_image(&self) -> &KeyImage {
        &self.content.key_image
    }

    /// get transaction hash
    pub fn transaction_hash(&self) -> Hash {
        self.content.transaction_hash
    }

    /// get public commitments
    pub fn public_commitments(&self) -> &Vec<Commitment> {
        &self.content.public_commitments
    }

    /// represent this SpentProof as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(&self.content.to_bytes());
        bytes.extend(&self.spentbook_pub_key.to_bytes());
        bytes.extend(&self.spentbook_sig.to_bytes());

        bytes
    }

    /// verify this SpentProof
    ///
    /// checks that the input transaction hash matches the tx_hash that was
    /// signed by the spentbook and verifies that spentbook signature is
    /// valid for this SpentProof.
    ///
    /// note that the verifier must already hold (trust) the spentbook's public key.
    pub fn verify<K: KeyManager>(&self, tx_hash: Hash, verifier: &K) -> Result<()> {
        // verify input tx_hash matches our tx_hash which was signed by spentbook.
        if tx_hash != self.content.transaction_hash {
            return Err(Error::InvalidTransactionHash);
        }

        verifier
            .verify(
                &self.content.hash(),
                &self.spentbook_pub_key,
                &self.spentbook_sig,
            )
            .map_err(|_| Error::InvalidSpentProofSignature(*self.key_image()))?;
        Ok(())
    }
}
