use crate::{
    Commitment, Error, Hash, KeyImage, KeyManager, NodeSignature, PublicKey, PublicKeySet, Result,
    Signature,
};

use std::cmp::Ordering;
use std::hash;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A share of a SpentProof, combine enough of these to form a
/// SpentProof.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SpentProofShare {
    pub key_image: KeyImage,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pks: PublicKeySet,

    pub spentbook_sig_share: NodeSignature,

    pub public_commitments: Vec<Commitment>,
}

impl PartialEq for SpentProofShare {
    fn eq(&self, other: &Self) -> bool {
        self.spentbook_pks == other.spentbook_pks
            && self.spentbook_sig_share == other.spentbook_sig_share
            && self.public_commitments == other.public_commitments
    }
}

impl Eq for SpentProofShare {}

impl hash::Hash for SpentProofShare {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key_image.hash(state);
        self.spentbook_pks.hash(state);
        self.spentbook_sig_share.hash(state);
        for pc in self.public_commitments.iter() {
            let bytes = pc.to_compressed();
            bytes.hash(state);
        }
    }
}

impl SpentProofShare {
    pub fn spentbook_sig_share(&self) -> &NodeSignature {
        &self.spentbook_sig_share
    }

    pub fn spentbook_pks(&self) -> &PublicKeySet {
        &self.spentbook_pks
    }

    pub fn spentbook_public_key(&self) -> PublicKey {
        self.spentbook_pks.public_key()
    }
}

/// SpentProof's are constructed when a DBC is logged to the spentbook.
// #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentProof {
    pub key_image: KeyImage,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pub_key: PublicKey,

    /// The Spentbook's signature notarizing the DBC was spent.
    /// signing over RingCtTransaction, spent_sig, and public_commitments.
    pub spentbook_sig: Signature,

    pub public_commitments: Vec<Commitment>,
}

impl SpentProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(&self.key_image.to_bytes());
        bytes.extend(&self.spentbook_sig.to_bytes());

        for pc in self.public_commitments.iter() {
            bytes.extend(&pc.to_compressed());
        }
        bytes
    }

    pub fn validate<K: KeyManager>(&self, tx: Hash, verifier: &K) -> Result<()> {
        verifier
            .verify(&tx, &self.spentbook_pub_key, &self.spentbook_sig)
            .map_err(|_| Error::InvalidSpentProofSignature(self.key_image.clone()))?;
        Ok(())
    }
}

impl PartialOrd for SpentProof {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SpentProof {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_image.cmp(&other.key_image)
    }
}
