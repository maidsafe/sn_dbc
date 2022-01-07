use crate::{
    Error, Hash, KeyImage, KeyManager, NodeSignature, PublicKey, PublicKeySet, Result, Signature,
};

use std::hash;
use serde::{Deserialize, Serialize};
use blstrs::G1Affine;

/// A share of a SpentProof, combine enough of these to form a
/// SpentProof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentProofShare {
    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pks: PublicKeySet,

    pub spentbook_sig_share: NodeSignature,

    pub public_commitments: Vec<G1Affine>,
}

impl hash::Hash for SpentProofShare {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentProof {
    pub index: usize,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pub_key: PublicKey,

    /// The Spentbook's signature notarizing the DBC was spent.
    /// signing over RingCtTransaction, spent_sig, and public_commitments.
    pub spentbook_sig: Signature,

    pub public_commitments: Vec<G1Affine>,
}

impl SpentProof {
    pub fn validate<K: KeyManager>(
        &self,
        key_image: KeyImage,
        tx: Hash,
        verifier: &K,
    ) -> Result<()> {
        let msg = Self::proof_msg(&tx);
        verifier
            .verify(&msg, &self.spentbook_pub_key, &self.spentbook_sig)
            .map_err(|_| Error::InvalidSpentProofSignature(key_image))?;
        Ok(())
    }

    pub fn proof_msg(tx: &Hash) -> Hash {
        use tiny_keccak::{Hasher, Sha3};
        let mut sha3 = Sha3::v256();

        sha3.update(&tx.0);

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }
}
