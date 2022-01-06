use crate::{
    Error, Hash, KeyImage, KeyManager, NodeSignature, PublicKey, PublicKeySet, Result, Signature,
};

use std::hash;
use serde::{Deserialize, Serialize};
use blstrs::G1Affine;

// #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
// pub struct SpendKey(pub PublicKey);
// pub struct SpendKey(pub KeyImage);

// Display Hash value as hex in Debug output.  consolidates 36 lines to 3 for pretty output
// and the hex value is the same as sn_dbc_mint display of DBC IDs.
// impl std::fmt::Debug for SpendKey {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_tuple("SpendKey")
//             .field(&hex::encode(self.0.to_bytes()))
//             .finish()
//     }
// }

// impl SpendKey {

//     // KeyImage = G1Projective
//     // G1Projective = blst_p1
//     // blst_p1 = blst_fp, blst_fp, blst_fp
//     // blst_fp = [limb_t; 6]
//     // limb_t = u64
//     // u64 = 8 bytes
//     // so: 8 * 6 * 3 = 144.
//     pub fn to_bytes(self) -> [u8; 144] {
//         self.0.to_bytes()
//     }
// }

/*
#[cfg(test)]
use rand::distributions::{Distribution, Standard};
#[cfg(test)]
use rand::Rng;

/// used when fuzzing DBC's in testing.
#[cfg(test)]
impl Distribution<SpendKey> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpendKey {
        SpendKey(
            crate::genesis_dbc_input()
                .0
                .derive_child(&rng.gen::<[u8; 32]>()),
        )
    }
}
*/

/// A share of a SpentProof, combine enough of these to form a
/// SpentProof.
// #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentProofShare {
    /// Signature from dbc.spend_key() over the transaction
    // pub spent_sig: Signature,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pks: PublicKeySet,

    pub spentbook_sig_share: NodeSignature,

    pub public_commitments: Vec<G1Affine>,
}

impl hash::Hash for SpentProofShare {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        // self.spent_sig.hash(state);
        self.spentbook_pks.hash(state);
        self.spentbook_sig_share.hash(state);
        // for pc in self.public_commitments.iter() {
        //     let bytes = pc.to_compressed();
        //     bytes.hash(state);
        // }
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

    /// Signature from KeyImage over the transaction, by client.
    // pub spent_sig: Signature,

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
        // unimplemented.

        // old
        // if !dbc.spend_key().0.verify(&self.spent_sig, tx) {
        //     return Err(Error::FailedSignature);
        // }  

        // new     
        // if !key_image.verify(&self.spent_sig, tx) {
        //     return Err(Error::FailedSignature);
        // }

        // let msg = Self::proof_msg(&tx, &self.spent_sig);
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
