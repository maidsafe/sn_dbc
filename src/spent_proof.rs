use crate::{
    Dbc, Error, Hash, KeyManager, NodeSignature, PublicKey, PublicKeySet, Result, Signature,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpendKey(pub PublicKey);

// Display Hash value as hex in Debug output.  consolidates 36 lines to 3 for pretty output
// and the hex value is the same as sn_dbc_mint display of DBC IDs.
impl std::fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SpendKey")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

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

/// A share of a SpentProof, combine enough of these to form a
/// SpentProof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpentProofShare {
    /// Signature from dbc.spend_key() over the transaction
    pub spend_sig: Signature,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pks: PublicKeySet,

    pub spentbook_sig_share: NodeSignature,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpentProof {
    /// Signature from dbc.spend_key() over the transaction
    pub spend_sig: Signature,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pub_key: PublicKey,

    /// The Spentbook's signature notarizing the DBC was spent.
    pub spentbook_sig: Signature,
}

impl SpentProof {
    pub fn validate<K: KeyManager>(&self, dbc: &Dbc, tx: Hash, verifier: &K) -> Result<()> {
        if !dbc.spend_key().0.verify(&self.spend_sig, tx) {
            return Err(Error::FailedSignature);
        }
        let msg = Self::proof_msg(&tx, &self.spend_sig);
        verifier
            .verify(&msg, &self.spentbook_pub_key, &self.spentbook_sig)
            .map_err(|_| Error::InvalidSpentProofSignature(dbc.spend_key()))?;
        Ok(())
    }

    pub fn proof_msg(tx: &Hash, spend_sig: &Signature) -> Hash {
        use tiny_keccak::{Hasher, Sha3};
        let mut sha3 = Sha3::v256();

        sha3.update(&tx.0);
        sha3.update(&spend_sig.to_bytes());

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        Hash(hash)
    }
}
