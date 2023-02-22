// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Commitment, Error, Hash, PublicKey, PublicKeySet, Result, Signature, SignatureShare};

use std::cmp::Ordering;

use custom_debug::Debug;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents the data to be signed by the SpentBook in a SpentProof.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentProofContent {
    /// PublicKey of input Dbc that this SpentProof is proving to be spent.
    pub public_key: PublicKey,

    /// Hash of transaction that input Dbc is being spent in.
    pub transaction_hash: Hash,

    /// Reason why this DBC was spent
    pub reason: Hash,

    #[debug(skip)]
    /// public commitment for the transaction
    pub public_commitment: Commitment,
}

impl SpentProofContent {
    /// represent this SpentProofContent as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(self.public_key.to_bytes());
        bytes.extend(self.transaction_hash.as_ref());
        bytes.extend(self.reason.as_ref());
        bytes.extend(self.public_commitment.compress().to_bytes());
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
        self.public_key.cmp(&other.public_key)
    }
}

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
        bytes.extend(self.signature_share.to_bytes());
        bytes
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
    pub spentbook_sig_share: IndexedSignatureShare,
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
    /// get PublicKey of input Dbc
    pub fn public_key(&self) -> &PublicKey {
        &self.content.public_key
    }

    /// get transaction hash
    pub fn transaction_hash(&self) -> Hash {
        self.content.transaction_hash
    }

    /// get reason
    pub fn reason(&self) -> Hash {
        self.content.reason
    }

    /// get public commitments
    pub fn public_commitment(&self) -> &Commitment {
        &self.content.public_commitment
    }

    /// get spentbook's signature share
    pub fn spentbook_sig_share(&self) -> &IndexedSignatureShare {
        &self.spentbook_sig_share
    }

    /// get spentbook's PublicKeySet
    pub fn spentbook_pks(&self) -> &PublicKeySet {
        &self.spentbook_pks
    }

    /// represent this SpentProofShare as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.content.to_bytes();

        bytes.extend(&self.spentbook_pks.to_bytes());
        bytes.extend(self.spentbook_sig_share.to_bytes());
        bytes
    }
}

/// For the spent proofs to verify, the caller must provide
/// an implementation of this trait which must have/know
/// the pubkey of the spentbook section that signed each of the proofs.
pub trait SpentProofKeyVerifier {
    type Error: std::error::Error;
    fn verify_known_key(&self, key: &PublicKey) -> Result<(), Self::Error>;
}

/// SpentProof's are constructed when a DBC is logged to the spentbook.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialOrd, Ord)]
pub struct SpentProof {
    /// data to be signed
    pub content: SpentProofContent,

    /// The Spentbook who notarized that this DBC was spent.
    pub spentbook_pub_key: PublicKey,

    /// The Spentbook's signature notarizing the DBC was spent.
    /// signing over SpentProofContent. (PublicKey, DbcTransaction, and public_commitment).
    pub spentbook_sig: Signature,
}

impl SpentProof {
    /// Attempts to build a SpentProof by combining a given set of proof shares
    pub fn try_from_proof_shares<'a>(
        public_key: PublicKey,
        transaction_hash: Hash,
        shares: impl Iterator<Item = &'a SpentProofShare>,
    ) -> Result<Self> {
        let mut peekable_shares = shares.peekable();
        let any_share = peekable_shares
            .peek()
            .cloned()
            .ok_or(Error::MissingSpentProofShare(public_key))?;

        let reason = any_share.reason();
        if !peekable_shares.all(|s| s.reason() == reason) {
            return Err(Error::SpentProofShareReasonMismatch(public_key));
        }

        let spentbook_pub_key = any_share.spentbook_pks().public_key();
        let spentbook_sig = any_share.spentbook_pks.combine_signatures(
            peekable_shares
                .map(SpentProofShare::spentbook_sig_share)
                .map(IndexedSignatureShare::threshold_crypto),
        )?;

        let public_commitment = *any_share.public_commitment();

        Ok(SpentProof {
            content: SpentProofContent {
                public_key,
                transaction_hash,
                public_commitment,
                reason,
            },
            spentbook_pub_key,
            spentbook_sig,
        })
    }

    /// get PublicKey of input Dbc
    pub fn public_key(&self) -> &PublicKey {
        &self.content.public_key
    }

    /// get transaction hash
    pub fn transaction_hash(&self) -> Hash {
        self.content.transaction_hash
    }

    /// get public commitments
    pub fn public_commitment(&self) -> &Commitment {
        &self.content.public_commitment
    }

    /// get reason
    pub fn reason(&self) -> Hash {
        self.content.reason
    }

    /// represent this SpentProof as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Default::default();

        bytes.extend(self.content.to_bytes());
        bytes.extend(self.spentbook_pub_key.to_bytes());
        bytes.extend(self.spentbook_sig.to_bytes());

        bytes
    }

    /// verify this SpentProof
    ///
    /// checks that the input transaction hash matches the tx_hash that was
    /// signed by the spentbook and verifies that spentbook signature is
    /// valid for this SpentProof.
    ///
    /// note that the verifier must already hold (trust) the spentbook's public key.
    pub fn verify<K: SpentProofKeyVerifier>(
        &self,
        tx_hash: Hash,
        proof_key_verifier: &K,
    ) -> Result<()> {
        // verify input tx_hash matches our tx_hash which was signed by spentbook.
        if tx_hash != self.content.transaction_hash {
            return Err(Error::InvalidTransactionHash);
        }

        let pub_key = &self.spentbook_pub_key;

        if !pub_key.verify(&self.spentbook_sig, self.content.hash()) {
            return Err(Error::InvalidSpentProofSignature(*self.public_key()));
        }

        proof_key_verifier
            .verify_known_key(pub_key)
            .map_err(|err| Error::FailedKnownKeyCheck(err.to_string()))
    }
}

// impl manually to avoid clippy complaint about Hash conflict.
impl PartialEq for SpentProof {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content
            && self.spentbook_pub_key == other.spentbook_pub_key
            && self.spentbook_sig == other.spentbook_sig
    }
}

impl Eq for SpentProof {}

impl std::hash::Hash for SpentProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = self.to_bytes();
        bytes.hash(state);
    }
}
