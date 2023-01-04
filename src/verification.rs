// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Commitment, Error, Hash, KeyImage, Result, SpentProof, SpentProofKeyVerifier};
use bls_ringct::ringct::RingCtTransaction;
use std::collections::BTreeSet;

// Here we are putting transaction verification logic that is beyond
// what RingCtTransaction::verify() provides.
//
// Another way to do this would be to create a NewType wrapper for RingCtTransaction.
// We can discuss if that is better or not.

pub struct TransactionVerifier {}

impl TransactionVerifier {
    /// Verifies a transaction including spent proofs.
    ///
    /// This function relies/assumes that the caller (wallet/client) obtains
    /// the spentbook's public keys (held by SpentProofKeyVerifier) in a
    /// trustless/verified way.  ie, the caller should not simply obtain keys
    /// from a SpentBookNode directly, but must somehow verify that the node is
    /// a valid authority.
    ///
    /// note: for spent_proofs to verify, the verifier must have/know the
    ///       public key of each spentbook section that recorded a tx input as spent.
    pub fn verify<K: SpentProofKeyVerifier>(
        verifier: &K,
        transaction: &RingCtTransaction,
        spent_proofs: &BTreeSet<SpentProof>,
    ) -> Result<(), Error> {
        if spent_proofs.len() != transaction.mlsags.len() {
            return Err(Error::SpentProofInputLenMismatch {
                current: spent_proofs.len(),
                expected: transaction.mlsags.len(),
            });
        }

        let transaction_hash = Hash::from(transaction.hash());

        // Verify that each pubkey is unique in this transaction.
        let pubkey_unique: BTreeSet<KeyImage> = transaction
            .outputs
            .iter()
            .map(|o| (*o.public_key()).into())
            .collect();
        if pubkey_unique.len() != transaction.outputs.len() {
            return Err(Error::PublicKeyNotUniqueAcrossOutputs);
        }

        // Verify that each input has a corresponding spent proof.
        for spent_proof in spent_proofs.iter() {
            if !transaction
                .mlsags
                .iter()
                .any(|m| Into::<KeyImage>::into(m.key_image) == *spent_proof.key_image())
            {
                return Err(Error::SpentProofInputKeyImageMismatch);
            }
        }

        // Verify that each spent proof is valid
        //
        // note: for the proofs to verify, our key_manager must have/know
        // the pubkey of the spentbook section that signed the proof.
        // This is a responsibility of our caller, not this crate.
        for spent_proof in spent_proofs.iter() {
            spent_proof.verify(transaction_hash, verifier)?;
        }

        // We must get the spent_proofs into the same order as mlsags
        // so that resulting public_commitments will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut spent_proofs_found: Vec<(usize, &SpentProof)> = spent_proofs
            .iter()
            .filter_map(|s| {
                transaction
                    .mlsags
                    .iter()
                    .position(|m| Into::<KeyImage>::into(m.key_image) == *s.key_image())
                    .map(|idx| (idx, s))
            })
            .collect();

        spent_proofs_found.sort_by_key(|s| s.0);
        let spent_proofs_sorted: Vec<&SpentProof> =
            spent_proofs_found.into_iter().map(|s| s.1).collect();

        let public_commitments: Vec<Vec<Commitment>> = spent_proofs_sorted
            .iter()
            .map(|s| s.public_commitments().clone())
            .collect();

        transaction.verify(&public_commitments)?;

        Ok(())
    }
}

/// Get the public commitments for the transaction for a key image spend.
///
/// They will be assigned to the spent proof share that is generated.
///
/// In the process of doing so, we verify the correct set of spent proofs and transactions have
/// been provided.
///
/// For the moment this function will only be called outside the library, hence the dead code
/// exception.
#[allow(dead_code)]
pub fn get_public_commitments_from_transaction(
    tx: &RingCtTransaction,
    spent_proofs: &BTreeSet<SpentProof>,
    spent_transactions: &BTreeSet<RingCtTransaction>,
) -> Result<Vec<(KeyImage, Vec<Commitment>)>> {
    let mut public_commitments_info = Vec::<(KeyImage, Vec<Commitment>)>::new();
    for mlsag in &tx.mlsags {
        // For each public key in ring, look up the matching Commitment
        // using the SpentProofs and spent TX set provided by the client.
        let commitments: Vec<Commitment> = mlsag
            .public_keys()
            .iter()
            .flat_map(move |input_pk| {
                spent_proofs.iter().flat_map(move |proof| {
                    // Make sure the spent proof corresponds to any of the spent TX provided,
                    // and the TX output PK matches the ring PK
                    spent_transactions.iter().filter_map(move |spent_tx| {
                        let tx_hash = Hash::from(spent_tx.hash());
                        if tx_hash == proof.transaction_hash() {
                            spent_tx
                                .outputs
                                .iter()
                                .find(|output| output.public_key() == &input_pk.clone())
                                .map(|output| output.commitment())
                        } else {
                            None
                        }
                    })
                })
            })
            .collect();

        if commitments.len() != mlsag.public_keys().len() {
            return Err(Error::CommitmentsInputLenMismatch {
                current: commitments.len(),
                expected: mlsag.public_keys().len(),
            });
        }

        public_commitments_info.push((mlsag.key_image.into(), commitments));
    }
    Ok(public_commitments_info)
}
