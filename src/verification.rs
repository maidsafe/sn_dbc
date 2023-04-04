// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::transaction::DbcTransaction;
use crate::{BlindedAmount, DbcId, Error, Hash, Result, SpentProof, SpentProofKeyVerifier};
use std::collections::BTreeSet;

// Here we are putting transaction verification logic that is beyond
// what DbcTransaction::verify() provides.
//
// Another way to do this would be to create a NewType wrapper for DbcTransaction.
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
        transaction: &DbcTransaction,
        spent_proofs: &BTreeSet<SpentProof>,
    ) -> Result<(), Error> {
        if spent_proofs.len() != transaction.inputs.len() {
            return Err(Error::SpentProofInputLenMismatch {
                current: spent_proofs.len(),
                expected: transaction.inputs.len(),
            });
        }

        let transaction_hash = Hash::from(transaction.hash());

        // Verify that each pubkey is unique in this transaction.
        let unique_dbc_ids: BTreeSet<DbcId> =
            transaction.outputs.iter().map(|o| (*o.dbc_id())).collect();
        if unique_dbc_ids.len() != transaction.outputs.len() {
            return Err(Error::DbcIdNotUniqueAcrossOutputs);
        }

        // Verify that each input has a corresponding spent proof.
        for spent_proof in spent_proofs.iter() {
            if !transaction
                .inputs
                .iter()
                .any(|m| m.dbc_id == *spent_proof.dbc_id())
            {
                return Err(Error::SpentProofInputIdMismatch);
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

        // We must get the spent proofs into the same order as inputs
        // so that resulting blinded amounts will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut spent_proofs_found: Vec<(usize, &SpentProof)> = spent_proofs
            .iter()
            .filter_map(|s| {
                transaction
                    .inputs
                    .iter()
                    .position(|m| m.dbc_id == *s.dbc_id())
                    .map(|idx| (idx, s))
            })
            .collect();

        spent_proofs_found.sort_by_key(|s| s.0);
        let spent_proofs_sorted: Vec<&SpentProof> =
            spent_proofs_found.into_iter().map(|s| s.1).collect();

        let blinded_amounts: Vec<BlindedAmount> = spent_proofs_sorted
            .iter()
            .map(|s| *s.blinded_amount())
            .collect();

        transaction.verify(&blinded_amounts)?;

        Ok(())
    }
}

/// Get the blinded amounts for the transaction.
/// They will be part of the spent proof share that is generated.
/// In the process of doing so, we verify the correct set of spent
/// proofs and transactions have been provided.
pub fn get_blinded_amounts_from_transaction(
    tx: &DbcTransaction,
    spent_proofs: &BTreeSet<SpentProof>,
    spent_transactions: &BTreeSet<DbcTransaction>,
) -> Result<Vec<(DbcId, BlindedAmount)>> {
    // Get txs that are referenced by the spent proofs.
    let mut referenced_spent_txs: Vec<&DbcTransaction> = vec![];
    for spent_prf in spent_proofs {
        for spent_tx in spent_transactions {
            let tx_hash = Hash::from(spent_tx.hash());
            if tx_hash == spent_prf.transaction_hash() {
                referenced_spent_txs.push(spent_tx);
            }
        }
    }

    // For each input's DbcId, look up the matching
    // blinded amount in those referenced Txs.
    let mut tx_keys_and_blinded_amounts = Vec::<(DbcId, BlindedAmount)>::new();
    for input in &tx.inputs {
        let input_dbc_id = input.dbc_id();

        let matching_amounts: Vec<BlindedAmount> = referenced_spent_txs
            .iter()
            .flat_map(|tx| {
                tx.outputs
                    .iter()
                    .find(|output| output.dbc_id() == &input_dbc_id)
                    .map(|output| output.blinded_amount())
            })
            .collect();

        match matching_amounts[..] {
            [] => return Err(Error::MissingAmountForDbcId(input_dbc_id)),
            [one_amount] => tx_keys_and_blinded_amounts.push((input_dbc_id, one_amount)),
            [_, _, ..] => return Err(Error::MultipleAmountsForDbcId(input_dbc_id)),
        }
    }

    Ok(tx_keys_and_blinded_amounts)
}
