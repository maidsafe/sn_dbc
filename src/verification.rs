// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    transaction::{self, DbcTransaction},
    BlindedAmount, DbcId, Error, Result, SignedSpend,
};

use std::collections::{BTreeMap, BTreeSet};

// Here we are putting transaction verification logic that is beyond
// what DbcTransaction::verify() provides.
//
// Another way to do this would be to create a NewType wrapper for DbcTransaction.
// We can discuss if that is better or not.

pub struct TransactionVerifier {}

impl TransactionVerifier {
    /// Verifies a transaction including signed spends.
    ///
    /// This function relies/assumes that the caller (wallet/client) obtains
    /// the DbcTransaction (held by every input spend's close group) in a
    /// trustless/verified way. I.e., the caller should not simply obtain a
    /// spend from a single peer, but must get the same spend from all in the close group.
    pub fn verify(
        spent_tx: &DbcTransaction,
        signed_spends: &BTreeSet<SignedSpend>,
    ) -> Result<(), Error> {
        if signed_spends.is_empty() {
            return Err(transaction::Error::MissingTxInputs)?;
        }

        if signed_spends.len() != spent_tx.inputs.len() {
            return Err(Error::SignedSpendInputLenMismatch {
                current: signed_spends.len(),
                expected: spent_tx.inputs.len(),
            });
        }

        let spent_tx_hash = spent_tx.hash();

        // Verify that each pubkey is unique in this transaction.
        let unique_dbc_ids: BTreeSet<DbcId> =
            spent_tx.outputs.iter().map(|o| (*o.dbc_id())).collect();
        if unique_dbc_ids.len() != spent_tx.outputs.len() {
            return Err(Error::DbcIdNotUniqueAcrossOutputs);
        }

        // Verify that each input has a corresponding signed spend.
        for signed_spend in signed_spends.iter() {
            if !spent_tx
                .inputs
                .iter()
                .any(|m| m.dbc_id == *signed_spend.dbc_id())
            {
                return Err(Error::SignedSpendInputIdMismatch);
            }
        }

        // Verify that each signed spend is valid
        for signed_spend in signed_spends.iter() {
            signed_spend.verify(spent_tx_hash)?;
        }

        // We must get the signed spends into the same order as inputs
        // so that resulting blinded amounts will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut signed_spends_found: Vec<(usize, &SignedSpend)> = signed_spends
            .iter()
            .filter_map(|s| {
                spent_tx
                    .inputs
                    .iter()
                    .position(|m| m.dbc_id == *s.dbc_id())
                    .map(|idx| (idx, s))
            })
            .collect();

        signed_spends_found.sort_by_key(|s| s.0);
        let signed_spends_sorted: Vec<&SignedSpend> =
            signed_spends_found.into_iter().map(|s| s.1).collect();

        let blinded_amounts: Vec<BlindedAmount> = signed_spends_sorted
            .iter()
            .map(|s| *s.blinded_amount())
            .collect();

        spent_tx.verify(&blinded_amounts)?;

        Ok(())
    }
}

/// Get the blinded amounts for the transaction.
/// They will be part of the signed spend that is generated.
/// In the process of doing so, we verify the correct set of signed
/// spends and transactions have been provided.
pub fn get_blinded_amounts_from_transaction(
    spent_tx: &DbcTransaction,
    input_signed_spends: &BTreeSet<SignedSpend>,
    spent_src_transactions: &BTreeMap<crate::Hash, DbcTransaction>,
) -> Result<Vec<(DbcId, BlindedAmount)>> {
    // Get txs that are referenced by the signed spends.
    let mut referenced_spent_txs: Vec<_> = vec![];
    for input in input_signed_spends {
        if let Some(src_tx) = spent_src_transactions.get(&input.spend.dbc_creation_tx.hash()) {
            if src_tx.hash() == input.spend.dbc_creation_tx.hash() {
                referenced_spent_txs.push(src_tx);
                continue;
            }
        }
        return Err(Error::MissingSpentSrcTransaction {
            dbc_id: *input.dbc_id(),
            dbc_creation_tx_hash: input.spend.dbc_creation_tx.hash(),
        });
    }

    // For each input's DbcId, look up the matching
    // blinded amount in the tx where it was created - its source tx.
    let mut tx_keys_and_blinded_amounts = Vec::<(DbcId, BlindedAmount)>::new();
    for input in &spent_tx.inputs {
        let input_dbc_id = input.dbc_id();

        let matching_amounts: Vec<BlindedAmount> = referenced_spent_txs
            .iter()
            .flat_map(|input_src_tx| {
                input_src_tx
                    .outputs
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
