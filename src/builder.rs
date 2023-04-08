// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bulletproofs::PedersenGens;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    dbc_id::DbcIdSource,
    transaction::{
        DbcTransaction, Output, RevealedAmount, RevealedInput, RevealedOutput, RevealedTx,
    },
    DbcId, DerivedKey, MainKey,
};
use crate::{
    rand::{CryptoRng, RngCore},
    BlindedAmount, Dbc, DbcCiphers, Error, Hash, Result, SignedSpend, Token, TransactionVerifier,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type OutputIdSources = BTreeMap<DbcId, DbcIdSource>;

/// A builder to create a DBC transaction from
/// inputs and outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    revealed_tx: RevealedTx,
    output_id_sources: OutputIdSources,
}

impl TransactionBuilder {
    /// Add an input given a RevealedInput.
    pub fn add_input(mut self, input: RevealedInput) -> Self {
        self.revealed_tx.inputs.push(input);
        self
    }

    /// Add an input given an iterator over RevealedInput.
    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = RevealedInput>) -> Self {
        self.revealed_tx.inputs.extend(inputs);
        self
    }

    /// Add an input given a Dbc and associated MainKey.
    pub fn add_input_dbc(mut self, dbc: &Dbc, main_key: &MainKey) -> Result<Self> {
        self = self.add_input(dbc.as_revealed_input(main_key)?);
        Ok(self)
    }

    /// Add an input given a list of Dbcs and associated MainKeys.
    pub fn add_inputs_dbc(
        mut self,
        dbcs: impl IntoIterator<Item = (Dbc, MainKey)>,
    ) -> Result<Self> {
        for (dbc, main_key) in dbcs.into_iter() {
            self = self.add_input_dbc(&dbc, &main_key)?;
        }
        Ok(self)
    }

    /// Add an input given a DerivedKey and a RevealedAmount.
    pub fn add_input_by_secrets(
        mut self,
        derived_key: DerivedKey,
        revealed_amount: RevealedAmount,
    ) -> Self {
        let revealed_input = RevealedInput::new(derived_key, revealed_amount);
        self = self.add_input(revealed_input);
        self
    }

    /// Add an input given a list of (DerivedKey, RevealedAmount).
    pub fn add_inputs_by_secrets(mut self, secrets: Vec<(DerivedKey, RevealedAmount)>) -> Self {
        for (derived_key, revealed_amount) in secrets.into_iter() {
            self = self.add_input_by_secrets(derived_key, revealed_amount);
        }
        self
    }

    /// Add an output given amount and the source of the DbcId for the new Dbc.
    pub fn add_output(mut self, amount: Token, dbc_id_src: DbcIdSource) -> Self {
        let output = Output::new(dbc_id_src.dbc_id(), amount.as_nano());
        self.output_id_sources.insert(output.dbc_id, dbc_id_src);
        self.revealed_tx.outputs.push(output);
        self
    }

    /// Add a list of outputs given the amounts and sources of DbcIds for the new Dbcs.
    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = (Token, DbcIdSource)>) -> Self {
        for (amount, dbc_id_src) in outputs.into_iter() {
            self = self.add_output(amount, dbc_id_src);
        }
        self
    }

    /// Get a list of input ids.
    pub fn input_ids(&self) -> Vec<DbcId> {
        self.revealed_tx.inputs.iter().map(|t| t.dbc_id()).collect()
    }

    /// Get sum of input amounts.
    pub fn inputs_amount_sum(&self) -> Token {
        let amount = self
            .revealed_tx
            .inputs
            .iter()
            .map(|t| t.revealed_amount.value)
            .sum();
        Token::from_nano(amount)
    }

    /// Get sum of output amounts.
    pub fn outputs_amount_sum(&self) -> Token {
        let amount = self.revealed_tx.outputs.iter().map(|o| o.amount).sum();
        Token::from_nano(amount)
    }

    /// Get inputs.
    pub fn inputs(&self) -> &Vec<RevealedInput> {
        &self.revealed_tx.inputs
    }

    /// Get outputs.
    pub fn outputs(&self) -> &Vec<Output> {
        &self.revealed_tx.outputs
    }

    /// Build the DbcTransaction by signing the inputs,
    /// and generating the blinded outputs. Return a DbcBuilder.
    pub fn build(self, reason: Hash, rng: impl RngCore + CryptoRng) -> Result<DbcBuilder> {
        let (tx, revealed_outputs) = self.revealed_tx.sign(rng)?;

        let tx_hash = Hash::from(tx.hash());
        let signed_spends: BTreeSet<_> = tx
            .inputs
            .iter()
            .flat_map(|input| {
                self.revealed_tx
                    .inputs
                    .iter()
                    .find(|i| i.dbc_id() == input.dbc_id())
                    .map(|i| {
                        let spend = crate::Spend {
                            dbc_id: input.dbc_id(),
                            tx_hash,
                            reason,
                            blinded_amount: input.blinded_amount,
                        };
                        let derived_key_sig = i.derived_key.sign(&spend.to_bytes());
                        SignedSpend {
                            spend,
                            derived_key_sig,
                        }
                    })
            })
            .collect();

        Ok(DbcBuilder::new(
            tx,
            revealed_outputs,
            self.output_id_sources,
            self.revealed_tx,
            signed_spends,
        ))
    }
}

/// A Builder for aggregating SignedSpends and generating the final Dbc outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DbcBuilder {
    pub tx: DbcTransaction,
    pub revealed_outputs: Vec<RevealedOutput>,
    pub output_id_sources: OutputIdSources,
    pub revealed_tx: RevealedTx,
    pub signed_spends: BTreeSet<SignedSpend>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder.
    pub fn new(
        tx: DbcTransaction,
        revealed_outputs: Vec<RevealedOutput>,
        output_id_sources: OutputIdSources,
        revealed_tx: RevealedTx,
        signed_spends: BTreeSet<SignedSpend>,
    ) -> Self {
        Self {
            tx,
            revealed_outputs,
            output_id_sources,
            revealed_tx,
            signed_spends,
        }
    }

    /// Return the signed spends.
    pub fn signed_spends(&self) -> Vec<(&DbcTransaction, &SignedSpend)> {
        self.signed_spends
            .iter()
            .map(|spend| (&self.tx, spend))
            .collect()
    }

    /// Build the output Dbcs, verifying the transaction and SignedSpends.
    ///
    /// See TransactionVerifier::verify() for a description of
    /// verifier requirements.
    pub fn build(self) -> Result<Vec<(Dbc, RevealedAmount)>> {
        // Verify the tx, along with spent proofs.
        // Note that we do this just once for entire tx, not once per output Dbc.
        TransactionVerifier::verify(&self.tx, &self.signed_spends)?;

        // Build output Dbcs.
        self.build_output_dbcs()
    }

    /// Build the output Dbcs (no verification over Tx or SignedSpend is performed).
    pub fn build_without_verifying(self) -> Result<Vec<(Dbc, RevealedAmount)>> {
        self.build_output_dbcs()
    }

    // Private helper to build output Dbcs.
    fn build_output_dbcs(self) -> Result<Vec<(Dbc, RevealedAmount)>> {
        let pc_gens = PedersenGens::default();
        let output_blinded_and_revealed_amounts: Vec<(BlindedAmount, RevealedAmount)> = self
            .revealed_outputs
            .iter()
            .map(|output| output.revealed_amount)
            .map(|r| (r.blinded_amount(&pc_gens), r))
            .collect();

        let dbc_id_list: Vec<&DbcIdSource> = self
            .tx
            .outputs
            .iter()
            .map(|output| {
                self.output_id_sources
                    .get(output.dbc_id())
                    .ok_or(Error::DbcIdNotFound)
            })
            .collect::<Result<_>>()?;

        // Form the final output DBCs
        let output_dbcs: Vec<(Dbc, RevealedAmount)> = self
            .tx
            .outputs
            .iter()
            .zip(dbc_id_list)
            .map(|(output, dbc_id_src)| {
                let revealed_amounts: Vec<RevealedAmount> = output_blinded_and_revealed_amounts
                    .iter()
                    .filter(|(c, _)| *c == output.blinded_amount())
                    .map(|(_, r)| *r)
                    .collect();
                assert_eq!(revealed_amounts.len(), 1);

                let ciphers = DbcCiphers::from((
                    &dbc_id_src.public_address,
                    &dbc_id_src.derivation_index,
                    revealed_amounts[0],
                ));
                let dbc = Dbc {
                    id: dbc_id_src.dbc_id(),
                    tx: self.tx.clone(),
                    ciphers,
                    signed_spends: self.signed_spends.clone(),
                };
                (dbc, revealed_amounts[0])
            })
            .collect();

        Ok(output_dbcs)
    }
}
