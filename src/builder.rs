// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dbc_id::DbcIdSource,
    transaction::{DbcTransaction, Output},
    Amount, DbcId, DerivationIndex, DerivedKey, Input, PublicAddress, Spend,
};
use crate::{Dbc, DbcCiphers, Error, Hash, Result, SignedSpend, Token};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type OutputIdSources = BTreeMap<DbcId, DbcIdSource>;
pub type InputTx = DbcTransaction;
pub type InputSrcTx = DbcTransaction;

/// A builder to create a DBC transaction from
/// inputs and outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    input_details: BTreeMap<DbcId, (DerivedKey, InputSrcTx)>,
    output_details: BTreeMap<DbcId, (PublicAddress, DerivationIndex)>,
    output_id_sources: OutputIdSources,
}

impl TransactionBuilder {
    /// Add an input given a the `Input`, the `DerivedKey` for the input and the `InputSrcTx`
    pub fn add_input(mut self, input: Input, derived_key: DerivedKey, src_tx: InputSrcTx) -> Self {
        self.input_details
            .insert(input.dbc_id(), (derived_key, src_tx));
        self.inputs.push(input);
        self
    }

    /// Add an input given a Dbc and its DerivedKey.
    pub fn add_input_dbc(mut self, dbc: &Dbc, derived_key: &DerivedKey) -> Result<Self> {
        let input_src_tx = dbc.src_tx.clone();
        let input = Input {
            dbc_id: dbc.id(),
            amount: dbc.amount()?,
        };
        self = self.add_input(input, derived_key.clone(), input_src_tx);
        Ok(self)
    }

    /// Add an input given a list of Dbcs and associated DerivedKeys.
    pub fn add_input_dbcs(mut self, dbcs: &[(Dbc, DerivedKey)]) -> Result<Self> {
        for (dbc, derived_key) in dbcs.iter() {
            self = self.add_input_dbc(dbc, derived_key)?;
        }
        Ok(self)
    }

    /// Add an output given amount and the source of the DbcId for the new Dbc.
    pub fn add_output(mut self, amount: Token, dbc_id_src: DbcIdSource) -> Self {
        let output = Output::new(dbc_id_src.dbc_id(), amount.as_nano());
        self.output_id_sources.insert(output.dbc_id, dbc_id_src);
        self.outputs.push(output);
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
        self.inputs.iter().map(|i| i.dbc_id()).collect()
    }

    /// Get sum of input amounts.
    pub fn inputs_amount_sum(&self) -> Token {
        let amount = self.inputs.iter().map(|i| i.amount.value).sum();
        Token::from_nano(amount)
    }

    /// Get sum of output amounts.
    pub fn outputs_amount_sum(&self) -> Token {
        let amount = self.outputs.iter().map(|o| o.amount.value).sum();
        Token::from_nano(amount)
    }

    /// Get inputs.
    pub fn inputs(&self) -> &Vec<Input> {
        &self.inputs
    }

    /// Get outputs.
    pub fn outputs(&self) -> &Vec<Output> {
        &self.outputs
    }

    /// Build the DbcTransaction by signing the inputs. Return a DbcBuilder.
    pub fn build(self, reason: Hash) -> Result<DbcBuilder> {
        let spent_tx = DbcTransaction {
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
        };
        let signed_spends: BTreeSet<_> = self
            .inputs
            .iter()
            .flat_map(|input| {
                let (derived_key, input_src_tx) = self.input_details.get(&input.dbc_id)?;
                let spend = Spend {
                    dbc_id: input.dbc_id(),
                    spent_tx: spent_tx.clone(),
                    reason,
                    amount: input.amount,
                    dbc_creation_tx: input_src_tx.clone(),
                };
                let derived_key_sig = derived_key.sign(&spend.to_bytes());
                Some(SignedSpend {
                    spend,
                    derived_key_sig,
                })
            })
            .collect();

        Ok(DbcBuilder::new(
            spent_tx,
            self.output_id_sources,
            signed_spends,
        ))
    }
}

/// A Builder for aggregating SignedSpends and generating the final Dbc outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DbcBuilder {
    pub spent_tx: DbcTransaction,
    pub output_id_sources: OutputIdSources,
    pub signed_spends: BTreeSet<SignedSpend>,
}

impl DbcBuilder {
    /// Create a new DbcBuilder.
    pub fn new(
        spent_tx: DbcTransaction,
        output_id_sources: OutputIdSources,
        signed_spends: BTreeSet<SignedSpend>,
    ) -> Self {
        Self {
            spent_tx,
            output_id_sources,
            signed_spends,
        }
    }

    /// Return the signed spends. They each already contain the
    /// spent_tx, so the inclusion of it in the result is just for convenience.
    pub fn signed_spends(&self) -> Vec<&SignedSpend> {
        self.signed_spends.iter().collect()
    }

    /// Build the output Dbcs, verifying the transaction and SignedSpends.
    ///
    /// See TransactionVerifier::verify() for a description of
    /// verifier requirements.
    pub fn build(self) -> Result<Vec<(Dbc, Amount)>> {
        // Verify the tx, along with signed spends.
        // Note that we do this just once for entire tx, not once per output Dbc.
        self.spent_tx
            .verify_against_inputs_spent(&self.signed_spends)?;

        // Build output Dbcs.
        self.build_output_dbcs()
    }

    /// Build the output Dbcs (no verification over Tx or SignedSpend is performed).
    pub fn build_without_verifying(self) -> Result<Vec<(Dbc, Amount)>> {
        self.build_output_dbcs()
    }

    // Private helper to build output Dbcs.
    fn build_output_dbcs(self) -> Result<Vec<(Dbc, Amount)>> {
        self.spent_tx
            .outputs
            .iter()
            .map(|output| {
                let dbc_id_src = self
                    .output_id_sources
                    .get(&output.dbc_id)
                    .ok_or(Error::DbcIdNotFound)?;
                let ciphers =
                    DbcCiphers::from((&dbc_id_src.public_address, &dbc_id_src.derivation_index));
                Ok((
                    Dbc {
                        id: dbc_id_src.dbc_id(),
                        src_tx: self.spent_tx.clone(),
                        ciphers,
                        signed_spends: self.signed_spends.clone(),
                    },
                    output.amount,
                ))
            })
            .collect()
    }
}
