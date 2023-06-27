// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dbc_id::DbcIdSource,
    transaction::{DbcTransaction, InputIntermediate, Output, TransactionIntermediate},
    Amount, DbcId, DerivedKey,
};
use crate::{Dbc, DbcCiphers, Error, Hash, Result, SignedSpend, Token, TransactionVerifier};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type OutputIdSources = BTreeMap<DbcId, DbcIdSource>;

/// A builder to create a DBC transaction from
/// inputs and outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    tx: TransactionIntermediate,
    output_id_sources: OutputIdSources,
}

impl TransactionBuilder {
    /// Add an input given a InputIntermediate.
    pub fn add_input(mut self, input: InputIntermediate) -> Self {
        self.tx.inputs.push(input);
        self
    }

    /// Add an input given an iterator over InputIntermediate.
    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = InputIntermediate>) -> Self {
        self.tx.inputs.extend(inputs);
        self
    }

    /// Add an input given a Dbc and its DerivedKey.
    pub fn add_input_dbc(mut self, dbc: &Dbc, derived_key: &DerivedKey) -> Result<Self> {
        let input_src_tx = dbc.src_tx.clone();
        self = self.add_input(InputIntermediate {
            derived_key: derived_key.clone(),
            amount: dbc.amount()?,
            input_src_tx,
        });
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
        self.tx.outputs.push(output);
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
        self.tx.inputs.iter().map(|t| t.dbc_id()).collect()
    }

    /// Get sum of input amounts.
    pub fn inputs_amount_sum(&self) -> Token {
        let amount = self.tx.inputs.iter().map(|t| t.amount.value).sum();
        Token::from_nano(amount)
    }

    /// Get sum of output amounts.
    pub fn outputs_amount_sum(&self) -> Token {
        let amount = self.tx.outputs.iter().map(|o| o.amount.value).sum();
        Token::from_nano(amount)
    }

    /// Get inputs.
    pub fn inputs(&self) -> &Vec<InputIntermediate> {
        &self.tx.inputs
    }

    /// Get outputs.
    pub fn outputs(&self) -> &Vec<Output> {
        &self.tx.outputs
    }

    /// Build the DbcTransaction by signing the inputs. Return a DbcBuilder.
    pub fn build(self, reason: Hash) -> Result<DbcBuilder> {
        let spent_tx = self.tx.sign()?;

        let signed_spends: BTreeSet<_> = spent_tx
            .inputs
            .iter()
            .flat_map(|input| {
                self.tx
                    .inputs
                    .iter()
                    .find(|i| i.dbc_id() == input.dbc_id())
                    .map(|i| {
                        let spend: crate::Spend = crate::Spend {
                            dbc_id: input.dbc_id(),
                            spent_tx: spent_tx.clone(),
                            reason,
                            amount: input.amount,
                            dbc_creation_tx: i.input_src_tx.clone(),
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
        TransactionVerifier::verify(&self.spent_tx, &self.signed_spends)?;

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
                let ciphers = DbcCiphers::from((
                    &dbc_id_src.public_address,
                    &dbc_id_src.derivation_index,
                    output.amount,
                ));
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
