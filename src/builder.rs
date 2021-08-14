use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use curve25519_dalek_ng::scalar::Scalar;

use crate::{AmountSecrets, Dbc, DbcContent, ReissueTransaction, Result};

///! Unblinded data for creating to sn_dbc::DbcContent
pub struct Output {
    pub amount: u64,
    pub owner: blsttc::PublicKey,
}

#[derive(Default)]
pub struct TransactionBuilder {
    pub inputs: HashMap<Dbc, AmountSecrets>,
    pub outputs: Vec<Output>,
}

impl TransactionBuilder {
    pub fn add_input(mut self, dbc: Dbc, amount_secrets: AmountSecrets) -> Self {
        self.inputs.insert(dbc, amount_secrets);
        self
    }

    pub fn add_output(mut self, output_mat: Output) -> Self {
        self.outputs.push(output_mat);
        self
    }

    pub fn build(self) -> Result<ReissueTransaction> {
        let parents = BTreeSet::from_iter(self.inputs.keys().map(Dbc::name));
        let inputs_bf_sum = self
            .inputs
            .values()
            .map(|amount_secrets| amount_secrets.blinding_factor)
            .sum();

        let mut outputs_bf_sum: Scalar = Default::default();
        let outputs = self
            .outputs
            .iter()
            .enumerate()
            .map(|(out_idx, output)| {
                let blinding_factor = DbcContent::calc_blinding_factor(
                    out_idx == self.outputs.len() - 1,
                    inputs_bf_sum,
                    outputs_bf_sum,
                );
                outputs_bf_sum += blinding_factor;

                DbcContent::new(
                    parents.clone(),
                    output.amount,
                    output.owner,
                    blinding_factor,
                )
            })
            .collect::<Result<HashSet<_>>>()?;

        Ok(ReissueTransaction {
            inputs: HashSet::from_iter(self.inputs.into_keys()),
            outputs,
        })
    }
}
