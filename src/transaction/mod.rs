// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

mod amount;
mod error;
mod input;
mod output;

use crate::DbcId;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet};
use tiny_keccak::{Hasher, Sha3};

pub use amount::Amount;
pub(crate) use error::Error;
pub use input::{Input, InputIntermediate};
pub use output::Output;

type Result<T> = std::result::Result<T, Error>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DbcTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl PartialEq for DbcTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

impl Eq for DbcTransaction {}

impl PartialOrd for DbcTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DbcTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash().cmp(&other.hash())
    }
}

impl DbcTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend("inputs".as_bytes());
        for m in self.inputs.iter() {
            v.extend(&m.to_bytes());
        }
        v.extend("outputs".as_bytes());
        for o in self.outputs.iter() {
            v.extend(&o.to_bytes());
        }
        v.extend("end".as_bytes());
        v
    }

    pub fn hash(&self) -> crate::Hash {
        let mut sha3 = Sha3::v256();
        sha3.update(&self.to_bytes());
        let mut hash = [0; 32];
        sha3.finalize(&mut hash);
        crate::Hash::from(hash)
    }

    /// Check if every input has the signature over this very tx,
    /// and that each public key of the inputs was the signer.
    pub fn verify(&self) -> Result<()> {
        // Verify that the tx has at least one input
        if self.inputs.is_empty() {
            return Err(Error::MissingTxInputs);
        }

        // Verify that each dbc id is unique.
        let id_count = self.inputs.len();
        let unique_ids: BTreeSet<_> = self.inputs.iter().map(|input| input.dbc_id).collect();
        if unique_ids.len() != id_count {
            return Err(Error::DbcIdNotUniqueAcrossInputs);
        }

        // Check that the input and output amounts are equal.
        let input_sum: u64 = self
            .inputs
            .iter()
            .map(|i| i.amount.value)
            .try_fold(0, |acc: u64, i| {
                acc.checked_add(i).ok_or(Error::NumericOverflow)
            })?;
        let output_sum: u64 = self
            .outputs
            .iter()
            .map(|o| o.amount.value)
            .try_fold(0, |acc: u64, o| {
                acc.checked_add(o).ok_or(Error::NumericOverflow)
            })?;

        if input_sum != output_sum {
            Err(Error::InconsistentDbcTransaction)
        } else {
            Ok(())
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct TransactionIntermediate {
    pub inputs: Vec<InputIntermediate>,
    pub outputs: Vec<Output>,
}

impl TransactionIntermediate {
    pub fn sign(&self) -> Result<DbcTransaction> {
        // We need to gather a bunch of things for our message to sign.
        //   All public keys in all inputs
        //   All input amounts
        //   All output public keys.
        //   All output amounts

        // Generate message to sign.
        // note: must match message generated by DbcTransaction::verify()

        // We create a signature for each input
        let inputs: Vec<Input> = self
            .inputs
            .iter()
            .map(|input_intermediate| input_intermediate.get_input())
            .collect();

        Ok(DbcTransaction {
            inputs,
            outputs: self.outputs.clone(),
        })
    }

    pub fn input_ids(&self) -> Vec<DbcId> {
        self.inputs
            .iter()
            .map(|input_intermediate| input_intermediate.dbc_id())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DerivedKey;
    use blsttc::SecretKey;
    use std::collections::BTreeMap;

    #[test]
    fn test_input_sign() {
        let tx_amount = 3;

        // The input src tx is a dummy here.
        let input_intermediate = InputIntermediate {
            derived_key: DerivedKey::new(SecretKey::random()),
            amount: Amount { value: tx_amount },
            input_src_tx: DbcTransaction {
                inputs: vec![],
                outputs: vec![],
            },
        };

        let mut amounts = BTreeMap::new();
        amounts.insert(input_intermediate.dbc_id(), Amount { value: 3 });
        amounts.insert(
            DerivedKey::new(SecretKey::random()).dbc_id(),
            Amount { value: 1 },
        );
        amounts.insert(
            DerivedKey::new(SecretKey::random()).dbc_id(),
            Amount { value: 1 },
        );

        let tx_intermediate = TransactionIntermediate {
            inputs: vec![input_intermediate],
            outputs: vec![Output {
                dbc_id: DerivedKey::new(SecretKey::random()).dbc_id(),
                amount: Amount { value: tx_amount },
            }],
        };

        let signed_tx = tx_intermediate.sign().expect("Failed to sign transaction");

        assert!(signed_tx.verify().is_ok());
    }
}
