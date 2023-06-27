// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
mod tests {
    use crate::{
        mock,
        tests::{TinyInt, TinyVec},
        Dbc, DerivedKey, Error, Hash, MainKey, Result, SignedSpend, Spend, Token,
        TransactionBuilder,
    };
    use blsttc::SecretKey;
    use quickcheck_macros::quickcheck;
    use std::collections::{BTreeMap, BTreeSet};
    use std::iter::FromIterator;

    #[test]
    fn issue_genesis() -> Result<(), Error> {
        let (_spentbook_node, genesis_dbc, genesis, _amount) =
            mock::GenesisBuilder::init_genesis_single()?;

        let verified = genesis_dbc.verify(&genesis.main_key);
        assert!(verified.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let mut output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<u64>));
        output_amounts
            .push(mock::GenesisMaterial::GENESIS_AMOUNT - output_amounts.iter().sum::<u64>());

        let n_outputs = output_amounts.len();
        let output_amount: u64 = output_amounts.iter().sum();

        let (mut spentbook_node, genesis_dbc, genesis, _amount) =
            mock::GenesisBuilder::init_genesis_single()?;

        let first_output_key_map: BTreeMap<_, _> = output_amounts
            .iter()
            .map(|amount| {
                let main_key = MainKey::random_from_rng(&mut rng);
                let dbc_id_src = main_key.random_dbc_id_src(&mut rng);
                let dbc_id = dbc_id_src.dbc_id();
                (dbc_id, (main_key, dbc_id_src, Token::from_nano(*amount)))
            })
            .collect();

        let derived_key = genesis_dbc.derived_key(&genesis.main_key).unwrap();
        let dbc_builder = TransactionBuilder::default()
            .add_input_dbc(&genesis_dbc, &derived_key)?
            .add_outputs(
                first_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(Hash::default())?;

        // We make this a closure to keep the spentbook loop readable.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::Transaction(crate::transaction::Error::InconsistentDbcTransaction) => {
                    // Verify that no outputs were present and we got correct verification error.
                    assert_eq!(n_outputs, 0);
                    Ok(())
                }
                _ => Err(error),
            }
        };

        let tx = &dbc_builder.spent_tx;
        for signed_spend in dbc_builder.signed_spends() {
            match spentbook_node.log_spent(tx, signed_spend) {
                Ok(s) => s,
                Err(e) => return check_error(e),
            };
        }
        let output_dbcs = dbc_builder.build()?;

        for (dbc, output_amount) in output_dbcs.iter() {
            let (main_key, _, amount) = first_output_key_map.get(&dbc.id()).unwrap();
            let dbc_amount = dbc.amount()?.value;
            assert_eq!(amount.as_nano(), dbc_amount);
            assert_eq!(dbc_amount, output_amount.value);
            assert!(dbc.verify(main_key).is_ok());
        }

        assert_eq!(
            {
                let mut sum: u64 = 0;
                for (dbc, _) in output_dbcs.iter() {
                    // note: we could just use the amount provided by DbcBuilder::build()
                    // but we go further to verify the correct value is encrypted in the Dbc.
                    sum += dbc.amount()?.value
                }
                sum
            },
            output_amount
        );

        Ok(())
    }

    #[quickcheck]
    fn prop_dbc_transaction_many_to_many(
        // the amount of each input transaction
        input_amounts: TinyVec<TinyInt>,
        // The amount for each transaction output
        output_amounts: TinyVec<TinyInt>,
        // Include an invalid SignedSpends for the following inputs
        invalid_signed_spends: TinyVec<TinyInt>,
    ) -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let mut first_input_amounts =
            Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<u64>));
        first_input_amounts
            .push(mock::GenesisMaterial::GENESIS_AMOUNT - first_input_amounts.iter().sum::<u64>());

        let mut first_output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<u64>));
        first_output_amounts
            .push(mock::GenesisMaterial::GENESIS_AMOUNT - first_output_amounts.iter().sum::<u64>());

        let invalid_signed_spends = BTreeSet::from_iter(
            invalid_signed_spends
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        let (mut spentbook_node, genesis_dbc, genesis_material, _amount) =
            mock::GenesisBuilder::init_genesis_single()?;

        let mut first_output_key_map: BTreeMap<_, _> = first_input_amounts
            .iter()
            .map(|amount| {
                let main_key = MainKey::random_from_rng(&mut rng);
                let dbc_id_src = main_key.random_dbc_id_src(&mut rng);
                let dbc_id = dbc_id_src.dbc_id();
                (dbc_id, (main_key, dbc_id_src, Token::from_nano(*amount)))
            })
            .collect();

        let derived_key = genesis_dbc.derived_key(&genesis_material.main_key).unwrap();
        let dbc_builder = TransactionBuilder::default()
            .add_input_dbc(&genesis_dbc, &derived_key)?
            .add_outputs(
                first_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(Hash::default())?;

        // note: we make this a closure to keep the spentbook loop readable.
        let check_tx_error = |error: Error| -> Result<()> {
            match error {
                Error::Transaction(crate::transaction::Error::InconsistentDbcTransaction) => {
                    // Verify that no inputs were present and we got correct verification error.
                    assert!(first_input_amounts.is_empty());
                    Ok(())
                }
                _ => Err(error),
            }
        };

        let tx1 = dbc_builder.spent_tx.clone();
        for signed_spend in dbc_builder.signed_spends() {
            // normally spentbook verifies the tx, but here we skip it in order check reissue results.
            match spentbook_node.log_spent_and_skip_tx_verification(&tx1, signed_spend) {
                Ok(s) => s,
                Err(e) => return check_tx_error(e),
            };
        }

        let first_output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next tx.
        let second_inputs_dbcs: Vec<(Dbc, DerivedKey)> = first_output_dbcs
            .into_iter()
            .map(|(dbc, _)| {
                let (main_key, _, _) = first_output_key_map.remove(&dbc.id()).unwrap();
                let derived_key = dbc.derived_key(&main_key).unwrap();
                (dbc, derived_key)
            })
            .collect();

        let second_inputs_dbcs_len = second_inputs_dbcs.len();

        let second_output_key_map: BTreeMap<_, _> = first_output_amounts
            .iter()
            .map(|amount| {
                let main_key = MainKey::random_from_rng(&mut rng);
                let dbc_id_src = main_key.random_dbc_id_src(&mut rng);
                let dbc_id = dbc_id_src.dbc_id();
                (dbc_id, (main_key, dbc_id_src, Token::from_nano(*amount)))
            })
            .collect();

        let dbc_builder = TransactionBuilder::default()
            .add_input_dbcs(&second_inputs_dbcs)?
            .add_outputs(
                second_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(Hash::default())?;

        let dbc_output_amounts = first_output_amounts.clone();
        let output_total_amount: u64 = dbc_output_amounts.iter().sum();

        assert_eq!(second_inputs_dbcs_len, dbc_builder.spent_tx.inputs.len());
        assert_eq!(second_inputs_dbcs_len, dbc_builder.signed_spends().len());

        let tx2 = dbc_builder.spent_tx.clone();

        // note: we make this a closure because the logic is needed in
        // a couple places.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::SignedSpendInputLenMismatch { expected, .. } => {
                    assert!(!invalid_signed_spends.is_empty());
                    assert_eq!(second_inputs_dbcs_len, expected);
                }
                Error::SignedSpendInputIdMismatch => {
                    assert!(!invalid_signed_spends.is_empty());
                }
                Error::Transaction(crate::transaction::Error::InconsistentDbcTransaction) => {
                    if mock::GenesisMaterial::GENESIS_AMOUNT == output_total_amount {
                        // This can correctly occur if there are 0 outputs and inputs sum to zero.
                        //
                        // The error occurs because there is no output
                        // to match against the input amount, and also no way to
                        // know that the input amount is zero.
                        assert!(first_output_amounts.is_empty());
                        assert_eq!(first_input_amounts.iter().sum::<u64>(), 0);
                        assert!(!first_input_amounts.is_empty());
                    }
                }
                Error::Transaction(crate::transaction::Error::MissingTxInputs) => {
                    assert_eq!(first_input_amounts.len(), 0);
                }
                Error::InvalidSpendSignature(dbc_id) => {
                    let idx = tx2
                        .inputs
                        .iter()
                        .position(|i| i.dbc_id() == dbc_id)
                        .unwrap();
                    assert!(invalid_signed_spends.contains(&idx));
                }
                _ => panic!("Unexpected err {:#?}", error),
            }
            Ok(())
        };

        let tx = &dbc_builder.spent_tx;
        for (i, signed_spend) in dbc_builder.signed_spends().into_iter().enumerate() {
            let is_invalid_signed_spend = invalid_signed_spends.contains(&i);

            let _signed_spend = match i % 2 {
                0 if is_invalid_signed_spend => {
                    // drop this signed spend
                    continue;
                }
                1 if is_invalid_signed_spend => {
                    // spentbook verifies the tx.  If an error, we need to check it
                    match spentbook_node.log_spent(tx, signed_spend) {
                        Ok(s) => s,
                        Err(e) => return check_error(e),
                    };
                    SignedSpend {
                        spend: Spend {
                            dbc_id: *signed_spend.dbc_id(),
                            spent_tx: signed_spend.spend.spent_tx.clone(),
                            reason: Hash::default(),
                            amount: *signed_spend.amount(),
                            dbc_creation_tx: tx1.clone(),
                        },
                        derived_key_sig: SecretKey::random().sign([0u8; 32]),
                    }
                }
                _ => {
                    // spentbook verifies the tx.
                    match spentbook_node.log_spent(tx, signed_spend) {
                        Ok(()) => signed_spend.clone(),
                        Err(e) => return check_error(e),
                    }
                }
            };
        }

        let many_to_many_result = dbc_builder.build();

        match many_to_many_result {
            Ok(second_output_dbcs) => {
                assert_eq!(mock::GenesisMaterial::GENESIS_AMOUNT, output_total_amount);
                // assert!(invalid_signed_spends.iter().all(|i| i >= &tx2.inputs.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts.clone()),
                    BTreeSet::from_iter(first_output_amounts)
                );

                for (dbc, _) in second_output_dbcs.iter() {
                    let (main_key, _, _) = second_output_key_map.get(&dbc.id()).unwrap();
                    let dbc_confirm_result = dbc.verify(main_key);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    second_output_dbcs
                        .iter()
                        .enumerate()
                        .map(|(idx, _dbc)| { dbc_output_amounts[idx] })
                        .sum::<u64>(),
                    output_total_amount
                );
                Ok(())
            }
            Err(err) => check_error(err),
        }
    }
}
