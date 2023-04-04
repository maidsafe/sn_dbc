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
        tests::{TinyInt, TinyVec},
        Hash, MainKey, RevealedAmount,
    };
    use blsttc::SecretKeySet;
    use quickcheck_macros::quickcheck;
    use std::collections::{BTreeMap, BTreeSet};
    use std::iter::FromIterator;

    use crate::{
        mock, Dbc, DbcContent, Error, IndexedSignatureShare, Result, SpentProofContent,
        SpentProofShare, Token, TransactionBuilder,
    };

    #[test]
    fn issue_genesis() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let (spentbook_node, genesis_dbc, genesis, _revealed_amount) =
            mock::GenesisBuilder::init_genesis_single(&mut rng)?;

        let verified = genesis_dbc.verify(&genesis.main_key, &spentbook_node.key_manager);
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

        let (mut spentbook_node, genesis_dbc, genesis, _revealed_amount) =
            mock::GenesisBuilder::init_genesis_single(&mut rng)?;

        let first_output_key_map: BTreeMap<_, _> = output_amounts
            .iter()
            .map(|amount| {
                let main_key = MainKey::random_from_rng(&mut rng);
                let dbc_id_src = main_key.random_dbc_id_src(&mut rng);
                let dbc_id = dbc_id_src.dbc_id();
                (dbc_id, (main_key, dbc_id_src, Token::from_nano(*amount)))
            })
            .collect();

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(&genesis_dbc, &genesis.main_key)?
            .add_outputs(
                first_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(&mut rng)?;

        // We make this a closure to keep the spentbook loop readable.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::Transaction(crate::transaction::Error::InconsistentDbcTransaction) => {
                    // Verify that no outputs were present and we got correct verification error.
                    assert_eq!(n_outputs, 0);
                    Ok(())
                }
                Error::Transaction(crate::transaction::Error::InvalidInputBlindedAmount) => {
                    // Verify that no outputs were present and we got correct verification error.
                    assert_eq!(n_outputs, 0);
                    Ok(())
                }
                _ => Err(error),
            }
        };

        for (input_id, tx) in dbc_builder.inputs() {
            let spent_proof_share =
                match spentbook_node.log_spent(input_id, tx.clone(), Hash::default()) {
                    Ok(s) => s,
                    Err(e) => return check_error(e),
                };
            dbc_builder = dbc_builder
                .add_spent_proof_share(spent_proof_share)
                .add_spent_transaction(tx);
        }
        let output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        for (dbc, revealed_amount) in output_dbcs.iter() {
            let (main_key, _, amount) = first_output_key_map.get(&dbc.id()).unwrap();
            let dbc_amount = revealed_amount.value();
            assert!(amount.as_nano() == dbc_amount);
            assert!(dbc.verify(main_key, &spentbook_node.key_manager,).is_ok());
        }

        assert_eq!(
            {
                let mut sum: u64 = 0;
                for (dbc, _) in output_dbcs.iter() {
                    let (main_key, _, _) = first_output_key_map.get(&dbc.id()).unwrap();
                    // note: we could just use revealed amount provided by DbcBuilder::build()
                    // but we go further to verify the correct value is encrypted in the Dbc.
                    sum += dbc.revealed_amount(main_key)?.value()
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
        // Include an invalid SpentProofs for the following inputs
        invalid_spent_proofs: TinyVec<TinyInt>,
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

        let invalid_spent_proofs = BTreeSet::from_iter(
            invalid_spent_proofs
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        let (mut spentbook_node, genesis_dbc, genesis_material, _revealed_amount) =
            mock::GenesisBuilder::init_genesis_single(&mut rng)?;

        let mut first_output_key_map: BTreeMap<_, _> = first_input_amounts
            .iter()
            .map(|amount| {
                let main_key = MainKey::random_from_rng(&mut rng);
                let dbc_id_src = main_key.random_dbc_id_src(&mut rng);
                let dbc_id = dbc_id_src.dbc_id();
                (dbc_id, (main_key, dbc_id_src, Token::from_nano(*amount)))
            })
            .collect();

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(&genesis_dbc, &genesis_material.main_key)?
            .add_outputs(
                first_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(&mut rng)?;

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

        for (input_id, tx) in dbc_builder.inputs() {
            // normally spentbook verifies the tx, but here we skip it in order check reissue results.
            let spent_proof_share = match spentbook_node.log_spent_and_skip_tx_verification(
                input_id,
                Hash::default(),
                tx.clone(),
            ) {
                Ok(s) => s,
                Err(e) => return check_tx_error(e),
            };
            dbc_builder = dbc_builder
                .add_spent_proof_share(spent_proof_share)
                .add_spent_transaction(tx);
        }

        let first_output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        // The outputs become inputs for next tx.
        let second_inputs_dbcs: Vec<(Dbc, MainKey)> = first_output_dbcs
            .into_iter()
            .map(|(dbc, _revealed_amount)| {
                let (main_key, _, _) = first_output_key_map.remove(&dbc.id()).unwrap();
                (dbc, main_key)
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

        let mut dbc_builder = TransactionBuilder::default()
            .add_inputs_dbc(second_inputs_dbcs)?
            .add_outputs(
                second_output_key_map
                    .values()
                    .map(|(_, dbc_id_src, amount)| (*amount, *dbc_id_src)),
            )
            .build(&mut rng)?;

        let dbc_output_amounts = first_output_amounts.clone();
        let output_total_amount: u64 = dbc_output_amounts.iter().sum();

        assert_eq!(second_inputs_dbcs_len, dbc_builder.transaction.inputs.len());
        assert_eq!(second_inputs_dbcs_len, dbc_builder.inputs().len());

        let tx2 = dbc_builder.transaction.clone();

        // note: we make this a closure because the logic is needed in
        // a couple places.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::SpentProofInputLenMismatch { expected, .. } => {
                    assert!(!invalid_spent_proofs.is_empty());
                    assert_eq!(second_inputs_dbcs_len, expected);
                }
                Error::SpentProofInputIdMismatch => {
                    assert!(!invalid_spent_proofs.is_empty());
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
                Error::Transaction(crate::transaction::Error::TransactionMustHaveAnInput) => {
                    assert_eq!(first_input_amounts.len(), 0);
                }
                Error::FailedSignature => {
                    assert!(!invalid_spent_proofs.is_empty());
                }
                Error::InvalidSpentProofSignature(dbc_id) => {
                    let idx = tx2
                        .inputs
                        .iter()
                        .position(|i| i.dbc_id() == dbc_id)
                        .unwrap();
                    assert!(invalid_spent_proofs.contains(&idx));
                }
                _ => panic!("Unexpected err {:#?}", error),
            }
            Ok(())
        };

        for (i, (input_id, tx)) in dbc_builder.inputs().into_iter().enumerate() {
            let is_invalid_spent_proof = invalid_spent_proofs.contains(&i);

            let spent_proof_share = match i % 2 {
                0 if is_invalid_spent_proof => {
                    // drop this spent proof
                    continue;
                }
                1 if is_invalid_spent_proof => {
                    // spentbook verifies the tx.  If an error, we need to check it
                    let spent_proof_share =
                        match spentbook_node.log_spent(input_id, tx.clone(), Hash::default()) {
                            Ok(s) => s,
                            Err(e) => return check_error(e),
                        };
                    SpentProofShare {
                        content: SpentProofContent {
                            dbc_id: *spent_proof_share.dbc_id(),
                            transaction_hash: spent_proof_share.transaction_hash(),
                            reason: Hash::default(),
                            blinded_amount: *spent_proof_share.blinded_amount(),
                        },
                        spentbook_pks: spent_proof_share.spentbook_pks,
                        spentbook_sig_share: IndexedSignatureShare::new(
                            0,
                            SecretKeySet::random(1, &mut rng)
                                .secret_key_share(1)
                                .sign([0u8; 32]),
                        ),
                    }
                }
                _ => {
                    // spentbook verifies the tx.
                    match spentbook_node.log_spent(input_id, tx.clone(), Hash::default()) {
                        Ok(s) => s,
                        Err(e) => return check_error(e),
                    }
                }
            };

            dbc_builder = dbc_builder
                .add_spent_proof_share(spent_proof_share)
                .add_spent_transaction(tx);
        }

        let many_to_many_result = dbc_builder.build(&spentbook_node.key_manager);

        match many_to_many_result {
            Ok(second_output_dbcs) => {
                assert_eq!(mock::GenesisMaterial::GENESIS_AMOUNT, output_total_amount);
                assert!(invalid_spent_proofs.iter().all(|i| i >= &tx2.inputs.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts.clone()),
                    BTreeSet::from_iter(first_output_amounts)
                );

                for (dbc, _revealed_amount) in second_output_dbcs.iter() {
                    let (main_key, _, _) = second_output_key_map.get(&dbc.id()).unwrap();
                    let dbc_confirm_result = dbc.verify(main_key, &spentbook_node.key_manager);
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

    #[quickcheck]
    #[ignore]
    fn prop_in_progress_transaction_can_be_continued_across_churn() {
        todo!()
    }

    #[quickcheck]
    #[ignore]
    fn prop_reject_invalid_prefix() {
        todo!();
    }

    #[test]
    fn test_inputs_are_verified() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let (spentbook_node, _genesis_dbc, _genesis, _revealed_amount) =
            mock::GenesisBuilder::init_genesis_single(&mut rng)?;

        let output_1_main_key = MainKey::random_from_rng(&mut rng);
        let output_1_dbc_id_src = output_1_main_key.random_dbc_id_src(&mut rng);

        let dbc_builder = TransactionBuilder::default()
            .add_output(Token::from_nano(100), output_1_dbc_id_src)
            .build(&mut rng)?;

        let revealed_amount = dbc_builder.revealed_outputs[0].revealed_amount;
        let secret_key = output_1_main_key.derive_key(&output_1_dbc_id_src.derivation_index);

        let output_2_main_key = MainKey::random_from_rng(&mut rng);
        let output_2_dbc_id_src = output_2_main_key.random_dbc_id_src(&mut rng);

        let fraud_dbc_builder = TransactionBuilder::default()
            .add_input_by_secrets(secret_key, revealed_amount)
            .add_output(Token::from_nano(100), output_2_dbc_id_src)
            .build(&mut rng)?;

        let result = fraud_dbc_builder.build(&spentbook_node.key_manager);

        // fixme: more/better assertions.
        assert!(result.is_err());
        Ok(())
    }

    /// This tests (and demonstrates) how the system handles a mis-match between the
    /// blinded amount and the encrypted revealed amount.
    ///
    /// Normally these should be the same, however a malicious user or buggy
    /// implementation could produce different values.  The spentbook never sees the
    /// RevealedAmount and thus cannot detect or prevent this situation.
    ///
    /// A correct spentbook implementation must verify the transaction before
    /// writing, including checking that (blinded) amounts are equal. So the spentbook
    /// will reject a tx with an output using an invalid amount, thereby preventing
    /// the input from becoming burned (unspendable).
    ///
    /// To be on the safe side, the recipient wallet should check that the amounts
    /// match upon receipt.
    ///
    /// Herein we do the following to test:
    ///
    /// 1. Produce the genesis Dbc (a) with value 1000
    /// 2. Reissue genesis Dbc (a) to Dbc (b) with value 1000.
    /// 3. modify b's revealed_amount.value to 2000, thereby creating b_fudged
    ///    (which a bad actor could pass to innocent recipient).
    /// 4. Check if the amounts match, using the provided API.
    ///      Assert that APIs report that they do not match.
    /// 5. Create a tx with (b_fudged) as input, and Dbc (c) with amount 2000 as output.
    /// 6. Attempt to write this tx to the spentbook.
    ///      This will fail because the input and output amounts are not equal.
    /// 7. Force an invalid write to the spentbook
    /// 8. Attempt to write to spentbook again using the correct amount (1000).
    ///      This will fail because b was already marked as spent in the spentbook.
    ///      This demonstrates how an input can become burned if spentbook does
    ///      not verify tx.
    /// 9. Re-write spentbook log correctly using the correct amount.
    ///      Verify that the write succeeds.
    #[test]
    fn test_mismatched_amount_and_blinded_amount() -> Result<(), Error> {
        // ----------
        // 1. produce a standard genesis DBC (a) with value 1000
        // ----------
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let output_amount = 1000;

        let (mut spentbook, genesis_dbc, a_dbc, a_main_key) =
            crate::dbc::tests::generate_dbc_and_its_main_key(output_amount, &mut rng)?;

        // ----------
        // 2. Spend genesis Dbc (a) to Dbc (b) with value 1000.
        // ----------

        // First we create a regular/valid tx reissuing the genesis Dbc to a
        // single new Dbc of the same amount.

        let b_output_main_key = MainKey::random_from_rng(&mut rng);
        let b_output_dbc_id_src = b_output_main_key.random_dbc_id_src(&mut rng);

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(&a_dbc, &a_main_key)?
            .add_output(Token::from_nano(output_amount), b_output_dbc_id_src)
            .build(&mut rng)?;

        for (input_id, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook.log_spent(
                    input_id,
                    tx.clone(),
                    Hash::default(),
                )?)
                .add_spent_transaction(tx);
        }

        // build output Dbcs
        let b_output_dbcs = dbc_builder.build(&spentbook.key_manager)?;
        let (b_dbc, ..) = &b_output_dbcs[0];

        // ----------
        // 3. Modify b's revealed_amount.value to AMOUNT * 2, thereby creating b_fudged
        //    (which a bad actor could pass to innocent recipient).
        // ----------

        // Replace the encrypted secret amount with an encrypted secret claiming
        // twice the amount.
        let a_revealed_amount = a_dbc.revealed_amount(&a_main_key)?;
        let b_fudged_revealed_amount = RevealedAmount::from((
            a_revealed_amount.value() * 2, // Claim we are paying twice the amount.
            a_revealed_amount.blinding_factor(), // Use the real blinding factor.
        ));

        let (b_output_dbc, ..) = b_output_dbcs[0].clone();

        let mut b_fudged_output_dbc = b_output_dbc.clone();
        b_fudged_output_dbc.content = DbcContent::from((
            &b_output_dbc_id_src.public_address,
            &b_output_dbc_id_src.derivation_index,
            b_fudged_revealed_amount,
        ));

        // obtain revealed amount (true and fudged)
        let revealed_amount = b_output_dbc.revealed_amount(&b_output_main_key)?;
        let fudged_amount = b_fudged_output_dbc.revealed_amount(&b_output_main_key)?;

        // confirm the amount is 2000.
        assert_eq!(fudged_amount.value(), output_amount * 2);

        // ----------
        // 4. Check if the amounts match, using the provided API.
        //      assert that APIs report they do not match.
        // ----------

        // confirm the mis-match is detectable by the recipient who has the key to access the secrets.
        assert!(matches!(
            b_fudged_output_dbc.verify(&b_output_main_key, &spentbook.key_manager),
            Err(Error::BlindedAmountsDoNotMatch)
        ));

        // Confirm that the sum of output revealed does not match the blinded amount.
        assert_ne!(
            b_fudged_output_dbc
                .revealed_amount(&b_output_main_key)?
                .value(),
            output_amount
        );

        // ----------
        // 5. Create a tx with (b_fudged) as input, and Dbc (c) with amount 2000 as output.
        // ----------

        let c_output_main_key = MainKey::random_from_rng(&mut rng);
        let c_output_dbc_id_src = c_output_main_key.random_dbc_id_src(&mut rng);

        let mut dbc_builder_fudged = crate::TransactionBuilder::default()
            .add_input_dbc(&b_fudged_output_dbc, &b_output_main_key)?
            .add_output(Token::from_nano(fudged_amount.value()), c_output_dbc_id_src)
            .build(&mut rng)?;

        // ----------
        // 6. Attempt to write this tx to the spentbook.
        //    This will fail because the input and output amounts are not equal.
        // ----------

        for (input_id, tx) in dbc_builder_fudged.inputs() {
            match spentbook.log_spent(input_id, tx, Hash::default()) {
                Err(Error::Transaction(crate::transaction::Error::InvalidInputBlindedAmount)) => {}
                _ => panic!(
                    "Expecting `Error::Transaction(transaction::Error::InvalidInputBlindedAmount)`"
                ),
            }
        }

        // ----------
        // 7. Force an invalid write to the spentbook
        //    Subsequent verification will fail for the same reason as (6)
        // ----------

        // Normally spentbook verifies the tx, but here we skip it in order to obtain
        // a spentproof with an invalid tx.
        for (input_id, tx) in dbc_builder_fudged.inputs() {
            let spent_proof_share = spentbook.log_spent_and_skip_tx_verification(
                input_id,
                Hash::default(),
                tx.clone(),
            )?;
            dbc_builder_fudged = dbc_builder_fudged
                .add_spent_proof_share(spent_proof_share)
                .add_spent_transaction(tx);
        }

        // The builder should give an error because the sum(inputs) does not equal sum(outputs)
        let result_fudged = dbc_builder_fudged.build(&spentbook.key_manager);

        match result_fudged {
            Err(Error::Transaction(crate::transaction::Error::InvalidInputBlindedAmount)) => {}
            _ => panic!(
                "Expecting `Error::Transaction(transaction::Error::InvalidInputBlindedAmount)`"
            ),
        }

        // ----------
        // 8. Attempt to spend again using the correct amount (1000).
        //    This will fail because b was already marked as spent in the spentbook.
        //    This demonstrates how an input can become burned if spentbook does
        //    not verify tx.
        // ----------

        // So at this point we have written an invalid Tx to the spentbook associated
        // with the input Dbc.  This means the input Dbc is burned (unspendable).
        //
        // Next we build a new Tx with the correct amount and attempt to spend.
        // But since we have the old spentproof for the invalid tx, this spend
        // is doomed to fail also.  We can't write to the spentbook again
        // because entries are immutable.

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_by_secrets(
                b_output_main_key.derive_key(&b_output_dbc_id_src.derivation_index),
                revealed_amount,
            )
            .add_output(
                Token::from_nano(revealed_amount.value()),
                c_output_dbc_id_src,
            )
            .build(&mut rng)?;

        let dbc_builder_bad_proof = dbc_builder.clone();
        for (input_id, tx) in dbc_builder_bad_proof.inputs() {
            let result =
                spentbook.log_spent_and_skip_tx_verification(input_id, Hash::default(), tx);

            // The builder should return an error because the spentproof does not match the tx.
            match result {
                Err(Error::Mock(mock::Error::PublicKeyAlreadySpent)) => {}
                _ => panic!("Expected `Error::Mock(mock::Error::PublicKeyAlreadySpent)`"),
            }
        }

        // ----------
        // 9. Re-write spentbook log correctly and attempt to spend using the
        //    correct amount.
        //      Verify that this spend succeeds.
        // ----------

        // The input to the fudged tx has already been recorded as spent in the spentbook
        // so it is effectively burned (forever unspendable).  In a production system we
        // would be out-of-luck.
        //
        // The recipient's wallet should normally avoid this situation by calling
        // Dbc::verify() immediately upon receipt of Dbc.
        //
        // For the test case/demo, we can remedy by:
        //
        // Make a new spentbook and replay the first three tx, plus the new tx_true
        // Note that the new spentbook uses the same signing key as the original
        let mut new_spentbook = mock::SpentBookNode::from(spentbook.key_manager);
        let _genesis_spent_proof_share = new_spentbook.log_spent(
            genesis_dbc.transaction.inputs[0].dbc_id,
            genesis_dbc.transaction.clone(),
            Hash::default(),
        )?;
        let _a_spent_proof_share = new_spentbook.log_spent(
            a_dbc.transaction.inputs[0].dbc_id,
            a_dbc.transaction.clone(),
            Hash::default(),
        )?;
        let _b_spent_proof_share = new_spentbook.log_spent(
            b_dbc.transaction.inputs[0].dbc_id,
            b_dbc.transaction.clone(),
            Hash::default(),
        )?;

        for (input_id, tx) in dbc_builder.inputs() {
            let spent_proof_share =
                new_spentbook.log_spent(input_id, tx.clone(), Hash::default())?;
            dbc_builder = dbc_builder
                .add_spent_proof_share(spent_proof_share)
                .add_spent_transaction(tx);
        }

        // Now that the SpentBook is correct, we have a valid spent_proof_share
        // and can successfully build our Dbc(s)
        //
        // This simulates the situation where recipient wallet later obtains the correct
        // secrets and spends them.
        let result = dbc_builder.build(&new_spentbook.key_manager);

        assert!(result.is_ok());

        Ok(())
    }
}
