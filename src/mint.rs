// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
mod tests {

    use crate::tests::{TinyInt, TinyVec};
    use blst_ringct::DecoyInput;
    use blsttc::{SecretKey, SecretKeySet};
    use quickcheck_macros::quickcheck;
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    use crate::{
        Amount, AmountSecrets, Dbc, DbcContent, Error, GenesisBuilderMock, GenesisMaterial,
        IndexedSignatureShare, KeyImage, Owner, OwnerOnce, Result, SpentBookNodeMock,
        SpentProofContent, SpentProofShare, TransactionBuilder,
    };

    #[test]
    fn issue_genesis() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let (spentbook_node, genesis_dbc, genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng)?;

        let verified = genesis_dbc.verify(
            &genesis.owner_once.owner_base().secret_key()?,
            &spentbook_node.key_manager,
        );
        assert!(verified.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let mut output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        output_amounts
            .push(GenesisMaterial::GENESIS_AMOUNT - output_amounts.iter().sum::<Amount>());

        let n_outputs = output_amounts.len();
        let output_amount = output_amounts.iter().sum();

        let (mut spentbook_node, genesis_dbc, _genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng)?;

        let owners: Vec<OwnerOnce> = (0..output_amounts.len())
            .map(|_| OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng))
            .collect();

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(
                &genesis_dbc,
                &genesis_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng,
            )?
            .add_outputs_by_amount(
                output_amounts
                    .iter()
                    .enumerate()
                    .map(|(idx, a)| (*a, owners[idx].clone())),
            )
            .build(&mut rng)?;

        // We make this a closure to keep the spentbook loop readable.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::RingCt(
                    blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
                ) => {
                    // Verify that no outputs were present and we got correct verification error.
                    assert_eq!(n_outputs, 0);
                    Ok(())
                }
                Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing) => {
                    // Verify that no outputs were present and we got correct verification error.
                    assert_eq!(n_outputs, 0);
                    Ok(())
                }
                _ => Err(error),
            }
        };

        for (key_image, tx) in dbc_builder.inputs() {
            let spent_proof_share = match spentbook_node.log_spent(key_image, tx.clone()) {
                Ok(s) => s,
                Err(e) => return check_error(e),
            };
            dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
        }
        let output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        for (dbc, owner_once, amount_secrets) in output_dbcs.iter() {
            let dbc_amount = amount_secrets.amount();
            assert!(output_amounts.iter().any(|a| *a == dbc_amount));
            assert!(dbc
                .verify(
                    &owner_once.owner_base().secret_key().unwrap(),
                    &spentbook_node.key_manager,
                )
                .is_ok());
        }

        assert_eq!(
            {
                let mut sum: Amount = 0;
                for (dbc, owner_once, _amount_secrets) in output_dbcs.iter() {
                    // note: we could just use amount_secrets provided by DbcBuilder::build()
                    // but we go further to verify the correct value is encrypted in the Dbc.
                    sum += dbc
                        .amount_secrets(&owner_once.owner_base().secret_key()?)?
                        .amount()
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
        // The number of decoy inputs
        num_decoy_inputs: TinyInt,
    ) -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let mut input_amounts =
            Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        input_amounts.push(GenesisMaterial::GENESIS_AMOUNT - input_amounts.iter().sum::<Amount>());

        let mut output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        output_amounts
            .push(GenesisMaterial::GENESIS_AMOUNT - output_amounts.iter().sum::<Amount>());

        let invalid_spent_proofs = BTreeSet::from_iter(
            invalid_spent_proofs
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        // We apply mod 2 because there is only one available decoy (genesis pubkey)
        // in the spentbook.  To test decoys further, we would need to devise a test
        // something like:  genesis --> 100 outputs --> x outputs --> y outputs.
        let num_decoy_inputs: usize = num_decoy_inputs.coerce::<usize>() % 2;

        let (mut spentbook_node, genesis_dbc, _genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng)?;

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(
                &genesis_dbc,
                &genesis_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng,
            )?
            .add_outputs_by_amount(input_amounts.iter().copied().map(|amount| {
                let owner_once =
                    OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);
                (amount, owner_once)
            }))
            .build(&mut rng)?;

        // note: we make this a closure to keep the spentbook loop readable.
        let check_tx_error = |error: Error| -> Result<()> {
            match error {
                Error::RingCt(
                    blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
                ) => {
                    // Verify that no inputs were present and we got correct verification error.
                    assert!(input_amounts.is_empty());
                    Ok(())
                }
                _ => Err(error),
            }
        };

        for (key_image, tx) in dbc_builder.inputs() {
            // normally spentbook verifies the tx, but here we skip it in order check reissue results.
            let spent_proof_share =
                match spentbook_node.log_spent_and_skip_tx_verification(key_image, tx.clone()) {
                    Ok(s) => s,
                    Err(e) => return check_tx_error(e),
                };
            dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
        }

        let output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        // The outputs become inputs for next tx.
        let inputs_dbcs: Vec<(Dbc, SecretKey, Vec<DecoyInput>)> = output_dbcs
            .into_iter()
            .map(|(dbc, owner_once, _amount_secrets)| {
                (
                    dbc,
                    owner_once.owner_base().secret_key().unwrap(),
                    spentbook_node.random_decoys(num_decoy_inputs, &mut rng),
                )
            })
            .collect();

        let owners: Vec<OwnerOnce> = (0..=output_amounts.len())
            .map(|_| OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng))
            .collect();

        let outputs = output_amounts.clone().into_iter().zip(owners);

        let mut dbc_builder = TransactionBuilder::default()
            .add_inputs_dbc(inputs_dbcs.clone(), &mut rng)?
            .add_outputs_by_amount(outputs.clone())
            .build(&mut rng)?;

        let dbc_output_amounts: Vec<Amount> = outputs.map(|(amt, _)| amt).collect();
        let output_total_amount: Amount = dbc_output_amounts.iter().sum();

        assert_eq!(inputs_dbcs.len(), dbc_builder.transaction.mlsags.len());
        assert_eq!(inputs_dbcs.len(), dbc_builder.inputs().len());

        let tx2 = dbc_builder.transaction.clone();

        // note: we make this a closure because the logic is needed in
        // a couple places.
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::SpentProofInputLenMismatch => {
                    assert!(!invalid_spent_proofs.is_empty());
                }
                Error::SpentProofInputKeyImageMismatch => {
                    assert!(!invalid_spent_proofs.is_empty());
                }
                Error::RingCt(
                    blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
                ) => {
                    if GenesisMaterial::GENESIS_AMOUNT == output_total_amount {
                        // This can correctly occur if there are 0 outputs and inputs sum to zero.
                        //
                        // The error occurs because there is no output with a commitment
                        // to match against the input commitment, and also no way to
                        // know that the input amount is zero.
                        assert!(output_amounts.is_empty());
                        assert_eq!(input_amounts.iter().sum::<Amount>(), 0);
                        assert!(!input_amounts.is_empty());
                    }
                }
                Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing) => {
                    assert!(!invalid_spent_proofs.is_empty());
                }
                Error::RingCt(blst_ringct::Error::TransactionMustHaveAnInput) => {
                    assert_eq!(input_amounts.len(), 0);
                }
                Error::FailedSignature => {
                    assert!(!invalid_spent_proofs.is_empty());
                }
                Error::InvalidSpentProofSignature(key, _msg) => {
                    let idx = tx2
                        .mlsags
                        .iter()
                        .position(|i| Into::<KeyImage>::into(i.key_image) == key)
                        .unwrap();
                    assert!(invalid_spent_proofs.contains(&idx));
                }
                _ => panic!("Unexpected err {:#?}", error),
            }
            Ok(())
        };

        for (i, (key_image, tx)) in dbc_builder.inputs().into_iter().enumerate() {
            let is_invalid_spent_proof = invalid_spent_proofs.contains(&i);

            let spent_proof_share = match i % 2 {
                0 if is_invalid_spent_proof => {
                    // drop this spent proof
                    continue;
                }
                1 if is_invalid_spent_proof => {
                    // spentbook verifies the tx.  If an error, we need to check it
                    let spent_proof_share = match spentbook_node.log_spent(key_image, tx.clone()) {
                        Ok(s) => s,
                        Err(e) => return check_error(e),
                    };
                    SpentProofShare {
                        content: SpentProofContent {
                            key_image: *spent_proof_share.key_image(),
                            transaction_hash: spent_proof_share.transaction_hash(),
                            public_commitments: spent_proof_share.public_commitments().clone(),
                        },
                        spentbook_pks: spent_proof_share.spentbook_pks,
                        spentbook_sig_share: IndexedSignatureShare::new(
                            0,
                            SecretKeySet::random(1, &mut rng)
                                .secret_key_share(1)
                                .sign(&[0u8; 32]),
                        ),
                    }
                }
                _ => {
                    // spentbook verifies the tx.
                    match spentbook_node.log_spent(key_image, tx.clone()) {
                        Ok(s) => s,
                        Err(e) => return check_error(e),
                    }
                }
            };

            dbc_builder = dbc_builder.add_spent_proof_share(spent_proof_share);
        }

        let many_to_many_result = dbc_builder.build(&spentbook_node.key_manager);

        match many_to_many_result {
            Ok(output_dbcs) => {
                assert_eq!(GenesisMaterial::GENESIS_AMOUNT, output_total_amount);
                assert!(invalid_spent_proofs.iter().all(|i| i >= &tx2.mlsags.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts.clone()),
                    BTreeSet::from_iter(output_amounts)
                );

                for (dbc, owner_once, _amount_secrets) in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.verify(
                        &owner_once.owner_base().secret_key()?,
                        &spentbook_node.key_manager,
                    );
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs
                        .iter()
                        .enumerate()
                        .map(|(idx, _dbc)| { dbc_output_amounts[idx] })
                        .sum::<Amount>(),
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

        let (spentbook_node, _genesis_dbc, _genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng)?;

        let output1_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let dbc_builder = TransactionBuilder::default()
            .add_output_by_amount(100, output1_owner.clone())
            .build(&mut rng)?;

        let amount_secrets = AmountSecrets::from(dbc_builder.revealed_commitments[0]);
        let secret_key = output1_owner.as_owner().secret_key()?;
        let decoy_inputs = vec![]; // no decoys.

        let output2_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let fraud_dbc_builder = TransactionBuilder::default()
            .add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, &mut rng)
            .add_output_by_amount(100, output2_owner)
            .build(&mut rng)?;

        let result = fraud_dbc_builder.build(&spentbook_node.key_manager);

        // fixme: more/better assertions.
        assert!(result.is_err());
        Ok(())
    }

    /// This tests (and demonstrates) how the system handles a mis-match between the
    /// committed amount and amount encrypted in AmountSecrets.
    ///
    /// Normally these should be the same, however a malicious user or buggy
    /// implementation could produce different values.  The spentbook never sees the
    /// AmountSecrets and thus cannot detect or prevent this this situation.
    ///
    /// A correct spentbook implementation must verify the transaction before
    /// writing, including checking that commitments match. So the spentbook
    /// will reject a tx with an output using an invalid amount, thereby preventing
    /// the input from becoming burned (unspendable).
    ///
    /// To be on the safe side, the recipient wallet should check that the amounts
    /// match upon receipt.
    ///
    /// Herein we do the following to test:
    ///
    /// 1. produce a standard genesis DBC (a) with value 1000
    /// 2. reissue genesis DBC (a) to Dbc (b)  with value 1000.
    /// 3. modify b's amount secrets.amount to 2000, thereby creating b_fudged
    ///    (which a bad actor could pass to innocent recipient).
    /// 4. Check if the amounts match, using the provided API.
    ///      assert that APIs report they do not match.
    /// 5. create a tx with (b_fudged) as input, and Dbc (c) with amount 2000 as output.
    /// 6. Attempt to write this tx to the spentbook.
    ///    This will fail because the input and output commitments do not match.
    /// 7. Force an invalid write to the spentbook
    /// 8. Attempt to write to spentbook again using the correct amount (1000).
    ///    This will fail because b was already marked as spent in the spentbook.
    ///    This demonstrates how an input can become burned if spentbook does
    ///    not verify tx.
    /// 9. Re-write spentbook log correctly using the correct amount that was
    ///    committed to.  Verify that the write succeeds.
    #[test]
    fn test_mismatched_amount_and_commitment() -> Result<(), Error> {
        // ----------
        // 1. produce a standard genesis DBC (a) with value 1000
        // ----------
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let output_amount = 1000;

        let (mut spentbook, genesis_dbc, starting_dbc, _change_dbc) =
            crate::dbc::tests::generate_dbc_of_value(output_amount, &mut rng)?;

        // ----------
        // 2. spend genesis DBC (a) to Dbc (b)  with value 1000.
        // ----------

        // First we create a regular/valid tx reissuing the genesis DBC to a
        // single new DBC of the same amount.

        let output_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let mut dbc_builder = TransactionBuilder::default()
            .add_input_dbc(
                &starting_dbc,
                &starting_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng,
            )?
            .add_output_by_amount(output_amount, output_owner.clone())
            .build(&mut rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder =
                dbc_builder.add_spent_proof_share(spentbook.log_spent(key_image, tx.clone())?);
        }

        // build output DBCs
        let output_dbcs = dbc_builder.build(&spentbook.key_manager)?;
        let (b_dbc, ..) = &output_dbcs[0];

        // ----------
        // 3. modify b's amount secrets.amount to AMOUNT/2, thereby creating b_fudged
        //    (which a bad actor could pass to innocent recipient).
        // ----------

        // Replace the encrypted secret amount with an encrypted secret claiming
        // twice the committed value.
        let starting_amount_secrets = starting_dbc.amount_secrets_bearer()?;
        let fudged_amount_secrets = AmountSecrets::from((
            starting_amount_secrets.amount() * 2, // Claim we are paying twice the committed value
            starting_amount_secrets.blinding_factor(), // Use the real blinding factor
        ));

        let (true_output_dbc, ..) = output_dbcs[0].clone();
        let c = &true_output_dbc.content;

        let mut fudged_output_dbc = true_output_dbc.clone();
        fudged_output_dbc.content = DbcContent::from((
            c.owner_base.clone(),
            output_owner.derivation_index,
            fudged_amount_secrets,
        ));

        // obtain amount secrets (true and fudged)
        let true_secrets =
            true_output_dbc.amount_secrets(&output_owner.owner_base().secret_key()?)?;
        let fudged_secrets =
            fudged_output_dbc.amount_secrets(&output_owner.owner_base().secret_key()?)?;

        // confirm the secret amount is 2000.
        assert_eq!(fudged_secrets.amount(), output_amount * 2);

        // ----------
        // 4. Check if the amounts match, using the provided API.
        //      assert that APIs report they do not match.
        // ----------

        // confirm the mis-match is detectable by the recipient who has the key to access the secrets.
        assert!(matches!(
            fudged_output_dbc.verify(
                &output_owner.owner_base().secret_key()?,
                &spentbook.key_manager
            ),
            Err(Error::AmountCommitmentsDoNotMatch)
        ));

        // confirm that the sum of output secrets does not match the committed amount.
        assert_ne!(
            fudged_output_dbc
                .amount_secrets(&output_owner.owner_base().secret_key()?)?
                .amount(),
            output_amount
        );

        // ----------
        // 5. create a tx with (b_fudged) as input, and Dbc (c) with amount 2000 as output.
        // ----------

        let decoy_inputs = vec![];

        let output_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let mut dbc_builder_fudged = crate::TransactionBuilder::default()
            .add_input_dbc(
                &fudged_output_dbc,
                &fudged_output_dbc.owner_base().secret_key()?,
                decoy_inputs.clone(),
                &mut rng,
            )?
            .add_output_by_amount(fudged_secrets.amount(), output_owner.clone())
            .build(&mut rng)?;

        // ----------
        // 6. Attempt to write this tx to the spentbook.
        //    This will fail because the input and output commitments do not match.
        // ----------

        for (key_image, tx) in dbc_builder_fudged.inputs() {
            match spentbook.log_spent(key_image, tx) {
                Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {}
                _ => panic!("Expecting RingCt Error::InvalidHiddenCommitmentInRing"),
            }
        }

        // ----------
        // 7. Force an invalid write to the spentbook
        //    Subsequent verification will fail for the same reason as (6)
        // ----------

        // normally spentbook verifies the tx, but here we skip it in order to obtain
        // a spentproof with an invalid tx.
        for (key_image, tx) in dbc_builder_fudged.inputs() {
            let spent_proof_share = spentbook.log_spent_and_skip_tx_verification(key_image, tx)?;
            dbc_builder_fudged = dbc_builder_fudged.add_spent_proof_share(spent_proof_share);
        }

        // The builder should give an error because the sum(inputs) does not equal sum(outputs)
        let result_fudged = dbc_builder_fudged.build(&spentbook.key_manager);

        match result_fudged {
            Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {}
            _ => panic!("Expecting RingCt Error::InvalidHiddenCommitmentInRing"),
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

        let mut dbc_builder_true = TransactionBuilder::default()
            .add_input_by_secrets(
                fudged_output_dbc.owner_once_bearer()?.secret_key()?,
                true_secrets.clone(),
                decoy_inputs,
                &mut rng,
            )
            .add_output_by_amount(true_secrets.amount(), output_owner)
            .build(&mut rng)?;

        let dbc_builder_bad_proof = dbc_builder_true.clone();
        for (key_image, tx) in dbc_builder_bad_proof.inputs() {
            let result = spentbook.log_spent_and_skip_tx_verification(key_image, tx);

            // The builder should return an error because the spentproof does not match the tx.
            match result {
                Err(Error::SpentbookKeyImageAlreadySpent) => {}
                _ => panic!("Expected Error::SpentbookKeyImageAlreadySpent"),
            }
        }

        // ----------
        // 9. Re-write spentbook log correctly and attempt to spend using the
        //    correct amount that was committed to.
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
        let mut new_spentbook = SpentBookNodeMock::from(spentbook.key_manager);
        let _genesis_spent_proof_share = new_spentbook.log_spent(
            genesis_dbc.transaction.mlsags[0].key_image.into(),
            genesis_dbc.transaction.clone(),
        )?;
        let _starting_spent_proof_share = new_spentbook.log_spent(
            starting_dbc.transaction.mlsags[0].key_image.into(),
            starting_dbc.transaction.clone(),
        )?;
        let _spent_proof_share = new_spentbook.log_spent(
            b_dbc.transaction.mlsags[0].key_image.into(),
            b_dbc.transaction.clone(),
        )?;

        for (key_image, tx) in dbc_builder_true.inputs() {
            let spent_proof_share = new_spentbook.log_spent(key_image, tx)?;
            dbc_builder_true = dbc_builder_true.add_spent_proof_share(spent_proof_share);
        }

        // Now that the SpentBook is correct, we have a valid spent_proof_share
        // and can successfully build our Dbc(s)
        //
        // This simulates the situation where recipient wallet later obtains the correct
        // secrets and spends them.
        let result = dbc_builder_true.build(&new_spentbook.key_manager);

        assert!(result.is_ok());

        Ok(())
    }
}
