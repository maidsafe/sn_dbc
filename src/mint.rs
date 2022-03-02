// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Code required to mint Dbcs
// The in the most basic terms means
// a valid input DBC can be split into
// 1 or more DBCs as long as
// input is vaid
// Outputs <= input value

use crate::{
    Error, Hash, IndexedSignatureShare, KeyImage, KeyManager, PublicKey, PublicKeySet, Result,
    SpentProof, SpentProofShare, TransactionVerifier,
};
use blst_ringct::ringct::RingCtTransaction;
use std::collections::BTreeSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ReissueRequest {
    pub transaction: RingCtTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ReissueShare {
    pub transaction: RingCtTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
    pub mint_public_key_set: PublicKeySet,
    pub mint_signature_share: IndexedSignatureShare,
}

impl ReissueShare {
    /// Returns bytes of all fields that should be the same
    /// across mint nodes.
    ///
    /// The mint_signature_share field is excluded because each node
    /// will have a different signature share.
    pub fn to_common_bytes(&self) -> Vec<u8> {
        let mut bytes = self.transaction.to_bytes();
        for sp in self.spent_proofs.iter() {
            bytes.extend(&sp.to_bytes());
        }
        // public key set
        bytes.extend(&self.mint_public_key_set.to_bytes());
        bytes
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct MintNode<K>
where
    K: KeyManager,
{
    pub key_manager: K,
}

impl<K: KeyManager> MintNode<K> {
    pub fn new(key_manager: K) -> Self {
        Self { key_manager }
    }

    //   TBD: Is this API sufficient, or do we need to accept some kind of proof key chain
    //        and verify entire chain from a known genesis key?
    //
    //        As written, this API is assuming/trusting that our caller is doing something
    //        like that.
    pub fn trust_spentbook_public_key(mut self, public_key: PublicKey) -> Result<Self> {
        self.key_manager
            .add_known_key(public_key)
            .map_err(|e| Error::Signing(e.to_string()))?;
        Ok(self)
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    // update 2022-04-07 (danda): Now that MintNodes trust SpentBook pubkeys, I
    // this this proposed API is unnecessary.  Because:
    //   1. MintNode trusts pubkey of each SpentBook section.  (adds to KeyManager)
    //   2. Wallet logs input to SpentBook section, obtaining SpentProofShares
    //   3. Wallet aggregates Shares into SpentProof with SpentBook section's signature.
    //   4. Wallet calls reissue() for each MintNode, including SpentProof.
    //   5. reissue() checks that (a) signing key is trusted, and (b) signature is valid.
    //
    //   TBD: step (1) may need additional verification, eg verify a chain of keys
    //        since genesis key.  Or maybe we just trust our caller does that...?

    // This API will be called multiple times, once per input dbc, per section.
    // The key_image param comes from the true input, but cannot be linked by mint to true input.
    pub fn spend(_key_image: KeyImage, _transaction: RingCtTransaction) -> Result<SpentProofShare> {
        unimplemented!()

        // note: client is writing spentbook, so needs to write:
        //  a: key_image --> RingCtTransaction,
        //  b: public_key --> key_image   (for lookup by public key)

        // note: do decoys have to be from same section?  (for drusu to think about)

        // 1. lookup key image in spentbook, return error if not existing.
        //    (client did not write spentbook entry.).

        // 2. verify that tx in spentbook matches tx received from client.

        // 3. find mlsag in transaction that corresponds to the key_image, else return error.

        // 4. for each input in mlsag
        //       lookup tx in spentbook whose output is equal to this input.
        //         (full table scan, ouch, or multiple indexes into spentbook (key_image + public_key))
        //       obtain the public commitment from the output.
        //       verify commitment from input matches spentbook output commitment.

        // 5. verify transaction itself.   tx.verify()  (RingCtTransaction)

        // 6. create SpentProofShare and return it.
    }

    pub fn reissue(&self, reissue_req: ReissueRequest) -> Result<ReissueShare> {
        let ReissueRequest {
            transaction,
            spent_proofs,
        } = reissue_req;

        TransactionVerifier::verify_without_sigs(self.key_manager(), &transaction, &spent_proofs)?;

        let (mint_public_key_set, mint_signature_share) = self.sign_transaction(&transaction)?;

        let reissue_share = ReissueShare {
            transaction,
            spent_proofs,
            mint_public_key_set,
            mint_signature_share,
        };

        Ok(reissue_share)
    }

    fn sign_transaction(
        &self,
        transaction: &RingCtTransaction,
    ) -> Result<(PublicKeySet, IndexedSignatureShare)> {
        let node_signature = self
            .key_manager
            .sign(&Hash::from(transaction.hash()))
            .map_err(|e| Error::Signing(e.to_string()))?;

        let public_key_set = self
            .key_manager
            .public_key_set()
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok((public_key_set, node_signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst_ringct::DecoyInput;
    use blsttc::{SecretKey, SecretKeySet};
    use quickcheck_macros::quickcheck;
    use rand_core::SeedableRng as SeedableRngCore;
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    use crate::{
        tests::{TinyInt, TinyVec},
        Amount, AmountSecrets, Dbc, DbcContent, GenesisBuilderMock, GenesisMaterial, Owner,
        OwnerOnce, ReissueRequestBuilder, SimpleKeyManager, SimpleSigner, SpentBookNodeMock,
        SpentProofContent,
    };

    #[test]
    fn issue_genesis() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

        let (mint_node, _spentbook, genesis_dbc, genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng8)?;

        let verified = genesis_dbc.verify(
            &genesis.owner_once.owner_base().secret_key()?,
            &mint_node.key_manager,
        );
        assert!(verified.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

        let mut output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        output_amounts
            .push(GenesisMaterial::GENESIS_AMOUNT - output_amounts.iter().sum::<Amount>());

        let n_outputs = output_amounts.len();
        let output_amount = output_amounts.iter().sum();

        let (mint_node, mut spentbook, genesis_dbc, _genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng8)?;

        let owners: Vec<OwnerOnce> = (0..output_amounts.len())
            .map(|_| {
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8)
            })
            .collect();

        let (mut rr_builder, mut dbc_builder, _material) = crate::TransactionBuilder::default()
            .add_input_dbc(
                &genesis_dbc,
                &genesis_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng8,
            )?
            .add_outputs_by_amount(
                output_amounts
                    .iter()
                    .enumerate()
                    .map(|(idx, a)| (*a, owners[idx].clone())),
            )
            .build(&mut rng8)?;

        // We make this a closure because it is used for checking both spentbook
        // result and reissue result.
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

        for (key_image, tx) in rr_builder.inputs() {
            let spent_proof_share = match spentbook.log_spent(key_image, tx.clone()) {
                Ok(s) => s,
                Err(e) => return check_error(e),
            };
            rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
        }
        let rr = rr_builder.build()?;

        let reissue_share = match mint_node.reissue(rr) {
            Ok(rs) => {
                // Verify that at least one output was present.
                assert_ne!(n_outputs, 0);
                rs
            }
            Err(e) => return check_error(e),
        };

        // Aggregate ReissueShare to build output DBCs
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build(mint_node.key_manager())?;

        for (dbc, owner_once, amount_secrets) in output_dbcs.iter() {
            let dbc_amount = amount_secrets.amount();
            assert!(output_amounts.iter().any(|a| *a == dbc_amount));
            assert!(dbc
                .verify(
                    &owner_once.owner_base().secret_key().unwrap(),
                    mint_node.key_manager(),
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
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

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

        let (mint_node, mut spentbook, genesis_dbc, _genesis, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(&mut rng8)?;

        let (mut rr_builder, mut dbc_builder, _material) = crate::TransactionBuilder::default()
            .add_input_dbc(
                &genesis_dbc,
                &genesis_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng8,
            )?
            .add_outputs_by_amount(input_amounts.iter().copied().map(|amount| {
                let owner_once =
                    OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);
                (amount, owner_once)
            }))
            .build(&mut rng8)?;

        // note: this closure is used for checking errors returned from both
        // MintNode::reissue and SpentBookNodeMock::log_spent().
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

        for (key_image, tx) in rr_builder.inputs() {
            // normally spentbook verifies the tx, but here we skip it in order check reissue results.
            let spent_proof_share =
                match spentbook.log_spent_and_skip_tx_verification(key_image, tx.clone()) {
                    Ok(s) => s,
                    Err(e) => return check_tx_error(e),
                };
            rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
        }
        let rr1 = rr_builder.build()?;

        let reissue_share = match mint_node.reissue(rr1) {
            Ok(rs) => {
                // Verify that at least one input (output in this tx) was present.
                assert!(!input_amounts.is_empty());
                rs
            }
            Err(e) => return check_tx_error(e),
        };

        // Aggregate ReissueShare to build output DBCs
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build(mint_node.key_manager())?;

        // The outputs become inputs for next reissue.
        let inputs_dbcs: Vec<(Dbc, SecretKey, Vec<DecoyInput>)> = output_dbcs
            .into_iter()
            .map(|(dbc, owner_once, _amount_secrets)| {
                (
                    dbc,
                    owner_once.owner_base().secret_key().unwrap(),
                    spentbook.random_decoys(num_decoy_inputs, &mut rng8),
                )
            })
            .collect();

        let owners: Vec<OwnerOnce> = (0..=output_amounts.len())
            .map(|_| {
                OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8)
            })
            .collect();

        let outputs = output_amounts.clone().into_iter().zip(owners);

        let (mut rr2_builder, mut dbc_builder, _material) = crate::TransactionBuilder::default()
            .add_inputs_dbc(inputs_dbcs.clone(), &mut rng8)?
            .add_outputs_by_amount(outputs.clone())
            .build(&mut rng8)?;

        let dbc_output_amounts: Vec<Amount> = outputs.map(|(amt, _)| amt).collect();
        let output_total_amount: Amount = dbc_output_amounts.iter().sum();

        assert_eq!(inputs_dbcs.len(), rr2_builder.transaction.mlsags.len());
        assert_eq!(inputs_dbcs.len(), rr2_builder.inputs().len());

        let reissue_tx2 = rr2_builder.transaction.clone();

        // note: this closure is used for checking errors returned from both
        // MintNode::reissue and SpentBookNodeMock::log_spent().
        let check_error = |error: Error| -> Result<()> {
            match error {
                Error::SpentProofInputMismatch => {
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
                Error::InvalidSpentProofSignature(key) => {
                    let idx = reissue_tx2
                        .mlsags
                        .iter()
                        .position(|i| Into::<KeyImage>::into(i.key_image) == key)
                        .unwrap();
                    assert!(invalid_spent_proofs.contains(&idx));
                }
                _ => panic!("Unexpected reissue err {:#?}", error),
            }
            Ok(())
        };

        for (i, (key_image, tx)) in rr2_builder.inputs().into_iter().enumerate() {
            let is_invalid_spent_proof = invalid_spent_proofs.contains(&i);

            let spent_proof_share = match i % 2 {
                0 if is_invalid_spent_proof => {
                    // drop this spent proof
                    continue;
                }
                1 if is_invalid_spent_proof => {
                    // spentbook verifies the tx.  If an error, we need to check it same as with reissue result
                    let spent_proof_share = match spentbook.log_spent(key_image, tx.clone()) {
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
                            SecretKeySet::random(1, &mut rng8)
                                .secret_key_share(1)
                                .sign(&[0u8; 32]),
                        ),
                    }
                }
                _ => {
                    // spentbook verifies the tx.  If an error, we need to check it same as with reissue result
                    match spentbook.log_spent(key_image, tx.clone()) {
                        Ok(s) => s,
                        Err(e) => return check_error(e),
                    }
                }
            };

            rr2_builder = rr2_builder.add_spent_proof_share(spent_proof_share);
        }

        let rr2 = rr2_builder.build()?;
        let many_to_many_result = mint_node.reissue(rr2);

        match many_to_many_result {
            Ok(rs) => {
                assert_eq!(GenesisMaterial::GENESIS_AMOUNT, output_total_amount);
                assert!(invalid_spent_proofs
                    .iter()
                    .all(|i| i >= &reissue_tx2.mlsags.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts.clone()),
                    BTreeSet::from_iter(output_amounts)
                );

                // Aggregate ReissueShare to build output DBCs
                dbc_builder = dbc_builder.add_reissue_share(rs);
                let output_dbcs = dbc_builder.build(mint_node.key_manager())?;

                for (dbc, owner_once, _amount_secrets) in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.verify(
                        &owner_once.owner_base().secret_key()?,
                        &mint_node.key_manager,
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
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

        let mint_node = MintNode::new(SimpleKeyManager::from(SimpleSigner::from(
            crate::bls_dkg_id(&mut rng8),
        )));

        let output1_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);

        let (_rr_builder, dbc_builder, ..) = crate::TransactionBuilder::default()
            .add_output_by_amount(100, output1_owner.clone())
            .build(&mut rng8)?;

        let amount_secrets = AmountSecrets::from(dbc_builder.revealed_commitments[0]);
        let secret_key = output1_owner.as_owner().secret_key()?;
        let decoy_inputs = vec![]; // no decoys.

        let output2_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);

        let (fraud_rr_builder, ..) = crate::TransactionBuilder::default()
            .add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, &mut rng8)
            .add_output_by_amount(100, output2_owner)
            .build(&mut rng8)?;

        let fraud_rr = fraud_rr_builder.build()?;

        let fraudulant_reissue_result = mint_node.reissue(fraud_rr);

        // fixme: more/better assertions.
        assert!(fraudulant_reissue_result.is_err());
        Ok(())
    }

    /// This tests (and demonstrates) how the system handles a mis-match between the
    /// committed amount and amount encrypted in AmountSecrets.
    ///
    /// Normally these should be the same, however a malicious user or buggy
    /// implementation could produce different values.  The mint never sees the
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
    /// 7. Force an invalid write to the spentbook, and attempt to reissue.
    ///    This will fail for the same reason as (6)
    /// 8. Attempt to reissue again using the correct amount (1000).
    ///    This will fail because b was already marked as spent in the spentbook.
    ///    This demonstrates how an input can become burned if spentbook does
    ///    not verify tx.
    /// 9. Re-write spentbook log correctly and attempt to reissue using the
    ///    correct amount that was committed to.
    ///      Verify that this reissue succeeds.
    #[test]
    fn test_mismatched_amount_and_commitment() -> Result<(), Error> {
        // ----------
        // 1. produce a standard genesis DBC (a) with value 1000
        // ----------
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);

        let output_amount = 1000;

        let (mint_node, mut spentbook, genesis_dbc, starting_dbc, _change_dbc) =
            crate::dbc::tests::generate_dbc_of_value(output_amount, &mut rng8)?;

        // ----------
        // 2. reissue genesis DBC (a) to Dbc (b)  with value 1000.
        // ----------

        // First we create a regular/valid tx reissuing the genesis DBC to a
        // single new DBC of the same amount.

        let output_owner =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);

        let (mut rr_builder, mut dbc_builder, ..) = crate::TransactionBuilder::default()
            .add_input_dbc(
                &starting_dbc,
                &starting_dbc.owner_base().secret_key()?,
                vec![], // genesis is only input, so no decoys.
                &mut rng8,
            )?
            .add_output_by_amount(output_amount, output_owner.clone())
            .build(&mut rng8)?;

        for (key_image, tx) in rr_builder.inputs() {
            rr_builder =
                rr_builder.add_spent_proof_share(spentbook.log_spent(key_image, tx.clone())?);
        }
        let rr = rr_builder.build()?;

        let reissue_share = mint_node.reissue(rr)?;

        // Aggregate ReissueShare to build output DBCs
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build(mint_node.key_manager())?;
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
                mint_node.key_manager()
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
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng8), &mut rng8);

        let (mut rr_builder_fudged, ..) = crate::TransactionBuilder::default()
            .add_input_dbc(
                &fudged_output_dbc,
                &fudged_output_dbc.owner_base().secret_key()?,
                decoy_inputs.clone(),
                &mut rng8,
            )?
            .add_output_by_amount(fudged_secrets.amount(), output_owner.clone())
            .build(&mut rng8)?;

        // ----------
        // 6. Attempt to write this tx to the spentbook.
        //    This will fail because the input and output commitments do not match.
        // ----------
        for (key_image, tx) in rr_builder_fudged.inputs() {
            match spentbook.log_spent(key_image, tx) {
                Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {}
                _ => panic!("Expecting RingCt Error::InvalidHiddenCommitmentInRing"),
            }
        }

        // ----------
        // 7. Force an invalid write to the spentbook, and attempt to reissue.
        //    This will fail for the same reason as (6)
        // ----------

        // normally spentbook verifies the tx, but here we skip it in order to obtain
        // a spentproof with an invalid tx.
        for (key_image, tx) in rr_builder_fudged.inputs() {
            let spent_proof_share = spentbook.log_spent_and_skip_tx_verification(key_image, tx)?;
            rr_builder_fudged = rr_builder_fudged.add_spent_proof_share(spent_proof_share);
        }

        let spent_proof_share_fudged = spentbook.log_spent_and_skip_tx_verification(
            rr_builder_fudged.transaction.mlsags[0].key_image.into(),
            rr_builder_fudged.transaction.clone(),
        )?;

        let rr_fudged = rr_builder_fudged
            .add_spent_proof_share(spent_proof_share_fudged.clone())
            .build()?;

        // The mint should give an error on reissue because the sum(inputs) does not equal sum(outputs)
        let result_fudged = mint_node.reissue(rr_fudged);

        match result_fudged {
            Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {}
            _ => panic!("Expecting RingCt Error::InvalidHiddenCommitmentInRing"),
        }

        // ----------
        // 8. Attempt to reissue again using the correct amount (1000).
        //    This will fail because b was already marked as spent in the spentbook.
        //    This demonstrates how an input can become burned if spentbook does
        //    not verify tx.
        // ----------

        // So at this point we have written an invalid Tx to the spentbook associated
        // with the input Dbc.  This means the input Dbc is burned (unspendable).
        //
        // Next we build a new Tx with the correct amount and attempt to reissue.
        // But since we have the old spentproof for the invalid tx, this reissue
        // is doomed to fail also.  And we can't write to the spentbook again
        // because entries are immutable.

        let (rr_builder_true, ..) = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                fudged_output_dbc.owner_once_bearer()?.secret_key()?,
                true_secrets.clone(),
                decoy_inputs,
                &mut rng8,
            )
            .add_output_by_amount(true_secrets.amount(), output_owner)
            .build(&mut rng8)?;

        let tx_true = rr_builder_true.transaction.clone();
        let rr_burned = rr_builder_true
            .add_spent_proof_share(spent_proof_share_fudged)
            .build()?;

        // The mint should return an error because the spentproof does not match the tx.
        let result = mint_node.reissue(rr_burned);
        match result {
            Err(Error::InvalidSpentProofSignature(_)) => {}
            _ => panic!("Expected Error::InvalidSpentProofSignature"),
        }

        // ----------
        // 9. Re-write spentbook log correctly and attempt to reissue using the
        //    correct amount that was committed to.
        //      Verify that this reissue succeeds.
        // ----------

        // The input to the fudged tx has already been recorded as spent in the spentbook
        // so it is effectively burned (forever unspendable).  In a production system we
        // would be out-of-luck.
        //
        // The recipient's wallet should avoid this situation by calling
        // Dbc::confirm_provided_amount_matches_commitment immediately upon receipt of Dbc
        // and before attempting to spend.
        //
        // For the test case, we can remedy by:
        //
        // Make a new spentbook and replay the first three tx, plus the new tx_true
        // Note that the new spentbook uses the same signing key as the original, which
        // MintNode's key_manager trusts.
        //
        let mut new_spentbook = SpentBookNodeMock::from(spentbook.key_manager);
        // new_spentbook.set_genesis(&genesis.ringct_material);
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
        let spent_proof_share_true =
            new_spentbook.log_spent(tx_true.mlsags[0].key_image.into(), tx_true.clone())?;

        // Now that the SpentBook is correct, we have a valid spent_proof_share
        // and can make a valid ReissueRequest
        //
        // This simulates the situation where recipient wallet later obtains the correct
        // secrets and spends them.
        let rr_true = ReissueRequestBuilder::new(tx_true)
            .add_spent_proof_share(spent_proof_share_true)
            .build()?;

        // The mint should reissue without error because the sum(inputs) equals sum(outputs)
        // and we have a correct spent proof.
        let result = mint_node.reissue(rr_true);

        assert!(result.is_ok());

        Ok(())
    }
}
