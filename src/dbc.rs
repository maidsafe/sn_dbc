// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{dbc_content::OwnerPublicKey, DbcContent, Error, KeyManager, Result};

use crate::{AmountSecrets, BlsHelper, Hash, SpentProof};
use blst_ringct::ringct::{OutputProof, RingCtTransaction};
use blst_ringct::RevealedCommitment;
use blstrs::group::Curve;
use blsttc::{PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use tiny_keccak::{Hasher, Sha3};

// note: typedef should be moved into blst_ringct crate
pub type KeyImage = [u8; 48]; // G1 compressed

// #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[derive(Debug, Clone)]
pub struct Dbc {
    pub content: DbcContent,
    pub transaction: RingCtTransaction,
    pub transaction_sigs: BTreeMap<KeyImage, (PublicKey, Signature)>,
    pub spent_proofs: BTreeSet<SpentProof>,
}

impl Dbc {
    /// Read the DBC owner
    pub fn owner(&self, base_sk: &SecretKey) -> Result<OwnerPublicKey> {
        let pubkey = self.content.derive_owner(base_sk)?;
        Ok(BlsHelper::blsttc_to_blstrs_pubkey(&pubkey))
    }

    pub fn has_secret_key(&self) -> bool {
        self.content.owner.has_secret_key()
    }

    /// Generate hash of this DBC
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.to_bytes());
        sha3.update(&self.transaction.hash());

        for (in_key, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            sha3.update(in_key);
            sha3.update(&mint_key.to_bytes());
            sha3.update(&mint_sig.to_bytes());
        }

        for sp in self.spent_proofs.iter() {
            sha3.update(&sp.to_bytes());
        }

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    // Check there exists a Transaction with the output containing this Dbc
    // todo: refactor so that common validation logic is shared by MintNode::reissue() and Dbc::confirm_valid()
    pub fn confirm_valid<K: KeyManager>(
        &self,
        base_sk: &SecretKey,
        mint_verifier: &K,
        spentbook_verifier: &K,
    ) -> Result<(), Error> {
        let tx_hash = Hash::from(self.transaction.hash());

        // Verify that each input has a corresponding valid mint signature.
        for (key_image, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            if !self
                .transaction
                .mlsags
                .iter()
                .any(|m| m.key_image.to_compressed() == *key_image)
            {
                return Err(Error::UnknownInput);
            }

            mint_verifier
                .verify(&tx_hash, mint_key, mint_sig)
                .map_err(|e| Error::Signing(e.to_string()))?;
        }

        // Verify that each input has a corresponding valid spent proof.
        for spent_proof in self.spent_proofs.iter() {
            if !self
                .transaction
                .mlsags
                .iter()
                .any(|m| m.key_image.to_compressed() == spent_proof.key_image)
            {
                return Err(Error::UnknownInput);
            }
            spent_proof.validate(tx_hash, spentbook_verifier)?;
        }

        let owner = self.owner(base_sk)?;

        if self.transaction.mlsags.is_empty() {
            Err(Error::TransactionMustHaveAnInput)
        } else if self.transaction_sigs.len() < self.transaction.mlsags.len() {
            Err(Error::MissingSignatureForInput)
        } else if self.spent_proofs.len() != self.transaction.mlsags.len() {
            Err(Error::MissingSpentProof)
        } else if !self
            .transaction
            .outputs
            .iter()
            .any(|o| *o.public_key() == owner)
        {
            Err(Error::DbcContentNotPresentInTransactionOutput)
        } else {
            Ok(())
        }
    }

    /// Checks if the provided AmountSecrets matches the amount commitment.
    /// note that both the amount and blinding_factor must be correct.
    pub fn confirm_provided_amount_matches_commitment(
        &self,
        base_sk: &SecretKey,
        amount: &AmountSecrets,
    ) -> Result<()> {
        let tx_commitment = self.my_output_proof(base_sk)?.commitment();
        let secrets_commitment = RevealedCommitment {
            value: amount.amount(),
            blinding: amount.blinding_factor(),
        }
        .commit(&Default::default())
        .to_affine();

        match secrets_commitment == tx_commitment {
            true => Ok(()),
            false => Err(Error::AmountCommitmentsDoNotMatch),
        }
    }

    fn my_output_proof(&self, base_sk: &SecretKey) -> Result<&OutputProof> {
        let owner = self.owner(base_sk)?;
        self.transaction
            .outputs
            .iter()
            .find(|o| *o.public_key() == owner)
            .ok_or(Error::OutputProofNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, SpentBookMock, TinyInt};
    use crate::{
        Amount, AmountSecrets, BlsHelper, DbcBuilder, DerivedOwner, Hash, KeyManager, MintNode,
        OwnerBase, ReissueRequest, ReissueRequestBuilder, SimpleKeyManager, SimpleSigner,
    };
    use blst_ringct::ringct::RingCtMaterial;
    use blst_ringct::{Output, RevealedCommitment};
    use blsttc::SecretKey;
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rand_core::SeedableRng as SeedableRngCore;

    fn divide(amount: Amount, n_ways: u8) -> impl Iterator<Item = Amount> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as Amount);
            let leftover = amount % (n_ways as Amount);

            let odd_compensation = if (i as Amount) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(
        dbc_owner: SecretKey,
        amount_secrets: AmountSecrets,
        n_ways: u8,
        output_owners: Vec<DerivedOwner>,
        spentbook: &mut SpentBookMock,
        mut rng8: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(
        ReissueRequest,
        Vec<RevealedCommitment>,
        BTreeMap<KeyImage, DerivedOwner>,
    )> {
        let amount = amount_secrets.amount();

        let decoy_inputs = vec![]; // for now.

        let (reissue_tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(
                    BlsHelper::blsttc_to_blstrs_sk(dbc_owner),
                    amount_secrets,
                    decoy_inputs,
                    &mut rng8,
                )
                .add_outputs(divide(amount, n_ways).zip(output_owners.into_iter()).map(
                    |(amount, derived_owner)| {
                        (
                            Output {
                                amount,
                                public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                                    &derived_owner.derive_public_key(),
                                ),
                            },
                            derived_owner,
                        )
                    },
                ))
                .build(&mut rng8)?;

        let key_image = reissue_tx.mlsags[0].key_image.to_compressed();
        let spent_proof_share = spentbook.log_spent(key_image, reissue_tx.clone())?;

        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(0, spent_proof_share)
            .build()?;

        Ok((rr, revealed_commitments, output_owners))
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let amount = 100;

        let derived_owner =
            DerivedOwner::from_owner_base(OwnerBase::from_random_secret_key(&mut rng), &mut rng8);

        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output {
                public_key: BlsHelper::blsttc_to_blstrs_pubkey(&derived_owner.derive_public_key()),
                amount,
            }],
        };

        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng8)
            .expect("Failed to sign transaction");

        assert_eq!(revealed_commitments.len(), 1);

        let input_content = DbcContent::from((
            derived_owner.owner_base.clone(),
            derived_owner.derivation_index,
            AmountSecrets::from(revealed_commitments[0]),
        ));

        let dbc = Dbc {
            content: input_content,
            transaction,
            transaction_sigs: Default::default(),
            spent_proofs: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(id.clone()),
            id.public_key_set.public_key(),
        );

        let spentbook_owner = crate::bls_dkg_id(&mut rng);
        let spentbook_key_manager = SimpleKeyManager::new(
            SimpleSigner::from(spentbook_owner.clone()),
            spentbook_owner.public_key_set.public_key(),
        );

        assert!(matches!(
            dbc.confirm_valid(
                &derived_owner.base_secret_key()?,
                &key_manager,
                &spentbook_key_manager
            ),
            Err(Error::TransactionMustHaveAnInput)
        ));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[quickcheck]
    fn prop_dbc_validation(
        n_inputs: NonZeroTinyInt,     // # of input DBC's
        n_valid_sigs: TinyInt,        // # of valid sigs
        n_wrong_signer_sigs: TinyInt, // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,    // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,  // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt, // Artifically increase output dbc value
    ) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let amount = 100;
        let mint_owner = crate::bls_dkg_id(&mut rng);

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(mint_owner.clone()),
            mint_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let spentbook_owner = crate::bls_dkg_id(&mut rng);
        let spentbook_key_manager = SimpleKeyManager::new(
            SimpleSigner::from(spentbook_owner.clone()),
            spentbook_owner.public_key_set.public_key(),
        );

        let genesis = genesis_node.issue_genesis_dbc(amount, &mut rng8)?;
        let genesis_input_key_image = genesis.ringct_material.inputs[0]
            .true_input
            .key_image()
            .to_compressed();
        let mut spentbook = SpentBookMock::from((spentbook_key_manager, genesis_input_key_image));

        let _genesis_spent_proof_share =
            spentbook.log_spent(genesis_input_key_image, genesis.transaction.clone())?;

        let input_owners: Vec<DerivedOwner> = (0..=n_inputs.coerce())
            .map(|_| {
                DerivedOwner::from_owner_base(
                    OwnerBase::from_random_secret_key(&mut rng),
                    &mut rng8,
                )
            })
            .collect();

        let (reissue_request, revealed_commitments, output_owners) = prepare_even_split(
            BlsHelper::blstrs_to_blsttc_sk(genesis.secret_key),
            genesis.amount_secrets,
            n_inputs.coerce(),
            input_owners,
            &mut spentbook,
            &mut rng8,
        )?;

        let sp = reissue_request.spent_proofs.iter().next().unwrap();
        assert!(sp.spentbook_pub_key.verify(
            &sp.spentbook_sig,
            Hash::from(reissue_request.transaction.hash())
        ));

        let split_reissue_share = genesis_node.reissue(reissue_request)?;

        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(split_reissue_share);
        let output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next reissue.
        let inputs: Vec<(blstrs::Scalar, AmountSecrets, Vec<blst_ringct::DecoyInput>)> =
            output_dbcs
                .into_iter()
                .map(|(_dbc, derived_owner, amount_secrets)| {
                    let decoy_inputs = vec![]; // todo
                    (
                        BlsHelper::blsttc_to_blstrs_sk(
                            derived_owner
                                .owner_base
                                .derive_secret_key(&derived_owner.derivation_index)
                                .unwrap(),
                        ),
                        amount_secrets,
                        decoy_inputs,
                    )
                })
                .collect();

        let derived_owner =
            DerivedOwner::from_owner_base(OwnerBase::from_random_secret_key(&mut rng), &mut rng8);
        let (reissue_tx, _revealed_commitments, material, _output_owners) =
            crate::TransactionBuilder::default()
                .add_inputs_by_secrets(inputs, &mut rng8)
                .add_output(
                    Output {
                        amount,
                        public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                            &derived_owner.derive_public_key(),
                        ),
                    },
                    derived_owner.clone(),
                )
                .build(&mut rng8)?;

        let mut rr_builder = ReissueRequestBuilder::new(reissue_tx.clone());
        for (i, (mlsag, _mlsag_material)) in reissue_tx
            .mlsags
            .iter()
            .zip(material.inputs.iter())
            .enumerate()
        {
            let spent_proof_share =
                spentbook.log_spent(mlsag.key_image.to_compressed(), reissue_tx.clone())?;
            rr_builder = rr_builder.add_spent_proof_share(i, spent_proof_share);
        }

        let rr = rr_builder.build()?;
        let reissue_share = genesis_node.reissue(rr)?;
        assert_eq!(reissue_tx.hash(), reissue_share.transaction.hash());

        let (mint_key_set, mint_sig_share) =
            &reissue_share.mint_node_signatures.values().next().unwrap();

        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let fuzzed_amt_secrets =
            AmountSecrets::from_amount(amount + extra_output_amount.coerce::<Amount>(), &mut rng8);
        let dbc_amount = fuzzed_amt_secrets.amount();

        let fuzzed_content = DbcContent::from((
            derived_owner.owner_base.clone(),
            derived_owner.derivation_index,
            fuzzed_amt_secrets.clone(),
        ));

        let mut fuzzed_transaction_sigs: BTreeMap<KeyImage, (PublicKey, Signature)> =
            BTreeMap::new();

        fuzzed_transaction_sigs.extend(
            reissue_share
                .mint_node_signatures
                .iter()
                .take(n_valid_sigs.coerce())
                .map(|(in_owner, _)| {
                    (
                        *in_owner,
                        (mint_owner.public_key_set.public_key(), mint_sig.clone()),
                    )
                }),
        );

        let mut repeating_inputs = reissue_tx
            .mlsags
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Invalid mint signatures BUT signing correct message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let id = crate::bls_dkg_id(&mut rng);
                let key_manager = SimpleKeyManager::new(
                    SimpleSigner::from(id.clone()),
                    mint_owner.public_key_set.public_key(),
                );
                let trans_sig_share = key_manager
                    .sign(&Hash::from(reissue_share.transaction.hash()))
                    .unwrap();
                let trans_sig = id
                    .public_key_set
                    .combine_signatures(vec![trans_sig_share.threshold_crypto()])
                    .unwrap();
                fuzzed_transaction_sigs.insert(
                    input.key_image.to_compressed(),
                    (id.public_key_set.public_key(), trans_sig),
                );
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = genesis_node.key_manager.sign(&Hash([0u8; 32])).unwrap();
                let wrong_msg_mint_sig = mint_owner
                    .public_key_set
                    .combine_signatures(vec![wrong_msg_sig.threshold_crypto()])
                    .unwrap();

                fuzzed_transaction_sigs.insert(
                    input.key_image.to_compressed(),
                    (mint_owner.public_key_set.public_key(), wrong_msg_mint_sig),
                );
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs.insert(
                [0u8; 48],
                (mint_owner.public_key_set.public_key(), mint_sig.clone()),
            );
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: reissue_share.transaction.clone(),
            transaction_sigs: fuzzed_transaction_sigs,
            spent_proofs: reissue_share.spent_proofs.clone(), // todo: fuzz spent proofs.
        };

        let key_manager = genesis_node.key_manager();
        let validation_res = dbc.confirm_valid(
            &derived_owner.base_secret_key()?,
            key_manager,
            &spentbook.key_manager,
        );

        let dbc_owner = dbc.owner(&derived_owner.base_secret_key()?)?;

        // Check if commitment in AmountSecrets matches the commitment in tx OutputProof
        let commitments_match = dbc
            .confirm_provided_amount_matches_commitment(
                &derived_owner.base_secret_key()?,
                &fuzzed_amt_secrets,
            )
            .is_ok();

        match validation_res {
            Ok(()) => {
                assert!(dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| *o.public_key() == dbc_owner));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);

                // note: reissue can succeed even though amount_secrets_cipher amount does not
                // match tx commited amount.
                assert!(dbc_amount == amount || !commitments_match);
                assert!(extra_output_amount.coerce::<u8>() == 0 || !commitments_match);
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs.coerce::<u8>() < n_inputs.coerce::<u8>());
            }
            Err(Error::MissingSpentProof) => {
                // todo: fuzz spent proofs.
                assert!(dbc.spent_proofs.len() < dbc.transaction.mlsags.len());
            }
            Err(Error::UnknownInput) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
                assert_ne!(
                    Vec::from_iter(dbc.transaction_sigs.keys().copied()),
                    dbc.transaction
                        .mlsags
                        .iter()
                        .map(|m| m.key_image.to_compressed())
                        .collect::<Vec<KeyImage>>()
                );
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| *o.public_key() == dbc_owner));
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::FailedSignature) => {
                assert_ne!(n_wrong_msg_sigs.coerce::<u8>(), 0);
            }
            Err(Error::Signing(s)) if s == Error::FailedSignature.to_string() => {
                assert_ne!(n_wrong_msg_sigs.coerce::<u8>(), 0);
            }
            Err(Error::UnrecognisedAuthority) => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            Err(Error::Signing(s)) if s == Error::UnrecognisedAuthority.to_string() => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        Ok(())
    }
}
