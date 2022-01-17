// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{dbc_content::OwnerPublicKey, DbcContent, Error, KeyManager, Result};

use crate::{Hash, SpentProof};
use blst_ringct::ringct::RingCtTransaction;
use blsttc::{PublicKey, Signature};
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
    pub fn owner(&self) -> OwnerPublicKey {
        self.content.owner
    }

    /// Generate hash of this DBC
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.hash().0);
        sha3.update(&self.transaction.hash());

        for (in_key, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            sha3.update(in_key);
            sha3.update(&mint_key.to_bytes());
            sha3.update(&mint_sig.to_bytes());
        }

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    // Check there exists a Transaction with the output containing this Dbc
    pub fn confirm_valid<K: KeyManager>(&self, verifier: &K) -> Result<(), Error> {
        for spent_proof in self.spent_proofs.iter() {
            if !self
                .transaction
                .mlsags
                .iter()
                .any(|m| m.key_image.to_compressed() == spent_proof.key_image)
            {
                return Err(Error::UnknownInput);
            }
            spent_proof.validate(Hash::from(self.transaction.hash()), verifier)?;
        }

        if self.transaction.mlsags.is_empty() {
            Err(Error::TransactionMustHaveAnInput)
        } else if self.transaction_sigs.len() < self.transaction.mlsags.len() {
            Err(Error::MissingSignatureForInput)
        } else if !self
            .transaction
            .outputs
            .iter()
            .any(|o| *o.public_key() == self.owner())
        {
            Err(Error::DbcContentNotPresentInTransactionOutput)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::{
        Amount, AmountSecrets, BlsHelper, DbcBuilder, Hash, KeyManager, MintNode, ReissueRequest,
        ReissueRequestBuilder, SimpleKeyManager, SimpleSigner, SpentProofShare,
    };
    use blst_ringct::ringct::RingCtMaterial;
    use blst_ringct::{Output, RevealedCommitment};
    use blsttc::{SecretKey, SecretKeySet};
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rand_core::SeedableRng as SeedableRngCore;
    use std::convert::TryFrom;

    fn divide(amount: Amount, n_ways: u8) -> impl Iterator<Item = Amount> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as Amount);
            let leftover = amount % (n_ways as Amount);

            let odd_compensation = if (i as Amount) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(
        // dbc_owner: &bls_dkg::outcome::Outcome,
        dbc_owner: SecretKey,
        dbc: Dbc,
        n_ways: u8,
        output_owners: Vec<PublicKey>,
        spentbook_node: &MintNode<SimpleKeyManager>,
        mut rng8: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(ReissueRequest, Vec<RevealedCommitment>)> {
        let amount_secrets =
            AmountSecrets::try_from((&dbc_owner, &dbc.content.amount_secrets_cipher))?;
        let amount = amount_secrets.amount();

        let decoy_inputs = vec![]; // for now.

        let (reissue_tx, revealed_commitments, material) = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                BlsHelper::blsttc_to_blstrs_sk(dbc_owner),
                amount_secrets,
                decoy_inputs,
                &mut rng8,
            )
            .add_outputs(
                divide(amount, n_ways)
                    .enumerate()
                    .map(|(idx, amount)| Output {
                        amount,
                        public_key: BlsHelper::blsttc_to_blstrs_pubkey(&output_owners[idx]),
                    }),
            )
            .build(&mut rng8)?;

        let tx_hash = Hash::from(reissue_tx.hash());

        let spentbook_pks = spentbook_node.key_manager.public_key_set()?;
        let spentbook_sig_share = spentbook_node.key_manager.sign(&tx_hash)?;

        let key_image = reissue_tx.mlsags[0].key_image.to_compressed();
        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(
                0,
                SpentProofShare {
                    key_image,
                    spentbook_pks,
                    spentbook_sig_share,
                    public_commitments: material.inputs[0].commitments(&Default::default()),
                },
            )
            .build()?;

        Ok((rr, revealed_commitments))
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let amount = 100;
        let public_key = crate::bls_dkg_id(&mut rng).public_key_set.public_key();

        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output {
                public_key: BlsHelper::blsttc_to_blstrs_pubkey(&public_key),
                amount,
            }],
        };

        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng8)
            .expect("Failed to sign transaction");

        assert_eq!(revealed_commitments.len(), 1);

        let input_content =
            DbcContent::from((public_key, AmountSecrets::from(revealed_commitments[0])));

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

        assert!(matches!(
            dbc.confirm_valid(&key_manager),
            Err(Error::TransactionMustHaveAnInput)
        ));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[quickcheck]
    fn prop_dbc_validation(
        n_inputs: NonZeroTinyInt,      // # of input DBC's
        n_valid_sigs: TinyInt,         // # of valid sigs
        n_wrong_signer_sigs: TinyInt,  // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,     // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,   // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt,  // Artifically increase output dbc value
        n_add_random_parents: TinyInt, // # of random parents to add to output DBC
        n_drop_parents: TinyInt,       // # of valid parents to drop from output DBC
    ) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        // let n_inputs = n_inputs.coerce::<u8>();
        let amount = 100;
        let mint_owner = crate::bls_dkg_id(&mut rng);

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(mint_owner.clone()),
            mint_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis = genesis_node.issue_genesis_dbc(amount, &mut rng8)?;

        let genesis_sig = genesis
            .public_key_set
            .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: genesis.dbc_content.clone(),
            transaction_sigs: genesis
                .transaction
                .mlsags
                .iter()
                .map(|mlsag| {
                    (
                        mlsag.key_image.to_compressed(),
                        (mint_owner.public_key_set.public_key(), genesis_sig.clone()),
                    )
                })
                .collect(),
            transaction: genesis.transaction.clone(),
            spent_proofs: genesis.spent_proofs.clone(),
        };

        // let input_owner = crate::bls_dkg_id();
        let input_owners: Vec<SecretKeySet> = (0..=n_inputs.coerce())
            .map(|_| SecretKeySet::random(1, &mut rng))
            .collect();
        let input_owners_blstrs: Vec<blstrs::Scalar> = input_owners
            .iter()
            .map(|sks| BlsHelper::blsttc_to_blstrs_sk(sks.secret_key()))
            .collect();

        let (reissue_request, revealed_commitments) = prepare_even_split(
            BlsHelper::blstrs_to_blsttc_sk(genesis.secret_key),
            genesis_dbc,
            n_inputs.coerce(),
            input_owners
                .iter()
                .map(|sks| sks.public_keys().public_key())
                .collect(),
            // input_owner.public_keys().public_key(),
            &genesis_node,
            &mut rng8,
        )?;

        let split_reissue_share = genesis_node.reissue(reissue_request)?;

        let mut dbc_builder = DbcBuilder::new(revealed_commitments);
        dbc_builder = dbc_builder.add_reissue_share(split_reissue_share);
        let output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next reissue.
        let inputs: Vec<(blstrs::Scalar, AmountSecrets, Vec<blst_ringct::DecoyInput>)> =
            output_dbcs
                .into_iter()
                .enumerate()
                .map(|(idx, dbc)| {
                    let amount_secrets = AmountSecrets::try_from((
                        &input_owners[idx],
                        &dbc.content.amount_secrets_cipher,
                    ))
                    .unwrap();
                    let decoy_inputs = vec![]; // todo
                    (input_owners_blstrs[idx], amount_secrets, decoy_inputs)
                })
                .collect();

        let (reissue_tx, _revealed_commitments, material) = crate::TransactionBuilder::default()
            .add_inputs_by_secrets(inputs, &mut rng8)
            .add_output(Output {
                amount,
                public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                    &crate::bls_dkg_id(&mut rng).public_key_set.public_key(),
                ),
            })
            .build(&mut rng8)?;

        let tx_hash = Hash::from(reissue_tx.hash());

        let mut rr_builder = ReissueRequestBuilder::new(reissue_tx.clone());
        for (i, (mlsag, mlsag_material)) in reissue_tx
            .mlsags
            .iter()
            .zip(material.inputs.iter())
            .enumerate()
        {
            let spentbook_pks = genesis_node.key_manager.public_key_set()?;
            let spentbook_sig_share = genesis_node.key_manager.sign(&tx_hash)?;

            let public_commitments = mlsag_material.commitments(&Default::default());

            rr_builder = rr_builder.add_spent_proof_share(
                i,
                SpentProofShare {
                    key_image: mlsag.key_image.to_compressed(),
                    spentbook_pks,
                    spentbook_sig_share,
                    public_commitments,
                },
            );
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
        let fuzzed_content = DbcContent::from((
            input_owners[0].public_keys().public_key(),
            fuzzed_amt_secrets,
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
                        (genesis.public_key_set.public_key(), mint_sig.clone()),
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
                    genesis.public_key_set.public_key(),
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
                let wrong_msg_mint_sig = genesis_node
                    .key_manager
                    .public_key_set()
                    .unwrap()
                    .combine_signatures(vec![wrong_msg_sig.threshold_crypto()])
                    .unwrap();

                fuzzed_transaction_sigs.insert(
                    input.key_image.to_compressed(),
                    (genesis.public_key_set.public_key(), wrong_msg_mint_sig),
                );
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs.insert(
                [0u8; 48],
                (genesis.public_key_set.public_key(), mint_sig.clone()),
            );
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: reissue_share.transaction,
            transaction_sigs: fuzzed_transaction_sigs,
            spent_proofs: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let key_manager =
            SimpleKeyManager::new(SimpleSigner::from(id), genesis.public_key_set.public_key());
        let validation_res = dbc.confirm_valid(&key_manager);

        let dbc_amount =
            AmountSecrets::try_from((&input_owners[0], &dbc.content.amount_secrets_cipher))?
                .amount();

        match validation_res {
            Ok(()) => {
                assert!(dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| *o.public_key() == dbc.owner()));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(dbc_amount, amount);
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);
                assert_eq!(extra_output_amount.coerce::<u8>(), 0);
                assert_eq!(n_add_random_parents.coerce::<u8>(), 0);
                assert_eq!(n_drop_parents.coerce::<u8>(), 0);
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs.coerce::<u8>() < n_inputs.coerce::<u8>());
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
                    .any(|o| *o.public_key() == dbc.owner()));
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
