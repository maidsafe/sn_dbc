// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    DbcContent, DbcContentHash, DbcTransaction, Error, Hash, KeyManager, PublicKey, Result,
    Signature,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Dbc {
    pub content: DbcContent,
    pub transaction: DbcTransaction,
    pub transaction_sigs: BTreeMap<PublicKey, (PublicKey, Signature)>,
}

impl Dbc {
    pub fn owner(&self) -> PublicKey {
        self.content.owner
    }

    // Check there exists a DbcTransaction with the output containing this Dbc
    // Check there DOES NOT exist a DbcTransaction with this Dbc as parent (already minted)
    pub fn confirm_valid<K: KeyManager>(&self, verifier: &K) -> Result<(), Error> {
        for (input, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            if !self.transaction.inputs.contains(input) {
                return Err(Error::UnknownInput);
            }

            verifier
                .verify(&self.transaction.hash(), mint_key, mint_sig)
                .map_err(|e| Error::Signing(e.to_string()))?;
        }
        if self.transaction.inputs.is_empty() {
            Err(Error::TransactionMustHaveAnInput)
        } else if self.transaction_sigs.len() < self.transaction.inputs.len() {
            Err(Error::MissingSignatureForInput)
        } else if self.transaction.inputs != self.content.parents {
            Err(Error::DbcContentParentsDifferentFromTransactionInputs)
        } else if !self.transaction.outputs.contains(&self.owner()) {
            Err(Error::DbcContentNotPresentInTransactionOutput)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek_ng::scalar::Scalar;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{DbcHelper, NonZeroTinyInt, TinyInt};
    use crate::{
        KeyManager, Mint, ReissueRequest, ReissueTransaction, SimpleKeyManager, SimpleSigner,
        SimpleSpendBook,
    };

    fn divide(amount: u64, n_ways: u8) -> impl Iterator<Item = u64> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as u64);
            let leftover = amount % (n_ways as u64);

            let odd_compensation = if (i as u64) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(
        dbc_owner: &bls_dkg::outcome::Outcome,
        dbc: &Dbc,
        n_ways: u8,
        output_owner: &blsttc::PublicKeySet,
    ) -> Result<(ReissueRequest, Scalar), Error> {
        let inputs = HashSet::from_iter(vec![dbc.clone()]);
        let input_owners = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.owner()));

        let amount_secrets = DbcHelper::decrypt_amount_secrets(dbc_owner, &dbc.content)?;

        let mut outputs_bf_sum: Scalar = Default::default();
        let output_amounts: Vec<u64> = divide(amount_secrets.amount, n_ways).collect();
        let outputs = HashSet::from_iter(output_amounts.iter().enumerate().map(|(i, amount)| {
            let blinding_factor = DbcContent::calc_blinding_factor(
                i == output_amounts.len() - 1,
                amount_secrets.blinding_factor,
                outputs_bf_sum,
            );
            outputs_bf_sum += blinding_factor;

            DbcContent::new(
                input_owners.clone(),
                *amount,
                i as u32,
                output_owner.public_key(),
                blinding_factor,
            )
            .unwrap()
        }));

        let transaction = ReissueTransaction { inputs, outputs };

        let sig_share = dbc_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = dbc_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        Ok((
            ReissueRequest {
                transaction,
                input_ownership_proofs: HashMap::from_iter(vec![(dbc.owner(), sig)]),
            },
            outputs_bf_sum,
        ))
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let input_content = DbcContent::new(
            BTreeSet::new(),
            100,
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;

        let input_content_owners = BTreeSet::from_iter(vec![input_content.owner]);

        let dbc = Dbc {
            content: input_content,
            transaction: DbcTransaction {
                inputs: BTreeSet::new(),
                outputs: input_content_owners,
            },
            transaction_sigs: Default::default(),
        };

        let id = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(id.public_key_set.clone(), (0, id.secret_key_share.clone())),
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
        let amount = 100;
        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                genesis_owner.public_key_set.clone(),
                (0, genesis_owner.secret_key_share.clone()),
            ),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let (gen_dbc_content, gen_dbc_trans, (gen_key_set, gen_node_sig)) = genesis_node
            .issue_genesis_dbc(crate::bls_dkg_id().public_key_set.public_key(), amount)
            .unwrap();

        let genesis_sig = gen_key_set
            .combine_signatures(vec![gen_node_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter(vec![(
                crate::bls_dkg_id().public_key_set.public_key(),
                (genesis_key, genesis_sig),
            )]),
        };

        let input_owner = crate::bls_dkg_id();
        let (reissue_request, inputs_bf_sum) = prepare_even_split(
            &genesis_owner,
            &genesis_dbc,
            n_inputs.coerce(),
            &input_owner.public_key_set,
        )?;
        let input_owners = reissue_request
            .transaction
            .inputs
            .iter()
            .map(|i| i.owner())
            .collect();
        let (split_transaction, split_transaction_sigs) = genesis_node
            .reissue(reissue_request.clone(), input_owners)
            .unwrap();

        assert_eq!(split_transaction, reissue_request.transaction.blinded());

        let (mint_key_set, mint_sig_share) = split_transaction_sigs.values().next().unwrap();
        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let inputs = HashSet::from_iter(reissue_request.transaction.outputs.into_iter().map(
            |content| {
                Dbc {
                    content,
                    transaction: split_transaction.clone(),
                    transaction_sigs: BTreeMap::from_iter(
                        split_transaction_sigs
                            .iter()
                            .map(|(input, _)| (*input, (genesis_key, mint_sig.clone()))),
                    ),
                }
            },
        ));

        let input_owners = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.owner()));

        let content = DbcContent::new(
            input_owners.clone(),
            amount,
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
            inputs_bf_sum,
        )?;
        let outputs = HashSet::from_iter(vec![content]);

        let transaction = ReissueTransaction { inputs, outputs };
        let sig_share = input_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let input_owner_key_set = input_owner.public_key_set.clone();
        let sig = input_owner_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let input_ownership_proofs = HashMap::from_iter(
            transaction
                .inputs
                .iter()
                .map(|input| (input.owner(), sig.clone())),
        );

        let reissue_request = ReissueRequest {
            transaction,
            input_ownership_proofs,
        };

        let (transaction, transaction_sigs) = genesis_node
            .reissue(reissue_request.clone(), input_owners.clone())
            .unwrap();
        assert_eq!(reissue_request.transaction.blinded(), transaction);

        let (mint_key_set, mint_sig_share) = transaction_sigs.values().next().unwrap();
        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let fuzzed_parents = BTreeSet::from_iter(
            input_owners
                .into_iter()
                .skip(n_drop_parents.coerce()) // drop some parents
                .chain(
                    // add some random parents
                    (0..n_add_random_parents.coerce())
                        .into_iter()
                        .map(|_| crate::bls_dkg_id().public_key_set.public_key()),
                ),
        );

        let fuzzed_content = DbcContent::new(
            fuzzed_parents,
            amount + extra_output_amount.coerce::<u64>(),
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;

        let mut fuzzed_transaction_sigs: BTreeMap<PublicKey, (PublicKey, Signature)> =
            BTreeMap::new();

        // Add valid sigs
        fuzzed_transaction_sigs.extend(
            transaction_sigs
                .iter()
                .take(n_valid_sigs.coerce())
                .map(|(in_owner, _)| (*in_owner, (genesis_key, mint_sig.clone()))),
        );
        let mut repeating_inputs = reissue_request
            .transaction
            .inputs
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let id = crate::bls_dkg_id();
                let key_manager = SimpleKeyManager::new(
                    SimpleSigner::new(id.public_key_set.clone(), (0, id.secret_key_share.clone())),
                    genesis_key,
                );
                let trans_sig_share = key_manager.sign(&transaction.hash()).unwrap();
                let trans_sig = id
                    .public_key_set
                    .combine_signatures(vec![trans_sig_share.threshold_crypto()])
                    .unwrap();
                fuzzed_transaction_sigs
                    .insert(input.owner(), (id.public_key_set.public_key(), trans_sig));
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

                fuzzed_transaction_sigs.insert(input.owner(), (genesis_key, wrong_msg_mint_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs.insert(
                crate::bls_dkg_id().public_key_set.public_key(),
                (genesis_key, mint_sig.clone()),
            );
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction,
            transaction_sigs: fuzzed_transaction_sigs,
        };

        let id = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(id.public_key_set.clone(), (0, id.secret_key_share)),
            genesis_key,
        );
        let validation_res = dbc.confirm_valid(&key_manager);

        let dbc_amount = DbcHelper::decrypt_amount(&input_owner, &dbc.content)?;

        println!("Validation Result: {:#?}", validation_res);
        match validation_res {
            Ok(()) => {
                assert!(dbc.transaction.outputs.contains(&dbc.content.owner));
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
                    BTreeSet::from_iter(dbc.transaction_sigs.keys().copied()),
                    dbc.transaction.inputs
                );
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert!(
                    n_add_random_parents.coerce::<u8>() > 0 || n_drop_parents.coerce::<u8>() > 0
                );
                assert!(dbc.transaction.inputs != dbc.content.parents);
                assert!(!dbc.transaction.outputs.contains(&dbc.content.owner));
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc.transaction.outputs.contains(&dbc.content.owner));
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
                    .any(|(k, _)| key_manager.verify_known_key(k).is_err()));
            }
            Err(Error::Signing(s)) if s == Error::UnrecognisedAuthority.to_string() => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(k, _)| key_manager.verify_known_key(k).is_err()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }
        Ok(())
    }
}
