// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    DbcContent, DbcContentHash, DbcTransaction, Error, Hash, KeyManager, PublicKey, Result,
    Signature, Verifier,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Dbc {
    pub content: DbcContent,
    pub transaction: DbcTransaction,
    pub transaction_sigs: BTreeMap<DbcContentHash, (PublicKey, Signature)>,
}

impl Dbc {
    pub fn amount(&self) -> u64 {
        self.content.amount
    }

    pub fn name(&self) -> Hash {
        self.content.hash()
    }

    // Check there exists a DbcTransaction with the output containing this Dbc
    // Check there DOES NOT exist a DbcTransaction with this Dbc as parent (already minted)
    pub async fn confirm_valid<K: KeyManager>(&self, verifier: &Verifier<K>) -> Result<(), Error> {
        for (input, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            if !self.transaction.inputs.contains(input) {
                return Err(Error::UnknownInput);
            }

            verifier
                .verify(&self.transaction.hash(), &mint_key, &mint_sig)
                .await
                .map_err(|e| Error::Signing(e.to_string()))?;
        }
        if self.transaction.inputs.is_empty() {
            Err(Error::TransactionMustHaveAnInput)
        } else if self.transaction_sigs.len() < self.transaction.inputs.len() {
            Err(Error::MissingSignatureForInput)
        } else if self.transaction.inputs != self.content.parents {
            Err(Error::DbcContentParentsDifferentFromTransactionInputs)
        } else if !self.transaction.outputs.contains(&self.content.hash()) {
            Err(Error::DbcContentNotPresentInTransactionOutput)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::{
        KeyManager, Mint, ReissueRequest, ReissueTransaction, SimpleKeyManager, SimpleSigner,
    };

    use futures::executor::block_on as block;
    use quickcheck_macros::quickcheck;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::iter::FromIterator;
    use std::sync::Arc;

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
        output_owner: &threshold_crypto::PublicKeySet,
    ) -> ReissueRequest {
        let inputs = HashSet::from_iter(vec![dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let outputs =
            HashSet::from_iter(divide(dbc.amount(), n_ways).enumerate().map(|(i, amount)| {
                DbcContent::new(
                    input_hashes.clone(),
                    amount,
                    i as u32,
                    output_owner.public_key(),
                )
            }));

        let transaction = ReissueTransaction { inputs, outputs };

        let sig_share = dbc_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = dbc_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(
                dbc.name(),
                (dbc_owner.public_key_set.public_key(), sig),
            )]),
        }
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() {
        let input_content = DbcContent::new(
            BTreeSet::new(),
            100,
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
        );

        let input_content_hashes = BTreeSet::from_iter(vec![input_content.hash()]);

        let dbc = Dbc {
            content: input_content,
            transaction: DbcTransaction {
                inputs: BTreeSet::new(),
                outputs: input_content_hashes,
            },
            transaction_sigs: Default::default(),
        };

        let id = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(id.public_key_set.clone(), (0, id.secret_key_share.clone())),
            id.public_key_set.public_key(),
        );

        assert!(matches!(
            block(dbc.confirm_valid(&Verifier::new(Arc::new(key_manager)))),
            Err(Error::TransactionMustHaveAnInput)
        ));
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
    ) {
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
        let mut genesis_node = Mint::new(Arc::new(key_manager));

        let (gen_dbc_content, gen_dbc_trans, (gen_key_set, gen_node_sig)) =
            block(genesis_node.issue_genesis_dbc(amount)).unwrap();

        let genesis_sig = gen_key_set
            .combine_signatures(vec![gen_node_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter(vec![(
                crate::mint::GENESIS_DBC_INPUT,
                (genesis_key, genesis_sig),
            )]),
        };

        let input_owner = crate::bls_dkg_id();
        let reissue_request = prepare_even_split(
            &genesis_owner,
            &genesis_dbc,
            n_inputs.coerce(),
            &input_owner.public_key_set,
        );
        let input_hashes = reissue_request
            .transaction
            .inputs
            .iter()
            .map(|i| i.name())
            .collect();
        let (split_transaction, split_transaction_sigs) =
            block(genesis_node.reissue(reissue_request.clone(), input_hashes)).unwrap();

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

        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let content = DbcContent::new(
            input_hashes.clone(),
            amount,
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
        );
        let outputs = HashSet::from_iter(vec![content]);

        let transaction = ReissueTransaction { inputs, outputs };
        let sig_share = input_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let input_owner_key_set = input_owner.public_key_set;
        let sig = input_owner_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let input_ownership_proofs = HashMap::from_iter(transaction.inputs.iter().map(|input| {
            (
                input.name(),
                (input_owner_key_set.public_key(), sig.clone()),
            )
        }));

        let reissue_request = ReissueRequest {
            transaction,
            input_ownership_proofs,
        };

        let (transaction, transaction_sigs) =
            block(genesis_node.reissue(reissue_request.clone(), input_hashes.clone())).unwrap();
        assert_eq!(reissue_request.transaction.blinded(), transaction);

        let (mint_key_set, mint_sig_share) = transaction_sigs.values().next().unwrap();
        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let fuzzed_parents = BTreeSet::from_iter(
            input_hashes
                .into_iter()
                .skip(n_drop_parents.coerce()) // drop some parents
                .chain(
                    // add some random parents
                    (0..n_add_random_parents.coerce())
                        .into_iter()
                        .map(|_| rand::random()),
                ),
        );

        let fuzzed_content = DbcContent::new(
            fuzzed_parents,
            amount + extra_output_amount.coerce::<u64>(),
            0,
            crate::bls_dkg_id().public_key_set.public_key(),
        );

        let mut fuzzed_transaction_sigs: BTreeMap<Hash, (PublicKey, Signature)> = BTreeMap::new();

        // Add valid sigs
        fuzzed_transaction_sigs.extend(
            transaction_sigs
                .iter()
                .take(n_valid_sigs.coerce())
                .map(|(in_hash, _)| (*in_hash, (genesis_key, mint_sig.clone()))),
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
                let trans_sig_share = block(key_manager.sign(&transaction.hash())).unwrap();
                let trans_sig = id
                    .public_key_set
                    .combine_signatures(vec![trans_sig_share.threshold_crypto()])
                    .unwrap();
                fuzzed_transaction_sigs
                    .insert(input.name(), (id.public_key_set.public_key(), trans_sig));
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = block(genesis_node.key_manager.sign(&Hash([0u8; 32]))).unwrap();
                let wrong_msg_mint_sig = block(genesis_node.key_manager.public_key_set())
                    .unwrap()
                    .combine_signatures(vec![wrong_msg_sig.threshold_crypto()])
                    .unwrap();

                fuzzed_transaction_sigs.insert(input.name(), (genesis_key, wrong_msg_mint_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs.insert(rand::random(), (genesis_key, mint_sig.clone()));
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
        let verifier = Verifier::new(Arc::new(key_manager));
        let validation_res = block(dbc.confirm_valid(&verifier));

        println!("Validation Result: {:#?}", validation_res);
        match validation_res {
            Ok(()) => {
                assert!(dbc.transaction.outputs.contains(&dbc.content.hash()));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(dbc.amount(), amount);
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
            Err(Error::UnrecognisedAuthority) => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(k, _)| block(verifier.verify_known_key(k)).is_err()));
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert!(
                    n_add_random_parents.coerce::<u8>() > 0 || n_drop_parents.coerce::<u8>() > 0
                );
                assert!(dbc.transaction.inputs != dbc.content.parents);
                assert!(!dbc.transaction.outputs.contains(&dbc.content.hash()));
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc.transaction.outputs.contains(&dbc.content.hash()));
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::FailedSignature) => {
                assert_ne!(n_wrong_msg_sigs.coerce::<u8>(), 0);
            }
            res => panic!("Unexpected verification result {:?}", res),
        }
    }
}
