// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeMap;

use crate::{
    DbcContent, DbcContentHash, DbcTransaction, Error, Hash, KeyCache, PublicKey, Result, Signature,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub fn confirm_valid(&self, key_cache: &KeyCache) -> Result<(), Error> {
        for (input, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            if !self.transaction.inputs.contains(input) {
                return Err(Error::UnknownInput);
            }

            key_cache.verify(&self.transaction.hash(), &mint_key, &mint_sig)?;
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

    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::{Mint, MintRequest, MintTransaction};

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
    ) -> MintRequest {
        let inputs = HashSet::from_iter(vec![dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let outputs =
            HashSet::from_iter(divide(dbc.amount(), n_ways).enumerate().map(|(i, amount)| {
                DbcContent {
                    parents: input_hashes.clone(),
                    amount,
                    output_number: i as u8,
                    owner: output_owner.clone(),
                }
            }));

        let transaction = MintTransaction { inputs, outputs };

        let sig_share = dbc_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = dbc_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        MintRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(dbc.name(), sig)]),
        }
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() {
        let input_content = DbcContent {
            parents: Default::default(),
            amount: 100,
            output_number: 0,
            owner: crate::bls_dkg_id().public_key_set,
        };

        let input_content_hashes = BTreeSet::from_iter(vec![input_content.hash()]);

        let dbc = Dbc {
            content: input_content,
            transaction: DbcTransaction {
                inputs: Default::default(),
                outputs: input_content_hashes,
            },
            transaction_sigs: Default::default(),
        };

        assert!(matches!(
            dbc.confirm_valid(&KeyCache::default()),
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
        let (mut genesis, genesis_dbc) =
            Mint::genesis(genesis_owner.public_key_set.clone(), amount);

        let input_owner = crate::bls_dkg_id();
        let mint_request = prepare_even_split(
            &genesis_owner,
            &genesis_dbc,
            n_inputs.coerce(),
            &input_owner.public_key_set,
        );
        let input_hashes = mint_request
            .transaction
            .inputs
            .iter()
            .map(|i| i.name())
            .collect();
        let (split_transaction, split_transaction_sigs) =
            genesis.reissue(mint_request.clone(), input_hashes).unwrap();

        assert_eq!(split_transaction, mint_request.transaction.blinded());

        let inputs = HashSet::from_iter(mint_request.transaction.outputs.into_iter().map(
            |content| Dbc {
                content,
                transaction: split_transaction.clone(),
                transaction_sigs: split_transaction_sigs.clone(),
            },
        ));

        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let content = DbcContent {
            parents: input_hashes.clone(),
            amount,
            output_number: 0,
            owner: crate::bls_dkg_id().public_key_set,
        };
        let outputs = HashSet::from_iter(vec![content]);

        let transaction = MintTransaction { inputs, outputs };
        let sig_share = input_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = input_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let input_ownership_proofs = HashMap::from_iter(
            transaction
                .inputs
                .iter()
                .map(|input| (input.name(), sig.clone())),
        );

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs,
        };

        let (transaction, transaction_sigs) = genesis
            .reissue(mint_request.clone(), input_hashes.clone())
            .unwrap();
        assert_eq!(mint_request.transaction.blinded(), transaction);

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

        let fuzzed_content = DbcContent {
            parents: fuzzed_parents,
            amount: amount + extra_output_amount.coerce::<u64>(),
            output_number: 0,
            owner: crate::bls_dkg_id().public_key_set,
        };

        let mut fuzzed_transaction_sigs = BTreeMap::new();

        // Add valid sigs
        fuzzed_transaction_sigs.extend(
            transaction_sigs
                .iter()
                .take(n_valid_sigs.coerce())
                .to_owned(),
        );
        let mut repeating_inputs = mint_request
            .transaction
            .inputs
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            use crate::key_manager::{ed25519_keypair, PublicKey, Signature};
            use ed25519::Signer;

            if let Some(input) = repeating_inputs.next() {
                let keypair = ed25519_keypair();
                let transaction_sig = keypair.sign(&transaction.hash());
                fuzzed_transaction_sigs.insert(
                    input.name(),
                    (PublicKey(keypair.public), Signature(transaction_sig)),
                );
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = genesis.key_mgr.sign(&Hash([0u8; 32]));
                fuzzed_transaction_sigs.insert(input.name(), (genesis.public_key(), wrong_msg_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        if let Some((_, key_sig)) = transaction_sigs.iter().next() {
            for _ in 0..n_extra_input_sigs.coerce() {
                fuzzed_transaction_sigs.insert(rand::random(), key_sig.to_owned());
            }
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction,
            transaction_sigs: fuzzed_transaction_sigs,
        };

        let key_cache = KeyCache::from(vec![genesis.public_key()]);
        let validation_res = dbc.confirm_valid(&key_cache);

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
            Err(Error::Ed25519(_)) => {
                assert!(n_wrong_msg_sigs.coerce::<u8>() > 0);
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
                    .any(|(k, _)| key_cache.verify_known_key(k).is_err()));
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
            res => panic!("Unexpected verification result {:?}", res),
        }
    }
}
