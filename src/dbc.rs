// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::{BTreeMap, HashSet};

use crate::{
    DbcContent, DbcContentHash, DbcTransaction, Error, Hash, KeyCache, PublicKey, Result, Signature,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

        if self.transaction_sigs.len() < self.transaction.inputs.len() {
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

    use std::collections::BTreeSet;

    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;

    use crate::{Mint, MintRequest};

    fn divide(amount: u64, n_ways: u8) -> impl Iterator<Item = u64> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as u64);
            let leftover = amount % (n_ways as u64);

            let odd_compensation = if (i as u64) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(dbc: &Dbc, n_ways: u8) -> MintRequest {
        let inputs: HashSet<_> = vec![dbc.clone()].into_iter().collect();
        let input_hashes: BTreeSet<_> = inputs.iter().map(|in_dbc| in_dbc.name()).collect();

        let outputs = divide(dbc.amount(), n_ways)
            .enumerate()
            .map(|(i, amount)| DbcContent::new(input_hashes.clone(), amount, i as u8))
            .collect();

        MintRequest { inputs, outputs }
    }

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct TinyInt(u8);

    impl TinyInt {
        fn into<T: From<u8>>(self) -> T {
            self.0.into()
        }
    }

    impl std::fmt::Debug for TinyInt {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Arbitrary for TinyInt {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(u8::arbitrary(g) % 5)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new((0..(self.0)).into_iter().rev().map(Self))
        }
    }

    #[quickcheck]
    fn prop_mint_signatures(
        n_inputs: TinyInt,             // # of input DBC's
        n_valid_sigs: TinyInt,         // # of valid sigs
        n_wrong_signer_sigs: TinyInt,  // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,     // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,   // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt,  // Artifically increase output dbc value
        n_add_random_parents: TinyInt, // # of random parents to add to output DBC
        n_drop_parents: TinyInt,       // # of valid parents to drop from output DBC
    ) -> TestResult {
        let amount = 100;

        let (genesis, genesis_dbc) = Mint::genesis(amount);

        let mint_request = prepare_even_split(&genesis_dbc, n_inputs.into());
        let (split_transaction, signature) = genesis.reissue(mint_request.clone()).unwrap();
        let split_transaction_sigs: BTreeMap<_, _> =
            vec![(genesis_dbc.name(), (genesis.public_key(), signature))]
                .into_iter()
                .collect();

        assert_eq!(split_transaction, mint_request.to_transaction());

        let inputs: HashSet<_> = mint_request
            .outputs
            .into_iter()
            .map(|content| Dbc {
                content,
                transaction: split_transaction.clone(),
                transaction_sigs: split_transaction_sigs.clone(),
            })
            .collect();

        let input_hashes: BTreeSet<DbcContentHash> =
            inputs.iter().map(|in_dbc| in_dbc.name()).collect();

        let content = DbcContent::new(input_hashes.clone(), amount, 0);
        let outputs = vec![content.clone()].into_iter().collect();

        let mint_request = MintRequest { inputs, outputs };

        let (transaction, mint_sig) = genesis.reissue(mint_request.clone()).unwrap();
        assert_eq!(mint_request.to_transaction(), transaction);

        let fuzzed_parents = input_hashes
            .into_iter()
            .skip(n_drop_parents.into()) // drop some parents
            .chain(
                // add some random parents
                (0..n_add_random_parents.into())
                    .into_iter()
                    .map(|_| rand::random()),
            )
            .collect();

        let fuzzed_content = DbcContent::new(
            fuzzed_parents,
            amount + extra_output_amount.into::<u64>(),
            0,
        );

        let mut transaction_sigs: BTreeMap<Hash, (PublicKey, Signature)> = Default::default();

        let mut repeating_inputs = mint_request.inputs.iter().cycle();

        // Valid sigs
        for _ in 0..n_valid_sigs.into() {
            if let Some(input) = repeating_inputs.next() {
                transaction_sigs.insert(input.name(), (genesis.public_key(), mint_sig));
            }
        }
        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_signer_sigs.into() {
            use crate::key_manager::{ed25519_keypair, PublicKey, Signature};
            use ed25519::Signer;

            if let Some(input) = repeating_inputs.next() {
                let keypair = ed25519_keypair();
                let transaction_sig = keypair.sign(&transaction.hash());
                transaction_sigs.insert(
                    input.name(),
                    (PublicKey(keypair.public), Signature(transaction_sig)),
                );
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.into() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = genesis.key_mgr.sign(&[0u8; 32]);
                transaction_sigs.insert(input.name(), (genesis.public_key(), wrong_msg_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.into() {
            transaction_sigs.insert(rand::random(), (genesis.public_key(), mint_sig));
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction,
            transaction_sigs,
        };

        let key_cache = KeyCache::from(vec![genesis.public_key()]);
        let validation_res = dbc.confirm_valid(&key_cache);

        println!("Validation Result: {:#?}", validation_res);
        match validation_res {
            Ok(()) => {
                assert_eq!(dbc.amount(), amount);
                assert!(dbc.transaction.outputs.contains(&dbc.content.hash()));
                assert_eq!(n_extra_input_sigs.into::<u8>(), 0);
                if n_inputs.into::<u8>() > 0 {
                    assert!(n_valid_sigs >= n_inputs);
                    assert_eq!(n_wrong_signer_sigs.into::<u8>(), 0);
                    assert_eq!(n_wrong_msg_sigs.into::<u8>(), 0);
                    assert_eq!(extra_output_amount.into::<u8>(), 0);
                    assert_eq!(n_add_random_parents.into::<u8>(), 0);
                    assert_eq!(n_drop_parents.into::<u8>(), 0);
                }
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs < n_inputs);
            }
            Err(Error::Ed25519(_)) => {
                assert!(n_wrong_msg_sigs > TinyInt(0));
            }
            Err(Error::UnknownInput) => {
                assert!(n_extra_input_sigs > TinyInt(0));
                assert!(
                    dbc.transaction_sigs
                        .keys()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        != dbc.transaction.inputs
                );
            }
            Err(Error::UnrecognisedAuthority) => {
                assert!(n_wrong_signer_sigs > TinyInt(0));
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(k, _)| key_cache.verify_known_key(k).is_err()));
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert!(n_add_random_parents > TinyInt(0) || n_drop_parents > TinyInt(0));
                assert!(dbc.transaction.inputs != dbc.content.parents);
                assert!(!dbc.transaction.outputs.contains(&dbc.content.hash()));
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc.transaction.outputs.contains(&dbc.content.hash()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        TestResult::passed()
    }
}
