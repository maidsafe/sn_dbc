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
        use ed25519::Verifier;
        for (input, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            if !self.transaction.inputs.contains(input) {
                return Err(Error::UnknownInput);
            }

            key_cache.verify(&self.transaction.hash(), &mint_key, &mint_sig)?;
        }

        if self.transaction_sigs.len() < self.content.parents.len() {
            Err(Error::MissingSignatureForInput)
        } else {
            Ok(())
        }
    }
    // Check the output values summed are  =< input value
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<DbcTransaction> {
        // self.confirm_valid()?;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use quickcheck::TestResult;
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

    // #[quickcheck]
    // fn prop_invalid_if_content_not_in_transaction_output(
    //     amount: u64,
    //     inputs: Vec<u8>,
    //     outputs: Vec<u8>,
    // ) {
    //     let input_hashes: BTreeSet<DbcContentHash> =
    //         inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

    //     let output_hashes: BTreeSet<DbcContentHash> =
    //         outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

    //     let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

    //     let content = DbcContent {
    //         parents: input_hashes.clone(),
    //         amount: amount,
    //     };

    //     let mint = Mint::new_random();

    //     let id = ed25519_keypair();
    //     let pubkey = id.public;
    //     let sig = id.sign(&content.hash());

    //     let dbc = Dbc {
    //         content,
    //         transaction,
    //         transaction_sigs: input_hashes
    //             .into_iter()
    //             .map(|i| (i, (pubkey, sig)))
    //             .collect(),
    //     };

    //     assert!(matches!(
    //         dbc.confirm_valid(&[&thresh_key]),
    //         Err(Error::DbcContentNotPresentInTransactionOutput)
    //     ));
    // }

    // #[quickcheck]
    // fn prop_output_parents_should_be_transaction_inputs(
    //     amount: u64,
    //     inputs: Vec<u8>,
    //     content_parents: Vec<u8>,
    //     outputs: Vec<u8>,
    // ) {
    //     let input_hashes: BTreeSet<DbcContentHash> =
    //         inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

    //     let parents: BTreeSet<DbcContentHash> =
    //         inputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

    //     let mut output_hashes: BTreeSet<DbcContentHash> =
    //         outputs.iter().map(|i| sha3_256(&i.to_be_bytes())).collect();

    //     let content = DbcContent { parents, amount };
    //     output_hashes.insert(content.hash());

    //     let transaction = DbcTransaction::new(input_hashes.clone(), output_hashes);

    //     let id = ed25519_keypair();
    //     let thresh_key = ThresholdPublicKey::new(1, vec![id.public].into_iter().collect()).unwrap();
    //     let mut thresh_sig = ThresholdSignature::new();
    //     thresh_sig.add_share(id.public, id.sign(&content.hash()));

    //     let dbc = Dbc {
    //         content,
    //         transaction,
    //         transaction_sigs: input_hashes
    //             .into_iter()
    //             .map(|i| (i, (thresh_key.clone(), thresh_sig.clone())))
    //             .collect(),
    //     };

    //     assert!(matches!(
    //         dbc.confirm_valid(&[&thresh_key]),
    //         Err(Error::DbcContentParentsDifferentFromTransactionInputs)
    //     ));
    // }

    #[quickcheck]
    fn prop_mint_signatures(
        amount: u64,
        n_inputs: u8,            // # of input DBC's
        n_valid_sigs: u8,        // # of valid sigs
        n_wrong_signer_sigs: u8, // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: u8,    // # of sigs from recognized authority but signing wrong message
        n_extra_input_sigs: u8,  // # of sigs for inputs not part of the transaction
    ) -> TestResult {
        if n_inputs > 7 {
            return TestResult::discard();
        }

        let (genesis, genesis_dbc) = Mint::genesis(amount);
        let genesis_inputs: BTreeSet<_> = vec![genesis_dbc.name()].into_iter().collect();

        let mint_request = prepare_even_split(&genesis_dbc, n_inputs);
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

        let mut transaction_sigs: BTreeMap<Hash, (PublicKey, Signature)> = Default::default();

        let mut repeating_inputs = mint_request.inputs.iter().cycle();

        // Valid sigs
        for _ in 0..n_valid_sigs {
            if let Some(input) = repeating_inputs.next() {
                transaction_sigs.insert(input.name(), (genesis.public_key(), mint_sig));
            }
        }
        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_signer_sigs {
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
        for _ in 0..n_wrong_msg_sigs {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = genesis.key_mgr.sign(&[0u8; 32]);
                transaction_sigs.insert(input.name(), (genesis.public_key(), wrong_msg_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs {
            transaction_sigs.insert(rand::random(), (genesis.public_key(), mint_sig));
        }

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs,
        };

        assert_eq!(dbc.amount(), amount);

        let validation_res = dbc.confirm_valid(&KeyCache::from(vec![genesis.public_key()]));

        println!("Validation Result: {:#?}", validation_res);
        match validation_res {
            Ok(()) => {
                assert_eq!(n_extra_input_sigs, 0);
                if n_inputs > 0 {
                    assert!(n_valid_sigs >= n_inputs);
                    assert_eq!(n_wrong_signer_sigs, 0);
                    assert_eq!(n_wrong_msg_sigs, 0);
                }
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs < n_inputs);
            }
            Err(Error::Ed25519(_)) => {
                assert!(n_wrong_msg_sigs > 0);
            }
            Err(Error::UnknownInput) => {
                assert!(n_extra_input_sigs > 0);
            }
            Err(Error::UnrecognisedAuthority) => {
                assert!(n_wrong_signer_sigs > 0);
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        TestResult::passed()
    }
}
