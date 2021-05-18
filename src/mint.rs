// Copyright 2021 MaidSafe.net limited.
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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    Dbc, DbcContent, DbcContentHash, DbcTransaction, Error, KeyCache, KeyManager, PublicKey,
    Result, Signature,
};

pub type InputSignatures = BTreeMap<DbcContentHash, (PublicKey, Signature)>;

#[derive(Default)]
struct SpendBook {
    transactions: BTreeMap<DbcContentHash, DbcTransaction>,
}

impl SpendBook {
    fn lookup(&self, dbc_hash: &DbcContentHash) -> Option<&DbcTransaction> {
        self.transactions.get(dbc_hash)
    }

    fn log(&mut self, dbc_hash: DbcContentHash, transaction: DbcTransaction) {
        self.transactions.insert(dbc_hash, transaction);
    }
}

#[derive(Debug, Clone)]
pub struct MintTransaction {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcContent>,
}

impl MintTransaction {
    pub fn blinded(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: self.inputs.iter().map(|i| i.name()).collect(),
            outputs: self.outputs.iter().map(|i| i.hash()).collect(),
        }
    }

    pub fn validate(&self, key_cache: &KeyCache) -> Result<()> {
        self.validate_balance()?;
        self.validate_input_dbcs(key_cache)?;
        self.validate_outputs()?;
        Ok(())
    }

    fn validate_balance(&self) -> Result<()> {
        let input: u64 = self.inputs.iter().map(|input| input.amount()).sum();
        let output: u64 = self.outputs.iter().map(|output| output.amount).sum();

        if input != output {
            Err(Error::DbcMintRequestDoesNotBalance { input, output })
        } else {
            Ok(())
        }
    }

    fn validate_input_dbcs(&self, key_cache: &KeyCache) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        }

        for input in self.inputs.iter() {
            input.confirm_valid(key_cache)?;
        }

        Ok(())
    }

    fn validate_outputs(&self) -> Result<()> {
        // Validate outputs are numbered 0..N_OUTPUTS
        let number_set = self
            .outputs
            .iter()
            .map(|dbc_content| dbc_content.output_number.into())
            .collect::<BTreeSet<_>>();

        let expected_number_set = (0..self.outputs.len()).into_iter().collect::<BTreeSet<_>>();

        if number_set != expected_number_set {
            println!(
                "output numbering is wrong {:?} != {:?}",
                number_set, expected_number_set
            );
            return Err(Error::OutputsAreNotNumberedCorrectly);
        }

        // Validate output parents match the blinded inputs
        let inputs = self.blinded().inputs;
        if self.outputs.iter().any(|o| o.parents != inputs) {
            return Err(Error::DbcContentParentsDifferentFromTransactionInputs);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub transaction: MintTransaction,
    // Signatures from the owners of each input, signing `self.transaction.blinded().hash()`
    pub input_ownership_proofs: HashMap<DbcContentHash, threshold_crypto::Signature>,
}

pub struct Mint {
    pub(crate) key_mgr: KeyManager,
    spendbook: SpendBook,
}

impl Mint {
    pub fn genesis(genesis_key: threshold_crypto::PublicKeySet, amount: u64) -> (Self, Dbc) {
        let key_mgr = KeyManager::new_genesis();

        let genesis_input = [0u8; 32];

        let parents = vec![genesis_input].into_iter().collect();
        let content = DbcContent::new(parents, amount, 0, genesis_key);

        let transaction = DbcTransaction {
            inputs: vec![genesis_input].into_iter().collect(),
            outputs: vec![content.hash()].into_iter().collect(),
        };

        let mut spendbook = SpendBook::default();
        spendbook.log(genesis_input, transaction.clone());

        let transaction_sig = key_mgr.sign(&transaction.hash());

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: vec![(genesis_input, (key_mgr.public_key(), transaction_sig))]
                .into_iter()
                .collect(),
        };

        (Self { key_mgr, spendbook }, dbc)
    }

    pub fn key_cache(&self) -> &KeyCache {
        self.key_mgr.key_cache()
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_mgr.public_key()
    }

    pub fn reissue(
        &mut self,
        mint_request: MintRequest,
    ) -> Result<(DbcTransaction, InputSignatures)> {
        mint_request.transaction.validate(self.key_cache())?;
        let transaction = mint_request.transaction.blinded();
        let transaction_hash = transaction.hash();

        for input_dbc in mint_request.transaction.inputs.iter() {
            let owner_key = input_dbc.content.owner.public_key();
            match mint_request.input_ownership_proofs.get(&input_dbc.name()) {
                Some(sig) if owner_key.verify(&sig, &transaction_hash) => (),
                Some(_) => return Err(Error::FailedSignature),
                None => return Err(Error::MissingInputOwnerProof),
            }
        }

        // Validate that each input has not yet been spent.
        for input in transaction.inputs.iter() {
            if let Some(transaction) = self.spendbook.lookup(&input).cloned() {
                // This input has already been spent, return the spend transaction to the user
                let transaction_sigs = self.sign_transaction(&transaction);
                return Err(Error::DbcAlreadySpent {
                    transaction,
                    transaction_sigs,
                });
            }
        }

        let transaction_sigs = self.sign_transaction(&transaction);

        for input in mint_request.transaction.inputs.iter() {
            self.spendbook.log(input.name(), transaction.clone());
        }

        Ok((transaction, transaction_sigs))
    }

    fn sign_transaction(
        &self,
        transaction: &DbcTransaction,
    ) -> BTreeMap<DbcContentHash, (PublicKey, Signature)> {
        let sig = self.key_mgr.sign(&transaction.hash());

        transaction
            .inputs
            .iter()
            .copied()
            .zip(std::iter::repeat((self.public_key(), sig)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{TinyInt, TinyVec};

    #[quickcheck]
    fn prop_genesis() {
        let genesis_owner = crate::bls_dkg_id();
        let (mint, genesis_dbc) = Mint::genesis(genesis_owner.public_key_set, 1000);

        assert_eq!(genesis_dbc.content.amount, 1000);
        let validation = genesis_dbc.confirm_valid(&mint.key_cache());
        println!("Genesis DBC Validation {:?}", validation);
        assert!(validation.is_ok());
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) {
        let output_amounts = Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<u64>));
        let output_amount = output_amounts.iter().sum();

        let genesis_owner = crate::bls_dkg_id();
        let (mut genesis, genesis_dbc) =
            Mint::genesis(genesis_owner.public_key_set.clone(), output_amount);

        let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let output_owner = crate::bls_dkg_id();
        let outputs = output_amounts
            .iter()
            .enumerate()
            .map(|(i, amount)| DbcContent {
                parents: input_hashes.clone(),
                amount: *amount,
                output_number: i as u8,
                owner: output_owner.public_key_set.clone(),
            })
            .collect();

        let transaction = MintTransaction { inputs, outputs };

        let sig_share = genesis_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(genesis_dbc.name(), sig)]),
        };

        let (transaction, transaction_sigs) = genesis.reissue(mint_request.clone()).unwrap();

        // Verify transaction returned to us by the Mint matches our request
        assert_eq!(mint_request.transaction.blinded(), transaction);

        // Verify signatures corespond to each input
        let (pubkey, sig) = transaction_sigs.values().cloned().next().unwrap();
        for input in mint_request.transaction.inputs.iter() {
            assert_eq!(transaction_sigs.get(&input.name()), Some(&(pubkey, sig)));
        }
        assert_eq!(transaction_sigs.len(), transaction.inputs.len());

        let output_dbcs = Vec::from_iter(mint_request.transaction.outputs.into_iter().map(
            |content| Dbc {
                content,
                transaction: transaction.clone(),
                transaction_sigs: transaction_sigs.clone(),
            },
        ));

        let key_cache = KeyCache::from(vec![genesis.public_key()]);
        for dbc in output_dbcs.iter() {
            let expected_amount: u64 = output_amounts[dbc.content.output_number as usize];
            assert_eq!(dbc.amount(), expected_amount);
            assert!(dbc.confirm_valid(&key_cache).is_ok());
        }

        assert_eq!(
            output_dbcs.iter().map(|dbc| dbc.amount()).sum::<u64>(),
            output_amount
        );
    }

    #[test]
    fn test_double_spend_protection() {
        let genesis_owner = crate::bls_dkg_id();
        let (mut genesis, genesis_dbc) = Mint::genesis(genesis_owner.public_key_set.clone(), 1000);

        let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(vec![genesis_dbc.name()]);

        let transaction = MintTransaction {
            inputs: inputs.clone(),
            outputs: HashSet::from_iter(vec![DbcContent {
                parents: input_hashes.clone(),
                amount: 1000,
                output_number: 0,
                owner: crate::bls_dkg_id().public_key_set,
            }]),
        };

        let sig_share = genesis_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(genesis_dbc.name(), sig)]),
        };

        let (t, s) = genesis.reissue(mint_request).unwrap();

        let double_spend_transaction = MintTransaction {
            inputs,
            outputs: HashSet::from_iter(vec![DbcContent {
                parents: input_hashes,
                amount: 1000,
                output_number: 0,
                owner: crate::bls_dkg_id().public_key_set,
            }]),
        };

        let sig_share = genesis_owner
            .secret_key_share
            .sign(&double_spend_transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let double_spend_mint_request = MintRequest {
            transaction: double_spend_transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(genesis_dbc.name(), sig)]),
        };

        let res = genesis.reissue(double_spend_mint_request);

        println!("res {:?}", res);
        assert!(matches!(
            res,
            Err(Error::DbcAlreadySpent { transaction, transaction_sigs }) if transaction == t && transaction_sigs == s
        ));
    }

    #[quickcheck]
    fn prop_dbc_transaction_many_to_many(
        // the amount of each input transaction
        input_amounts: TinyVec<TinyInt>,
        // The output_number and amount for each transaction output
        output_amounts: TinyVec<(TinyInt, TinyInt)>,
        // Outputs with output_numbers that appear in this vec will
        // have extra parents inserted into the transaction
        extra_output_parents: TinyVec<TinyInt>,
        // Include a valid ownership proof for the following inputs
        input_owner_proofs: TinyVec<TinyInt>,
        // Include an invalid ownership proof for the following inputs
        invalid_input_owner_proofs: TinyVec<TinyInt>,
    ) {
        let input_amounts = Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<u64>));

        let output_amounts = Vec::from_iter(
            output_amounts
                .into_iter()
                .map(|(number, amount)| (number.coerce::<u8>(), amount.coerce::<u64>())),
        );

        let extra_output_parents =
            Vec::from_iter(extra_output_parents.into_iter().map(TinyInt::coerce::<u8>));

        let inputs_to_create_owner_proofs =
            BTreeSet::from_iter(input_owner_proofs.into_iter().map(TinyInt::coerce::<u8>));

        let inputs_to_create_invalid_owner_proofs = BTreeSet::from_iter(
            invalid_input_owner_proofs
                .into_iter()
                .map(TinyInt::coerce::<u8>),
        );

        let genesis_owner = crate::bls_dkg_id();
        let genesis_amount: u64 = input_amounts.iter().sum();
        let (mut genesis, genesis_dbc) =
            Mint::genesis(genesis_owner.public_key_set.clone(), genesis_amount);

        let mut owners: BTreeMap<u8, threshold_crypto::SecretKeyShare> = Default::default();

        let gen_inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
        let gen_input_hashes = BTreeSet::from_iter(gen_inputs.iter().map(Dbc::name));
        let input_content =
            HashSet::from_iter(input_amounts.iter().enumerate().map(|(i, amount)| {
                let owner = crate::bls_dkg_id();
                owners.insert(i as u8, owner.secret_key_share);
                DbcContent::new(
                    gen_input_hashes.clone(),
                    *amount,
                    i as u8,
                    owner.public_key_set,
                )
            }));

        let mut mint_request = MintRequest {
            transaction: MintTransaction {
                inputs: gen_inputs,
                outputs: input_content.clone(),
            },
            input_ownership_proofs: HashMap::default(),
        };
        let sig_share = genesis_owner
            .secret_key_share
            .sign(&mint_request.transaction.blinded().hash());
        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();
        mint_request
            .input_ownership_proofs
            .insert(genesis_dbc.name(), sig);

        let (transaction, transaction_sigs) = genesis.reissue(mint_request).unwrap();

        let input_dbcs = HashSet::from_iter(input_content.into_iter().map(|content| Dbc {
            content,
            transaction: transaction.clone(),
            transaction_sigs: transaction_sigs.clone(),
        }));

        let input_hashes = BTreeSet::from_iter(input_dbcs.iter().map(Dbc::name));

        let outputs = HashSet::from_iter(output_amounts.iter().map(|(output_number, amount)| {
            let mut fuzzed_parents = input_hashes.clone();

            for _ in extra_output_parents
                .iter()
                .filter(|idx| idx == &output_number)
            {
                fuzzed_parents.insert(rand::random());
            }

            let output_owner = crate::bls_dkg_id();
            DbcContent::new(
                fuzzed_parents,
                *amount,
                *output_number,
                output_owner.public_key_set,
            )
        }));

        let transaction = MintTransaction {
            inputs: input_dbcs,
            outputs: outputs.clone(),
        };

        let transaction_hash = transaction.blinded().hash();

        let mut input_ownership_proofs: HashMap<crate::Hash, threshold_crypto::Signature> =
            Default::default();
        input_ownership_proofs.extend(
            inputs_to_create_owner_proofs
                .iter()
                .filter_map(|in_number| {
                    transaction
                        .inputs
                        .iter()
                        .find(|dbc| dbc.content.output_number == *in_number)
                })
                .map(|dbc| {
                    let sig_share = owners[&dbc.content.output_number].sign(&transaction_hash);
                    let sig = dbc
                        .content
                        .owner
                        .combine_signatures(vec![(0, &sig_share)])
                        .unwrap();

                    (dbc.name(), sig)
                }),
        );

        input_ownership_proofs.extend(
            inputs_to_create_invalid_owner_proofs
                .iter()
                .filter_map(|in_number| {
                    transaction
                        .inputs
                        .iter()
                        .find(|dbc| dbc.content.output_number == *in_number)
                })
                .map(|dbc| {
                    let random_owner = crate::bls_dkg_id();
                    let sig_share = random_owner.secret_key_share.sign(&transaction_hash);
                    let sig = random_owner
                        .public_key_set
                        .combine_signatures(vec![(0, &sig_share)])
                        .unwrap();

                    (dbc.name(), sig)
                }),
        );

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs,
        };

        let many_to_many_result = genesis.reissue(mint_request);

        let output_amount: u64 = outputs.iter().map(|output| output.amount).sum();
        let number_of_fuzzed_output_parents = BTreeSet::from_iter(extra_output_parents)
            .intersection(&BTreeSet::from_iter(output_amounts.iter().map(|(n, _)| *n)))
            .count();

        match many_to_many_result {
            Ok((transaction, transaction_sigs)) => {
                assert_eq!(genesis_amount, output_amount);
                assert_eq!(number_of_fuzzed_output_parents, 0);
                assert!(
                    input_amounts.is_empty()
                        || inputs_to_create_invalid_owner_proofs
                            .intersection(&BTreeSet::from_iter(owners.keys().copied()))
                            .next()
                            .is_none()
                );
                assert!(BTreeSet::from_iter(owners.keys().copied())
                    .is_subset(&inputs_to_create_owner_proofs));

                // The output amounts should correspond to the output_amounts
                assert_eq!(
                    BTreeSet::from_iter(outputs.iter().map(|o| o.amount)),
                    BTreeSet::from_iter(output_amounts.into_iter().map(|(_, a)| a))
                );

                // The outputs should have been uniquely number from 0 to N (N = # of outputs)
                assert_eq!(
                    BTreeSet::from_iter(
                        outputs.iter().map(|content| content.output_number as usize)
                    ),
                    BTreeSet::from_iter(0..outputs.len())
                );

                let output_dbcs = Vec::from_iter(outputs.into_iter().map(|content| Dbc {
                    content,
                    transaction: transaction.clone(),
                    transaction_sigs: transaction_sigs.clone(),
                }));

                for dbc in output_dbcs.iter() {
                    let dbc_confirm_result =
                        dbc.confirm_valid(&KeyCache::from(vec![genesis.public_key()]));
                    println!("DBC confirm result {:?}", dbc_confirm_result);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs.iter().map(|dbc| dbc.amount()).sum::<u64>(),
                    output_amount
                );
            }
            Err(Error::DbcMintRequestDoesNotBalance { .. }) => {
                assert_ne!(genesis_amount, output_amount);
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(input_amounts.len(), 0);
            }
            Err(Error::OutputsAreNotNumberedCorrectly) => {
                assert_ne!(
                    BTreeSet::from_iter(
                        outputs.iter().map(|content| content.output_number as usize)
                    ),
                    BTreeSet::from_iter(0..outputs.len())
                );
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert_ne!(number_of_fuzzed_output_parents, 0)
            }
            Err(Error::MissingInputOwnerProof) => {
                assert!(!BTreeSet::from_iter(owners.keys().copied())
                    .is_subset(&inputs_to_create_owner_proofs));
            }
            Err(Error::FailedSignature) => {
                assert_ne!(inputs_to_create_invalid_owner_proofs.len(), 0);
            }
            err => panic!("Unexpected reissue err {:#?}", err),
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
    fn test_inputs_are_validated() {
        let genesis_owner = crate::bls_dkg_id();
        let (mut genesis, _) = Mint::genesis(genesis_owner.public_key_set, 1000);

        let input_owner = crate::bls_dkg_id();

        let input_content = DbcContent {
            parents: Default::default(),
            amount: 100,
            output_number: 0,
            owner: input_owner.public_key_set,
        };
        let input_content_hashes = BTreeSet::from_iter(vec![input_content.hash()]);

        let output_owner = crate::bls_dkg_id();

        let fraudulant_reissue_result = genesis.reissue(MintRequest {
            transaction: MintTransaction {
                inputs: HashSet::from_iter(vec![Dbc {
                    content: input_content,
                    transaction: DbcTransaction {
                        inputs: Default::default(),
                        outputs: input_content_hashes.clone(),
                    },
                    transaction_sigs: Default::default(),
                }]),
                outputs: HashSet::from_iter(vec![DbcContent {
                    parents: input_content_hashes,
                    amount: 100,
                    output_number: 0,
                    owner: output_owner.public_key_set,
                }]),
            },
            input_ownership_proofs: HashMap::default(),
        });
        assert!(fraudulant_reissue_result.is_err());
    }
}
