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

use crate::{
    Dbc, DbcContent, DbcTransaction, Error, KeyManager, NodeSignature, PublicKeySet, Result,
};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    iter::FromIterator,
};

pub type MintSignatures = BTreeMap<blsttc::PublicKey, (PublicKeySet, NodeSignature)>;

pub trait SpendBook: std::fmt::Debug + Clone {
    type Error: std::error::Error;

    fn lookup(&self, owner: &blsttc::PublicKey) -> Result<Option<&DbcTransaction>, Self::Error>;
    fn log(
        &mut self,
        owner: blsttc::PublicKey,
        transaction: DbcTransaction,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimpleSpendBook {
    pub transactions: BTreeMap<blsttc::PublicKey, DbcTransaction>,
}

impl SpendBook for SimpleSpendBook {
    type Error = std::convert::Infallible;

    fn lookup(&self, owner: &blsttc::PublicKey) -> Result<Option<&DbcTransaction>, Self::Error> {
        Ok(self.transactions.get(owner))
    }

    fn log(
        &mut self,
        owner: blsttc::PublicKey,
        transaction: DbcTransaction,
    ) -> Result<(), Self::Error> {
        self.transactions.insert(owner, transaction);
        Ok(())
    }
}

impl<'a> IntoIterator for &'a SimpleSpendBook {
    type Item = (&'a blsttc::PublicKey, &'a DbcTransaction);
    type IntoIter = std::collections::btree_map::Iter<'a, blsttc::PublicKey, DbcTransaction>;

    fn into_iter(self) -> Self::IntoIter {
        self.transactions.iter()
    }
}

impl IntoIterator for SimpleSpendBook {
    type Item = (blsttc::PublicKey, DbcTransaction);
    type IntoIter = std::collections::btree_map::IntoIter<blsttc::PublicKey, DbcTransaction>;

    fn into_iter(self) -> Self::IntoIter {
        self.transactions.into_iter()
    }
}

impl SimpleSpendBook {
    pub fn new() -> Self {
        Self {
            transactions: Default::default(),
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueTransaction {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcContent>,
}

impl ReissueTransaction {
    pub fn blinded(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: BTreeSet::from_iter(self.inputs.iter().map(|i| i.owner())),
            outputs: BTreeSet::from_iter(self.outputs.iter().map(|i| i.owner)),
        }
    }

    pub fn validate<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        self.validate_balance()?;
        self.validate_input_dbcs(verifier)?;
        self.validate_outputs()?;
        Ok(())
    }

    fn validate_balance(&self) -> Result<()> {
        // Calculate sum(input_commitments) and sum(output_commitments)
        let inputs: RistrettoPoint = self
            .inputs
            .iter()
            .map(|input| {
                input
                    .content
                    .commitment
                    .decompress()
                    .ok_or(Error::AmountCommitmentInvalid)
            })
            .sum::<Result<RistrettoPoint, _>>()?;
        let outputs: RistrettoPoint = self
            .outputs
            .iter()
            .map(|output| {
                output
                    .commitment
                    .decompress()
                    .ok_or(Error::AmountCommitmentInvalid)
            })
            .sum::<Result<RistrettoPoint, _>>()?;

        // Verify the range proof for each output.  (bulletproof)
        // This validates that the committed amount is a positive value.
        // (somewhere in the range 0..u64::max)
        //
        // TODO: investigate is there some way we could use RangeProof::verify_multiple() instead?
        // batched verifications should be faster.  It would seem to require that client call
        // RangeProof::prove_multiple() over all output DBC amounts. But then where to store the aggregated
        // RangeProof?  It corresponds to a set of outputs, not a single DBC. Would it make sense to store
        // a dup copy in each?  Unlike eg Monero we do not have a long-lived Transaction to store such data.
        for output in self.outputs.iter() {
            output.verify_range_proof()?;
        }

        if inputs != outputs {
            Err(Error::DbcReissueRequestDoesNotBalance)
        } else {
            Ok(())
        }
    }

    fn validate_input_dbcs<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        }

        for input in self.inputs.iter() {
            input.confirm_valid(verifier)?;
        }

        Ok(())
    }

    fn validate_outputs(&self) -> Result<()> {
        // Validate outputs are numbered 0..N_OUTPUTS
        let number_set = BTreeSet::from_iter(
            self.outputs
                .iter()
                .map(|dbc_content| dbc_content.output_number),
        );

        let expected_number_set = BTreeSet::from_iter(0..self.outputs.len() as u32);

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

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueRequest {
    pub transaction: ReissueTransaction,
    // Signatures from the owners of each input, signing `self.transaction.blinded().hash()`
    pub input_ownership_proofs: HashMap<blsttc::PublicKey, blsttc::Signature>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mint<K, S>
where
    K: KeyManager,
    S: SpendBook,
{
    pub(crate) key_manager: K,
    pub spendbook: S,
}

impl<K: KeyManager, S: SpendBook> Mint<K, S> {
    pub fn new(key_manager: K, spendbook: S) -> Self {
        Self {
            key_manager,
            spendbook,
        }
    }

    pub fn issue_genesis_dbc(
        &mut self,
        genesis_owner: blsttc::PublicKey,
        amount: u64,
    ) -> Result<(DbcContent, DbcTransaction, (PublicKeySet, NodeSignature))> {
        let parents = BTreeSet::from_iter([genesis_owner]);
        let content = DbcContent::new(
            parents,
            amount,
            0,
            self.key_manager
                .public_key_set()
                .map_err(|e| Error::Signing(e.to_string()))?
                .public_key(),
            DbcContent::random_blinding_factor(),
        )?;
        let transaction = DbcTransaction {
            inputs: BTreeSet::from_iter([genesis_owner]),
            outputs: BTreeSet::from_iter([content.owner]),
        };

        match self
            .spendbook
            .lookup(&genesis_owner)
            .map_err(|e| Error::SpendBook(e.to_string()))?
        {
            Some(tx) if tx != &transaction => return Err(Error::GenesisInputAlreadySpent),
            _ => (),
        }

        self.spendbook
            .log(genesis_owner, transaction.clone())
            .map_err(|e| Error::SpendBook(e.to_string()))?;
        let transaction_sig = self
            .key_manager
            .sign(&transaction.hash())
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok((
            content,
            transaction,
            (
                self.key_manager
                    .public_key_set()
                    .map_err(|e| Error::Signing(e.to_string()))?,
                transaction_sig,
            ),
        ))
    }

    pub fn is_spent(&self, owner: blsttc::PublicKey) -> Result<bool> {
        Ok(self
            .spendbook
            .lookup(&owner)
            .map_err(|e| Error::SpendBook(e.to_string()))?
            .is_some())
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    pub fn reissue(
        &mut self,
        reissue_req: ReissueRequest,
        inputs_belonging_to_mint: BTreeSet<blsttc::PublicKey>,
    ) -> Result<(DbcTransaction, MintSignatures)> {
        reissue_req.transaction.validate(self.key_manager())?;
        let transaction = reissue_req.transaction.blinded();
        let transaction_hash = transaction.hash();

        for input_dbc in reissue_req.transaction.inputs.iter() {
            match reissue_req.input_ownership_proofs.get(&input_dbc.owner()) {
                Some(sig) if !input_dbc.owner().verify(sig, &transaction_hash) => {
                    return Err(Error::FailedSignature)
                }
                Some(_) => (),
                None => return Err(Error::MissingInputOwnerProof),
            }
        }

        if !inputs_belonging_to_mint.is_subset(&transaction.inputs) {
            return Err(Error::FilteredInputNotPresent);
        }

        // Validate that each input has not yet been spent.
        for input in inputs_belonging_to_mint.iter() {
            if let Some(transaction) = self
                .spendbook
                .lookup(input)
                .map_err(|e| Error::SpendBook(e.to_string()))?
                .cloned()
            {
                // This input has already been spent, return the spend transaction to the user
                let transaction_sigs = self.sign_transaction(&transaction)?;
                return Err(Error::DbcAlreadySpent {
                    transaction,
                    transaction_sigs,
                });
            }
        }

        let transaction_sigs = self.sign_transaction(&transaction)?;

        for input in reissue_req
            .transaction
            .inputs
            .iter()
            .filter(|&i| inputs_belonging_to_mint.contains(&i.owner()))
        {
            self.spendbook
                .log(input.owner(), transaction.clone())
                .map_err(|e| Error::SpendBook(e.to_string()))?;
        }

        Ok((transaction, transaction_sigs))
    }

    fn sign_transaction(
        &self,
        transaction: &DbcTransaction,
    ) -> Result<BTreeMap<blsttc::PublicKey, (PublicKeySet, NodeSignature)>> {
        let sig = self
            .key_manager
            .sign(&transaction.hash())
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(transaction
            .inputs
            .iter()
            .copied()
            .zip(std::iter::repeat((
                self.key_manager
                    .public_key_set()
                    .map_err(|e| Error::Signing(e.to_string()))?,
                sig,
            )))
            .collect())
    }

    // Used in testing / benchmarking
    pub fn snapshot_spendbook(&self) -> S {
        self.spendbook.clone()
    }

    // Used in testing / benchmarking
    pub fn reset_spendbook(&mut self, spendbook: S) {
        self.spendbook = spendbook
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::scalar::Scalar;
    use quickcheck_macros::quickcheck;

    use crate::{
        tests::{DbcHelper, TinyInt, TinyVec},
        SimpleKeyManager, SimpleSigner,
    };

    #[quickcheck]
    fn prop_genesis() -> Result<(), Error> {
        let mint_owner = crate::bls_dkg_id();
        let mint_key = mint_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                mint_owner.public_key_set.clone(),
                (0, mint_owner.secret_key_share.clone()),
            ),
            mint_key,
        );
        let mut mint_node = Mint::new(key_manager, SimpleSpendBook::new());

        let genesis_key = crate::bls_dkg_id().public_key_set.public_key();
        let (gen_dbc_content, gen_dbc_trans, (mint_key_set, mint_node_sig)) =
            mint_node.issue_genesis_dbc(genesis_key, 1000).unwrap();

        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_node_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter([(genesis_key, (mint_key, mint_sig))]),
        };

        let genesis_amount = DbcHelper::decrypt_amount(&mint_owner, &genesis_dbc.content)?;

        assert_eq!(genesis_amount, 1000);
        genesis_dbc.confirm_valid(mint_node.key_manager())?;

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let output_amounts = Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<u64>));
        let output_amount = output_amounts.iter().sum();

        let mint_owner = crate::bls_dkg_id();
        let mint_key = mint_owner.public_key_set.public_key();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                mint_owner.public_key_set.clone(),
                (0, mint_owner.secret_key_share.clone()),
            ),
            mint_owner.public_key_set.public_key(),
        );
        let mut mint_node = Mint::new(key_manager.clone(), SimpleSpendBook::new());

        let genesis_key = crate::bls_dkg_id().public_key_set.public_key();
        let (gen_dbc_content, gen_dbc_trans, (mint_key_set, mint_node_sig)) =
            mint_node.issue_genesis_dbc(genesis_key, output_amount)?;
        let mint_sig = mint_key_set.combine_signatures([mint_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter([(genesis_key, (mint_key, mint_sig))]),
        };

        let inputs = HashSet::from_iter([genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.owner()));

        let genesis_amount_secrets =
            DbcHelper::decrypt_amount_secrets(&mint_owner, &genesis_dbc.content)?;

        let output_owner = crate::bls_dkg_id();
        let mut outputs_bf_sum = Scalar::default();
        let outputs = HashSet::from_iter(
            output_amounts
                .iter()
                .enumerate()
                .map(|(i, amount)| {
                    let blinding_factor = DbcContent::calc_blinding_factor(
                        i == output_amounts.len() - 1,
                        genesis_amount_secrets.blinding_factor,
                        outputs_bf_sum,
                    );
                    outputs_bf_sum += blinding_factor;

                    DbcContent::new(
                        input_hashes.clone(),
                        *amount,
                        i as u32,
                        output_owner.public_key_set.public_key(),
                        blinding_factor,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        let transaction = ReissueTransaction { inputs, outputs };

        let sig_share = mint_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = mint_owner
            .public_key_set
            .combine_signatures([(0, &sig_share)])?;

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter([(genesis_dbc.owner(), sig)]),
        };

        let (transaction, transaction_sigs) =
            match mint_node.reissue(reissue_req.clone(), input_hashes) {
                Ok((tx, sigs)) => {
                    // Verify that at least one output was present.
                    assert!(!output_amounts.is_empty());
                    (tx, sigs)
                }
                Err(Error::DbcReissueRequestDoesNotBalance) => {
                    // Verify that no outputs were present and we got correct validation error.
                    assert!(output_amounts.is_empty());
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

        // Verify transaction returned to us by the Mint matches our request
        assert_eq!(reissue_req.transaction.blinded(), transaction);

        // Verify signatures corespond to each input
        let (pub_key_set, sig) = transaction_sigs.values().cloned().next().unwrap();
        for input in reissue_req.transaction.inputs.iter() {
            assert_eq!(
                transaction_sigs.get(&input.owner()),
                Some(&(pub_key_set.clone(), sig.clone()))
            );
        }
        assert_eq!(transaction_sigs.len(), transaction.inputs.len());

        let mint_sig = mint_owner
            .public_key_set
            .combine_signatures(vec![sig.threshold_crypto()])?;

        let output_dbcs =
            Vec::from_iter(reissue_req.transaction.outputs.into_iter().map(|content| {
                Dbc {
                    content,
                    transaction: transaction.clone(),
                    transaction_sigs: BTreeMap::from_iter(
                        transaction_sigs
                            .iter()
                            .map(|(input, _)| (*input, (mint_key, mint_sig.clone()))),
                    ),
                }
            }));

        for dbc in output_dbcs.iter() {
            let expected_amount: u64 = output_amounts[dbc.content.output_number as usize];
            let dbc_amount = DbcHelper::decrypt_amount(&output_owner, &dbc.content)?;
            assert_eq!(dbc_amount, expected_amount);
            dbc.confirm_valid(&key_manager).unwrap();
            assert!(dbc.confirm_valid(&key_manager).is_ok());
        }

        assert_eq!(
            output_dbcs
                .iter()
                .map(|dbc| { DbcHelper::decrypt_amount(&output_owner, &dbc.content) })
                .sum::<Result<u64, _>>()?,
            output_amount
        );

        Ok(())
    }

    #[test]
    fn test_double_spend_protection() -> Result<()> {
        let mint_owner = crate::bls_dkg_id();
        let mint_key = mint_owner.public_key_set.public_key();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                mint_owner.public_key_set.clone(),
                (0, mint_owner.secret_key_share.clone()),
            ),
            mint_key,
        );
        let mut mint_node = Mint::new(key_manager, SimpleSpendBook::new());

        let genesis_key = crate::bls_dkg_id().public_key_set.public_key();
        let (gen_dbc_content, gen_dbc_trans, (mint_key_set, mint_node_sig)) =
            mint_node.issue_genesis_dbc(genesis_key, 1000)?;
        let mint_sig = mint_key_set.combine_signatures(vec![mint_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter([(genesis_key, (mint_key, mint_sig))]),
        };

        let inputs = HashSet::from_iter([genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter([genesis_dbc.owner()]);

        let genesis_secrets = DbcHelper::decrypt_amount_secrets(&mint_owner, &genesis_dbc.content)?;
        let outputs_owner = crate::bls_dkg_id();

        let transaction = ReissueTransaction {
            inputs: inputs.clone(),
            outputs: HashSet::from_iter([DbcContent::new(
                input_hashes.clone(),
                1000,
                0,
                outputs_owner.public_key_set.public_key(),
                genesis_secrets.blinding_factor,
            )
            .unwrap()]),
        };

        let sig_share = mint_node.key_manager.sign(&transaction.blinded().hash())?;

        let sig = mint_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter([(genesis_dbc.owner(), sig)]),
        };

        let (t, s) = mint_node.reissue(reissue_req, input_hashes.clone())?;

        let double_spend_transaction = ReissueTransaction {
            inputs,
            outputs: HashSet::from_iter([DbcContent::new(
                input_hashes.clone(),
                1000,
                0,
                outputs_owner.public_key_set.public_key(),
                genesis_secrets.blinding_factor,
            )?]),
        };

        let node_share = mint_node
            .key_manager
            .sign(&double_spend_transaction.blinded().hash())?;

        let sig = mint_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![node_share.threshold_crypto()])?;

        let double_spend_reissue_req = ReissueRequest {
            transaction: double_spend_transaction,
            input_ownership_proofs: HashMap::from_iter([(genesis_dbc.owner(), sig)]),
        };

        let res = mint_node.reissue(double_spend_reissue_req, input_hashes);

        println!("res {:?}", res);
        assert!(matches!(
            res,
            Err(Error::DbcAlreadySpent { transaction, transaction_sigs }) if transaction == t && transaction_sigs == s
        ));

        Ok(())
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
    ) -> Result<(), Error> {
        let input_amounts = Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<u64>));

        let output_amounts = Vec::from_iter(
            output_amounts
                .into_iter()
                .map(|(number, amount)| (number.coerce::<u32>(), amount.coerce::<u64>())),
        );

        let extra_output_parents =
            Vec::from_iter(extra_output_parents.into_iter().map(TinyInt::coerce::<u32>));

        let inputs_to_create_owner_proofs =
            BTreeSet::from_iter(input_owner_proofs.into_iter().map(TinyInt::coerce::<u32>));

        let inputs_to_create_invalid_owner_proofs = BTreeSet::from_iter(
            invalid_input_owner_proofs
                .into_iter()
                .map(TinyInt::coerce::<u32>),
        );

        let mint_owner = crate::bls_dkg_id();
        let mint_key = mint_owner.public_key_set.public_key();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                mint_owner.public_key_set.clone(),
                (0, mint_owner.secret_key_share.clone()),
            ),
            mint_key,
        );
        let mut mint_node = Mint::new(key_manager, SimpleSpendBook::new());

        let genesis_key = crate::bls_dkg_id().public_key_set.public_key();
        let genesis_amount: u64 = input_amounts.iter().sum();
        let (gen_dbc_content, gen_dbc_trans, (_gen_key, mint_node_sig)) =
            mint_node.issue_genesis_dbc(genesis_key, genesis_amount)?;

        let mint_sig = mint_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![mint_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter([(genesis_key, (mint_key, mint_sig))]),
        };

        let mut owners: BTreeMap<u32, bls_dkg::outcome::Outcome> = Default::default();

        let gen_inputs = HashSet::from_iter([genesis_dbc.clone()]);
        let gen_input_owners = BTreeSet::from_iter(gen_inputs.iter().map(Dbc::owner));
        let mut inputs_bf_sum: Scalar = Default::default();
        let genesis_amount_secrets =
            DbcHelper::decrypt_amount_secrets(&mint_owner, &genesis_dbc.content)?;
        let input_content = HashSet::from_iter(
            input_amounts
                .iter()
                .enumerate()
                .map(|(i, amount)| {
                    let owner = crate::bls_dkg_id();
                    let owner_public_key = owner.public_key_set.public_key();
                    owners.insert(i as u32, owner);
                    let blinding_factor = DbcContent::calc_blinding_factor(
                        i == input_amounts.len() - 1,
                        genesis_amount_secrets.blinding_factor,
                        inputs_bf_sum,
                    );
                    inputs_bf_sum += blinding_factor;
                    DbcContent::new(
                        gen_input_owners.clone(),
                        *amount,
                        i as u32,
                        owner_public_key,
                        blinding_factor,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        let mut reissue_req = ReissueRequest {
            transaction: ReissueTransaction {
                inputs: gen_inputs,
                outputs: input_content.clone(),
            },
            input_ownership_proofs: HashMap::default(),
        };
        let sig_share = mint_node
            .key_manager
            .sign(&reissue_req.transaction.blinded().hash())?;
        let sig = mint_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;
        reissue_req
            .input_ownership_proofs
            .insert(genesis_dbc.owner(), sig);

        let (transaction, transaction_sigs) = match mint_node.reissue(reissue_req, gen_input_owners)
        {
            Ok((tx, sigs)) => {
                // Verify that at least one input (output in this tx) was present.
                assert!(!input_amounts.is_empty());
                (tx, sigs)
            }
            Err(Error::DbcReissueRequestDoesNotBalance) => {
                // Verify that no inputs (outputs in this tx) were present and we got correct validation error.
                assert!(input_amounts.is_empty());
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let (mint_key_set, mint_sig_share) = transaction_sigs.values().cloned().next().unwrap();

        let mint_sig = mint_key_set.combine_signatures(vec![mint_sig_share.threshold_crypto()])?;

        let input_dbcs = HashSet::from_iter(input_content.into_iter().map(|content| {
            Dbc {
                content,
                transaction: transaction.clone(),
                transaction_sigs: BTreeMap::from_iter(
                    transaction_sigs
                        .iter()
                        .map(|(input, _)| (*input, (mint_key, mint_sig.clone()))),
                ),
            }
        }));

        let input_owners = BTreeSet::from_iter(input_dbcs.iter().map(Dbc::owner));

        let outputs_owner = crate::bls_dkg_id();
        let mut outputs_bf_sum: Scalar = Default::default();
        let mut output_counter: usize = 0;
        let outputs = HashSet::from_iter(
            output_amounts
                .iter()
                .map(|(output_number, amount)| {
                    let mut fuzzed_parents = input_owners.clone();

                    for _ in extra_output_parents
                        .iter()
                        .filter(|idx| idx == &output_number)
                    {
                        fuzzed_parents.insert(crate::bls_dkg_id().public_key_set.public_key());
                    }

                    let blinding_factor = DbcContent::calc_blinding_factor(
                        output_counter == output_amounts.len() - 1,
                        inputs_bf_sum,
                        outputs_bf_sum,
                    );
                    outputs_bf_sum += blinding_factor;
                    output_counter += 1;

                    DbcContent::new(
                        fuzzed_parents,
                        *amount,
                        *output_number,
                        outputs_owner.public_key_set.public_key(),
                        blinding_factor,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        let transaction = ReissueTransaction {
            inputs: input_dbcs,
            outputs: outputs.clone(),
        };

        let transaction_hash = transaction.blinded().hash();

        let mut input_ownership_proofs: HashMap<blsttc::PublicKey, blsttc::Signature> =
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
                    let owner = &owners[&dbc.content.output_number];
                    let sig_share = owner.secret_key_share.sign(&transaction_hash);
                    let owner_key_set = &owner.public_key_set;
                    let sig = owner_key_set
                        .combine_signatures(vec![(0, &sig_share)])
                        .unwrap();

                    (dbc.owner(), sig)
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
                    let owner_key_set = random_owner.public_key_set;
                    let sig = owner_key_set
                        .combine_signatures(vec![(0, &sig_share)])
                        .unwrap();

                    (dbc.owner(), sig)
                }),
        );

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs,
        };

        let many_to_many_result = mint_node.reissue(reissue_req, input_owners);

        let output_amount: u64 = outputs
            .iter()
            .map(|output| DbcHelper::decrypt_amount(&outputs_owner, output))
            .sum::<Result<u64, _>>()?;
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
                    outputs
                        .iter()
                        .map(|o| { DbcHelper::decrypt_amount(&outputs_owner, o) })
                        .collect::<Result<BTreeSet<_>, _>>()?,
                    BTreeSet::from_iter(output_amounts.into_iter().map(|(_, a)| a))
                );

                // The outputs should have been uniquely number from 0 to N (N = # of outputs)
                assert_eq!(
                    BTreeSet::from_iter(
                        outputs.iter().map(|content| content.output_number as usize)
                    ),
                    BTreeSet::from_iter(0..outputs.len())
                );

                let (mint_key_set, mint_sig_share) = transaction_sigs.values().next().unwrap();
                let mint_sig =
                    mint_key_set.combine_signatures([mint_sig_share.threshold_crypto()])?;

                let output_dbcs = Vec::from_iter(outputs.into_iter().map(|content| {
                    Dbc {
                        content,
                        transaction: transaction.clone(),
                        transaction_sigs: BTreeMap::from_iter(
                            transaction_sigs
                                .iter()
                                .map(|(input, _)| (*input, (mint_key, mint_sig.clone()))),
                        ),
                    }
                }));

                for dbc in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.confirm_valid(&mint_node.key_manager);
                    println!("DBC confirm result {:?}", dbc_confirm_result);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs
                        .iter()
                        .map(|dbc| { DbcHelper::decrypt_amount(&outputs_owner, &dbc.content) })
                        .sum::<Result<u64, _>>()?,
                    output_amount
                );
            }
            Err(Error::DbcReissueRequestDoesNotBalance { .. }) => {
                if genesis_amount == output_amount {
                    // This can correctly occur if there are 0 outputs and inputs sum to zero.
                    //
                    // The error occurs because there is no output with a commitment
                    // to match against the input commitment, and also no way to
                    // know that the input amount is zero.
                    assert!(output_amounts.is_empty());
                    assert_eq!(input_amounts.iter().sum::<u64>(), 0);
                    assert!(!input_amounts.is_empty());
                }
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
            Err(Error::FailedUnblinding) => {
                assert_ne!(inputs_to_create_invalid_owner_proofs.len(), 0);
            }
            err => panic!("Unexpected reissue err {:#?}", err),
        }

        Ok(())
    }

    #[quickcheck]
    #[ignore]
    fn prop_in_progress_transaction_can_be_continued_across_churn() {
        todo!()
    }

    #[test]
    fn test_inputs_are_validated() -> Result<(), Error> {
        let mint_owner = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::new(
                mint_owner.public_key_set.clone(),
                (0, mint_owner.secret_key_share.clone()),
            ),
            mint_owner.public_key_set.public_key(),
        );
        let mut mint_node = Mint::new(key_manager, SimpleSpendBook::new());

        let input_owner = crate::bls_dkg_id();
        let input_content = DbcContent::new(
            Default::default(),
            100,
            0,
            input_owner.public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;
        let input_content_owners = BTreeSet::from_iter([input_content.owner]);

        let fraudulant_reissue_result = mint_node.reissue(
            ReissueRequest {
                transaction: ReissueTransaction {
                    inputs: HashSet::from_iter([Dbc {
                        content: input_content,
                        transaction: DbcTransaction {
                            inputs: Default::default(),
                            outputs: input_content_owners.clone(),
                        },
                        transaction_sigs: Default::default(),
                    }]),
                    outputs: HashSet::from_iter([DbcContent::new(
                        input_content_owners.clone(),
                        100,
                        0,
                        crate::bls_dkg_id().public_key_set.public_key(),
                        DbcContent::random_blinding_factor(),
                    )?]),
                },
                input_ownership_proofs: HashMap::default(),
            },
            input_content_owners,
        );
        assert!(fraudulant_reissue_result.is_err());

        Ok(())
    }
}
