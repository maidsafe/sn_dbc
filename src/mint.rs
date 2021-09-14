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
    Amount, Dbc, DbcContent, DbcTransaction, Error, KeyManager, NodeSignature, PublicKey,
    PublicKeySet, Result, SpendBook, SpendKey,
};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    iter::FromIterator,
};

pub type MintNodeSignatures = BTreeMap<SpendKey, (PublicKeySet, NodeSignature)>;

pub fn genesis_dbc_input() -> SpendKey {
    use blsttc::group::CurveProjective;
    let gen_bytes = blsttc::convert::g1_to_be_bytes(blsttc::G1::one());
    SpendKey(PublicKey::from_bytes(gen_bytes).unwrap())
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueTransaction {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcContent>,
}

impl ReissueTransaction {
    pub fn blinded(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: BTreeSet::from_iter(self.inputs.iter().map(Dbc::spend_key)),
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
    pub input_ownership_proofs: HashMap<SpendKey, blsttc::Signature>,
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueShare {
    pub dbc_transaction: DbcTransaction,
    pub mint_node_signatures: MintNodeSignatures,
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
        amount: Amount,
    ) -> Result<(DbcContent, DbcTransaction, (PublicKeySet, NodeSignature))> {
        let parents = BTreeSet::from_iter([genesis_dbc_input()]);
        let content = DbcContent::new(
            parents,
            amount,
            self.key_manager
                .public_key_set()
                .map_err(|e| Error::Signing(e.to_string()))?
                .public_key(),
            DbcContent::random_blinding_factor(),
        )?;
        let transaction = DbcTransaction {
            inputs: BTreeSet::from_iter([genesis_dbc_input()]),
            outputs: BTreeSet::from_iter([content.owner]),
        };

        match self
            .spendbook
            .lookup(&genesis_dbc_input())
            .map_err(|e| Error::SpendBook(e.to_string()))?
        {
            Some(tx) if tx != &transaction => return Err(Error::GenesisInputAlreadySpent),
            _ => (),
        }

        self.spendbook
            .log(genesis_dbc_input(), transaction.clone())
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

    pub fn is_spent(&self, spend_key: SpendKey) -> Result<bool> {
        Ok(self
            .spendbook
            .lookup(&spend_key)
            .map_err(|e| Error::SpendBook(e.to_string()))?
            .is_some())
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    pub fn reissue(
        &mut self,
        reissue_req: ReissueRequest,
        inputs_belonging_to_mint: BTreeSet<SpendKey>,
    ) -> Result<ReissueShare> {
        reissue_req.transaction.validate(self.key_manager())?;
        let transaction = reissue_req.transaction.blinded();
        let transaction_hash = transaction.hash();

        for input_dbc in reissue_req.transaction.inputs.iter() {
            let input_spend_key = input_dbc.spend_key();
            match reissue_req.input_ownership_proofs.get(&input_spend_key) {
                Some(sig) if input_spend_key.0.verify(sig, &transaction_hash) => (),
                Some(_) => return Err(Error::FailedSignature),
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
            .filter(|&i| inputs_belonging_to_mint.contains(&i.spend_key()))
        {
            self.spendbook
                .log(input.spend_key(), transaction.clone())
                .map_err(|e| Error::SpendBook(e.to_string()))?;
        }

        let reissue_share = ReissueShare {
            dbc_transaction: transaction,
            mint_node_signatures: transaction_sigs,
        };

        Ok(reissue_share)
    }

    fn sign_transaction(
        &self,
        transaction: &DbcTransaction,
    ) -> Result<BTreeMap<SpendKey, (PublicKeySet, NodeSignature)>> {
        let sig = self
            .key_manager
            .sign(&transaction.hash())
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(BTreeMap::from_iter(
            transaction.inputs.iter().copied().zip(std::iter::repeat((
                self.key_manager
                    .public_key_set()
                    .map_err(|e| Error::Signing(e.to_string()))?,
                sig,
            ))),
        ))
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
    use blsttc::{Ciphertext, DecryptionShare, SecretKeyShare};
    use quickcheck_macros::quickcheck;

    use crate::{
        tests::{TinyInt, TinyVec},
        DbcBuilder, DbcHelper, SimpleKeyManager, SimpleSigner, SimpleSpendBook,
    };

    #[quickcheck]
    fn prop_genesis() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let (gen_dbc_content, gen_dbc_trans, (gen_key_set, gen_node_sig)) =
            genesis_node.issue_genesis_dbc(1000).unwrap();

        let genesis_sig = gen_key_set
            .combine_signatures(vec![gen_node_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_trans,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };

        let genesis_amount = DbcHelper::decrypt_amount(&genesis_owner, &genesis_dbc.content)?;

        assert_eq!(genesis_amount, 1000);
        let validation = genesis_dbc.confirm_valid(genesis_node.key_manager());
        assert!(validation.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        let n_outputs = output_amounts.len();
        let output_amount = output_amounts.iter().sum();

        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();
        let key_manager =
            SimpleKeyManager::new(SimpleSigner::from(genesis_owner.clone()), genesis_key);
        let mut genesis_node = Mint::new(key_manager.clone(), SimpleSpendBook::new());

        let (gen_dbc_content, gen_dbc_tx, (gen_key_set, gen_node_sig)) =
            genesis_node.issue_genesis_dbc(output_amount)?;
        let genesis_sig = gen_key_set.combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_tx,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };
        let gen_dbc_spend_key = genesis_dbc.spend_key();

        let genesis_amount_secrets =
            DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

        let output_owner = crate::bls_dkg_id();
        let output_owner_pk = output_owner.public_key_set.public_key();

        let reissue_tx = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone(), genesis_amount_secrets)
            .add_outputs(output_amounts.iter().map(|a| crate::Output {
                amount: *a,
                owner: output_owner_pk,
            }))
            .build()?;

        let sig_share = genesis_owner
            .secret_key_share
            .derive_child(&genesis_dbc.spend_key_index())
            .sign(&reissue_tx.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(genesis_owner.index, &sig_share)])?;

        let reissue_req = ReissueRequest {
            transaction: reissue_tx.clone(),
            input_ownership_proofs: HashMap::from_iter([(gen_dbc_spend_key, sig)]),
        };

        let reissue_share =
            match genesis_node.reissue(reissue_req, BTreeSet::from_iter([gen_dbc_spend_key])) {
                Ok(rs) => {
                    // Verify that at least one output was present.
                    assert_ne!(n_outputs, 0);
                    rs
                }
                Err(Error::DbcReissueRequestDoesNotBalance) => {
                    // Verify that no outputs were present and we got correct validation error.
                    assert_eq!(n_outputs, 0);
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(reissue_tx);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        for dbc in output_dbcs.iter() {
            let dbc_amount = DbcHelper::decrypt_amount(&output_owner, &dbc.content)?;
            assert!(output_amounts.iter().any(|a| *a == dbc_amount));
            assert!(dbc.confirm_valid(&key_manager).is_ok());
        }

        assert_eq!(
            output_dbcs
                .iter()
                .map(|dbc| { DbcHelper::decrypt_amount(&output_owner, &dbc.content) })
                .sum::<Result<Amount, _>>()?,
            output_amount
        );

        Ok(())
    }

    #[test]
    fn test_double_spend_protection() -> Result<()> {
        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();
        let key_manager =
            SimpleKeyManager::new(SimpleSigner::from(genesis_owner.clone()), genesis_key);
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let (gen_dbc_content, gen_dbc_tx, (gen_key_set, gen_node_sig)) =
            genesis_node.issue_genesis_dbc(1000)?;
        let genesis_sig = gen_key_set.combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_tx,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };
        let gen_dbc_spend_key = genesis_dbc.spend_key();

        let genesis_amount_secrets =
            DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

        let output_owner = crate::bls_dkg_id();
        let reissue_tx = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone(), genesis_amount_secrets)
            .add_output(crate::Output {
                amount: 1000,
                owner: output_owner.public_key_set.public_key(),
            })
            .build()?;

        let sig_share = genesis_node
            .key_manager
            .sign_with_child_key(&genesis_dbc.spend_key_index(), &reissue_tx.blinded().hash())?;

        let sig = genesis_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;

        let reissue_req = ReissueRequest {
            transaction: reissue_tx,
            input_ownership_proofs: HashMap::from_iter([(gen_dbc_spend_key, sig)]),
        };

        let reissue_share =
            genesis_node.reissue(reissue_req, BTreeSet::from_iter([gen_dbc_spend_key]))?;
        let t = reissue_share.dbc_transaction;
        let s = reissue_share.mint_node_signatures;

        let double_spend_reissue_tx = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone(), genesis_amount_secrets)
            .add_output(crate::Output {
                amount: 1000,
                owner: output_owner.public_key_set.public_key(),
            })
            .build()?;

        let sig_share = genesis_node.key_manager.sign_with_child_key(
            &genesis_dbc.spend_key_index(),
            &double_spend_reissue_tx.blinded().hash(),
        )?;

        let sig = genesis_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;

        let double_spend_reissue_req = ReissueRequest {
            transaction: double_spend_reissue_tx,
            input_ownership_proofs: HashMap::from_iter([(gen_dbc_spend_key, sig)]),
        };

        let res = genesis_node.reissue(
            double_spend_reissue_req,
            BTreeSet::from_iter([gen_dbc_spend_key]),
        );

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
        // The amount for each transaction output
        output_amounts: TinyVec<TinyInt>,
        // Controls which output dbc's will receive extra parent hashes
        extra_output_parents: TinyVec<TinyInt>,
        // Include a valid ownership proof for the following inputs
        input_owner_proofs: TinyVec<TinyInt>,
        // Include an invalid ownership proof for the following inputs
        invalid_input_owner_proofs: TinyVec<TinyInt>,
    ) -> Result<(), Error> {
        let input_amounts =
            Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<Amount>));

        let output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));

        let extra_output_parents = Vec::from_iter(
            extra_output_parents
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        let inputs_to_create_owner_proofs =
            BTreeSet::from_iter(input_owner_proofs.into_iter().map(TinyInt::coerce::<usize>));

        let inputs_to_create_invalid_owner_proofs = BTreeSet::from_iter(
            invalid_input_owner_proofs
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let genesis_amount: Amount = input_amounts.iter().sum();
        let (gen_dbc_content, gen_dbc_tx, (_gen_key, gen_node_sig)) =
            genesis_node.issue_genesis_dbc(genesis_amount)?;

        let genesis_sig = genesis_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_tx,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };
        let gen_dbc_spend_key = genesis_dbc.spend_key();

        let genesis_amount_secrets =
            DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

        let owner_amounts_and_keys = BTreeMap::from_iter(input_amounts.iter().copied().map(|a| {
            let owner = crate::bls_dkg_id();
            (owner.public_key_set.public_key(), (a, owner))
        }));

        let reissue_tx = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone(), genesis_amount_secrets)
            .add_outputs(
                owner_amounts_and_keys
                    .clone()
                    .into_iter()
                    .map(|(owner, (amount, _))| crate::Output { amount, owner }),
            )
            .build()?;

        let sig_share = genesis_node
            .key_manager
            .sign_with_child_key(&genesis_dbc.spend_key_index(), &reissue_tx.blinded().hash())?;
        let sig = genesis_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;

        let reissue_req1 = ReissueRequest {
            transaction: reissue_tx,
            input_ownership_proofs: HashMap::from_iter([(gen_dbc_spend_key, sig)]),
        };

        let reissue_share = match genesis_node.reissue(
            reissue_req1.clone(),
            BTreeSet::from_iter([gen_dbc_spend_key]),
        ) {
            Ok(rs) => {
                // Verify that at least one input (output in this tx) was present.
                assert!(!input_amounts.is_empty());
                rs
            }
            Err(Error::DbcReissueRequestDoesNotBalance) => {
                // Verify that no inputs (outputs in this tx) were present and we got correct validation error.
                assert!(input_amounts.is_empty());
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(reissue_req1.transaction);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        let input_dbcs = output_dbcs
            .into_iter()
            .map(|dbc| {
                let (_, owner) = &owner_amounts_and_keys[&dbc.owner()];
                let amount_secrets = DbcHelper::decrypt_amount_secrets(owner, &dbc.content)?;
                Ok((dbc, amount_secrets))
            })
            .collect::<Result<Vec<(Dbc, crate::AmountSecrets)>>>()?;

        let outputs_owner = crate::bls_dkg_id();

        let mut reissue_tx = crate::TransactionBuilder::default()
            .add_inputs(input_dbcs)
            .add_outputs(output_amounts.iter().map(|amount| crate::Output {
                amount: *amount,
                owner: outputs_owner.public_key_set.public_key(),
            }))
            .build()?;

        let mut dbcs_with_fuzzed_parents = BTreeSet::new();

        for (out_idx, mut out_dbc_content) in std::mem::take(&mut reissue_tx.outputs)
            .into_iter()
            .enumerate()
        {
            let extra_random_parents = Vec::from_iter(
                extra_output_parents
                    .iter()
                    .filter(|idx| **idx == out_idx)
                    .map(|_| rand::random::<SpendKey>()),
            );
            if !extra_random_parents.is_empty() {
                dbcs_with_fuzzed_parents.insert(out_dbc_content.hash());
            }
            out_dbc_content.parents.extend(extra_random_parents);
            reissue_tx.outputs.insert(out_dbc_content);
        }

        let dbcs_with_valid_ownership_proofs = inputs_to_create_owner_proofs
            .into_iter()
            .filter_map(|input_num| reissue_tx.inputs.iter().nth(input_num))
            .map(|dbc| {
                let (_, owner) = &owner_amounts_and_keys[&dbc.owner()];
                let sig_share = owner
                    .secret_key_share
                    .derive_child(&dbc.spend_key_index())
                    .sign(&reissue_tx.blinded().hash());
                let owner_key_set = &owner.public_key_set;
                let sig = owner_key_set.combine_signatures(vec![(owner.index, &sig_share)])?;
                Ok((dbc.spend_key(), sig))
            })
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let dbcs_with_invalid_ownership_proofs = inputs_to_create_invalid_owner_proofs
            .into_iter()
            .filter_map(|input_num| reissue_tx.inputs.iter().nth(input_num))
            .map(|dbc| {
                let random_owner = crate::bls_dkg_id();
                let sig_share = random_owner
                    .secret_key_share
                    .sign(&reissue_tx.blinded().hash());
                let owner_key_set = random_owner.public_key_set;
                let sig =
                    owner_key_set.combine_signatures(vec![(random_owner.index, &sig_share)])?;

                Ok((dbc.spend_key(), sig))
            })
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let input_ownership_proofs = HashMap::from_iter(
            dbcs_with_valid_ownership_proofs
                .clone()
                .into_iter()
                .chain(dbcs_with_invalid_ownership_proofs.clone().into_iter()),
        );

        let dbc_output_amounts = reissue_tx
            .outputs
            .iter()
            .map(|o| DbcHelper::decrypt_amount(&outputs_owner, o))
            .collect::<Result<Vec<_>, _>>()?;
        let output_total_amount: Amount = dbc_output_amounts.iter().sum();

        let reissue_req2 = ReissueRequest {
            transaction: reissue_tx,
            input_ownership_proofs,
        };

        let many_to_many_result = genesis_node.reissue(
            reissue_req2.clone(),
            BTreeSet::from_iter(reissue_req2.transaction.blinded().inputs),
        );

        match many_to_many_result {
            Ok(rs) => {
                assert_eq!(genesis_amount, output_total_amount);
                assert_eq!(dbcs_with_fuzzed_parents.len(), 0);
                assert!(
                    input_amounts.is_empty()
                        || BTreeSet::from_iter(dbcs_with_invalid_ownership_proofs.keys().copied())
                            .intersection(&BTreeSet::from_iter(owner_amounts_and_keys.keys().map(
                                |pk| {
                                    reissue_req2
                                        .transaction
                                        .inputs
                                        .iter()
                                        .find(|dbc| dbc.owner() == *pk)
                                        .unwrap()
                                        .spend_key()
                                }
                            )))
                            .next()
                            .is_none()
                );

                assert!(BTreeSet::from_iter(owner_amounts_and_keys.keys().map(|pk| {
                    reissue_req2
                        .transaction
                        .inputs
                        .iter()
                        .find(|dbc| dbc.owner() == *pk)
                        .unwrap()
                        .spend_key()
                }))
                .is_subset(&BTreeSet::from_iter(
                    dbcs_with_valid_ownership_proofs.keys().copied()
                )));

                // The output amounts should correspond to the output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts),
                    BTreeSet::from_iter(output_amounts)
                );

                // Aggregate ReissueShare to build output DBCs
                let mut dbc_builder = DbcBuilder::new(reissue_req2.transaction);
                dbc_builder = dbc_builder.add_reissue_share(rs);
                let output_dbcs = dbc_builder.build()?;

                for dbc in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.confirm_valid(&genesis_node.key_manager);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs
                        .iter()
                        .map(|dbc| { DbcHelper::decrypt_amount(&outputs_owner, &dbc.content) })
                        .sum::<Result<Amount, _>>()?,
                    output_total_amount
                );
            }
            Err(Error::DbcReissueRequestDoesNotBalance { .. }) => {
                if genesis_amount == output_total_amount {
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
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(input_amounts.len(), 0);
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert_ne!(dbcs_with_fuzzed_parents.len(), 0)
            }
            Err(Error::MissingInputOwnerProof) => {
                assert!(
                    !BTreeSet::from_iter(owner_amounts_and_keys.keys().map(|pk| {
                        reissue_req2
                            .transaction
                            .inputs
                            .iter()
                            .find(|dbc| dbc.owner() == *pk)
                            .unwrap()
                            .spend_key()
                    }))
                    .is_subset(&BTreeSet::from_iter(
                        dbcs_with_valid_ownership_proofs.keys().copied()
                    ))
                );
            }
            Err(Error::FailedSignature) => {
                assert_ne!(dbcs_with_invalid_ownership_proofs.len(), 0);
            }
            Err(Error::FailedUnblinding) => {
                assert_ne!(dbcs_with_invalid_ownership_proofs.len(), 0);
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

    #[quickcheck]
    #[ignore]
    fn prop_reject_invalid_prefix() {
        todo!();
    }

    #[test]
    fn test_inputs_are_validated() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let input_owner = crate::bls_dkg_id();
        let input_content = DbcContent::new(
            Default::default(),
            100,
            input_owner.public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;
        let input_owners = BTreeSet::from_iter([input_content.owner]);

        let in_dbc = Dbc {
            content: input_content,
            transaction: DbcTransaction {
                inputs: Default::default(),
                outputs: input_owners,
            },
            transaction_sigs: Default::default(),
        };

        let in_dbc_spend_keys = BTreeSet::from_iter([in_dbc.spend_key()]);

        let fraudulant_reissue_result = genesis_node.reissue(
            ReissueRequest {
                transaction: ReissueTransaction {
                    inputs: HashSet::from_iter([in_dbc]),
                    outputs: HashSet::from_iter([DbcContent::new(
                        in_dbc_spend_keys.clone(),
                        100,
                        crate::bls_dkg_id().public_key_set.public_key(),
                        DbcContent::random_blinding_factor(),
                    )?]),
                },
                input_ownership_proofs: HashMap::default(),
            },
            in_dbc_spend_keys,
        );
        assert!(fraudulant_reissue_result.is_err());

        Ok(())
    }

    /// This tests how the system handles a mis-match between the
    /// committed amount and amount encrypted in AmountSecrets.
    /// Normally these should be the same, however a malicious user or buggy
    /// implementation could produce different values.  The mint cannot detect
    /// this situation and prevent it as the secret amount is encrypted.  So it
    /// is up to the recipient to check that the amounts match upon receipt.  If they
    /// do not match and the recipient cannot learn (or guess) the committed value then
    /// the DBC will be unspendable. If they do learn the committed amount then it
    /// can still be spent.  So herein we do the following to test:
    ///
    /// 1. produce a standard genesis DBC with value 1000
    /// 2. reissue genesis DBC to an output with mis-matched amounts where the
    ///      committed amount is 1000 (required to match input) but the secret
    ///      amount is 2000.
    /// 3. Check if the amounts match, using the two provided APIs.
    ///      assert that APIs report they do not match.
    /// 4. Attempt to reissue the mis-matched output using the amount from
    ///      AmountSecrets.  Verify that this fails with error DbcReissueRequestDoesNotBalance
    /// 5. Attempt to reissue using the correct amount that was committed to.
    ///      Verify that this reissue succeeds.
    #[test]
    fn test_mismatched_amount_and_commitment() -> Result<(), Error> {
        // ----------
        // Phase 1. Creation of Genesis DBC
        // ----------
        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager.clone(), SimpleSpendBook::new());

        let (gen_dbc_content, gen_dbc_tx, (gen_key_set, gen_node_sig)) =
            genesis_node.issue_genesis_dbc(1000)?;
        let genesis_sig = gen_key_set.combine_signatures(vec![gen_node_sig.threshold_crypto()])?;

        let genesis_dbc = Dbc {
            content: gen_dbc_content,
            transaction: gen_dbc_tx,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };

        let genesis_secrets =
            DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

        let outputs_owner = crate::bls_dkg_id();
        let outputs_owner_pk = outputs_owner.public_key_set.public_key();
        let output_amount = 1000;

        let mut transaction = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone(), genesis_secrets)
            .add_output(crate::Output {
                amount: output_amount,
                owner: outputs_owner_pk,
            })
            .build()?;

        // ----------
        // Phase 2. Creation of mis-matched output
        // ----------

        // Here we modify the transaction output to have a different committed amount than the secret amount.
        // The sn_dbc API does not allow this so we manually modify the reissue transaction.
        let mut out_dbc_content = std::mem::take(&mut transaction.outputs)
            .into_iter()
            .next()
            .expect("We should have a single output");

        // obtain amount secrets
        let secrets = DbcHelper::decrypt_amount_secrets(&outputs_owner, &out_dbc_content)?;

        // Replace the encrypted secret amount with an encrypted secret claiming
        // twice the committed value.
        let fudged_amount_secrets = crate::AmountSecrets {
            amount: secrets.amount * 2, // Claim we are paying twice the committed value
            blinding_factor: secrets.blinding_factor, // Use the real blinding factor
        };

        out_dbc_content.amount_secrets_cipher =
            outputs_owner_pk.encrypt(fudged_amount_secrets.to_bytes().as_slice());

        // Add the fudged output back into the reissue transaction.
        transaction.outputs.insert(out_dbc_content);

        let sig_share = genesis_node.key_manager.sign_with_child_key(
            &genesis_dbc.spend_key_index(),
            &transaction.blinded().hash(),
        )?;

        let sig = genesis_node
            .key_manager
            .public_key_set()?
            .combine_signatures(vec![sig_share.threshold_crypto()])?;

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter([(genesis_dbc.spend_key(), sig)]),
        };

        // The mint should reissue this without error because the output commitment sum matches the
        // input commitment sum.  However the recipient will be unable to spend it using the received
        // secret amount.  The only way to spend it would be receive the true amount from the sender,
        // or guess it.  And that's assuming the secret blinding_factor is correct, which it is in this
        // case, but might not be in the wild.  So the output DBC could be considered to be in a
        // semi-unspendable state.
        let reissue_share = genesis_node.reissue(
            reissue_req.clone(),
            BTreeSet::from_iter([genesis_dbc.spend_key()]),
        )?;

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(reissue_req.transaction);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        let output_dbc = &output_dbcs[0];

        // obtain decryption shares so we can call confirm_amount_matches_commitment()
        let mut sk_shares: BTreeMap<usize, SecretKeyShare> = Default::default();
        sk_shares.insert(0, outputs_owner.secret_key_share.clone());
        let decrypt_shares =
            gen_decryption_shares(&output_dbc.content.amount_secrets_cipher, &sk_shares);

        // obtain amount secrets
        let secrets = DbcHelper::decrypt_amount_secrets(&outputs_owner, &output_dbc.content)?;

        // confirm the secret amount is 2000.
        assert_eq!(secrets.amount, 1000 * 2);
        // confirm the dbc is considered valid using the mint-accessible api.
        assert!(output_dbc.confirm_valid(&key_manager).is_ok());
        // confirm the mis-match is detectable by the user who has the key to access the secrets.
        assert!(!output_dbc
            .content
            .confirm_provided_amount_matches_commitment(&secrets));
        assert!(!output_dbc
            .content
            .confirm_amount_matches_commitment(&outputs_owner.public_key_set, &decrypt_shares)?);

        // confirm that the sum of output secrets does not match the committed amount.
        assert_ne!(
            output_dbcs
                .iter()
                .map(|dbc| { DbcHelper::decrypt_amount(&outputs_owner, &dbc.content) })
                .sum::<Result<Amount, _>>()?,
            output_amount
        );

        // ----------
        // Phase 3. Attempt reissue of mis-matched DBC using provided AmountSecrets
        // ----------

        // Next: attempt reissuing the output DBC:
        //  a) with provided secret amount (in band for recipient).     (should fail)
        //  b) with true committed amount (out of band for recipient).  (should succeed)

        let input_dbc = output_dbc;
        let input_secrets = DbcHelper::decrypt_amount_secrets(&outputs_owner, &input_dbc.content)?;

        let transaction = crate::TransactionBuilder::default()
            .add_input(input_dbc.clone(), input_secrets)
            .add_output(crate::Output {
                amount: input_secrets.amount,
                owner: outputs_owner_pk,
            })
            .build()?;

        let sig_share = outputs_owner
            .secret_key_share
            .derive_child(&input_dbc.spend_key_index())
            .sign(&transaction.blinded().hash());

        let sig = outputs_owner
            .public_key_set
            .combine_signatures(vec![(outputs_owner.index, &sig_share)])?;

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter([(input_dbc.spend_key(), sig)]),
        };

        // The mint should give an error on reissue because the sum(inputs) does not equal sum(outputs)
        let result =
            genesis_node.reissue(reissue_req, BTreeSet::from_iter([input_dbc.spend_key()]));

        match result {
            Err(Error::DbcReissueRequestDoesNotBalance) => {}
            _ => panic!("Expecting Error::DbcReissueRequestDoesNotBalance"),
        }

        // ----------
        // Phase 4. Successful reissue of mis-matched DBC using true committed amount.
        // ----------

        let transaction = crate::TransactionBuilder::default()
            .add_input(input_dbc.clone(), input_secrets)
            .add_output(crate::Output {
                amount: output_amount,
                owner: outputs_owner_pk,
            })
            .build()?;

        let sig_share = outputs_owner
            .secret_key_share
            .derive_child(&input_dbc.spend_key_index())
            .sign(&transaction.blinded().hash());

        let sig = outputs_owner
            .public_key_set
            .combine_signatures(vec![(outputs_owner.index, &sig_share)])?;

        let reissue_req = ReissueRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter([(input_dbc.spend_key(), sig)]),
        };

        // The mint should reissue without error because the sum(inputs) does equal sum(outputs)
        let result =
            genesis_node.reissue(reissue_req, BTreeSet::from_iter([input_dbc.spend_key()]));
        assert!(result.is_ok());

        Ok(())
    }

    /// helper fn to generate DecryptionShares from SecretKeyShare(s) and a Ciphertext
    fn gen_decryption_shares(
        cipher: &Ciphertext,
        secret_key_shares: &BTreeMap<usize, SecretKeyShare>,
    ) -> BTreeMap<usize, DecryptionShare> {
        let mut decryption_shares: BTreeMap<usize, DecryptionShare> = Default::default();
        for (idx, sec_share) in secret_key_shares.iter() {
            let share = sec_share.decrypt_share_no_verify(cipher);
            decryption_shares.insert(*idx, share);
        }
        decryption_shares
    }
}
