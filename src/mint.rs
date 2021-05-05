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

use std::collections::{BTreeMap, HashSet};

use crate::{
    Dbc, DbcContent, DbcContentHash, DbcTransaction, KeyCache, KeyManager, PublicKey, Result,
    Signature,
};

#[derive(Default)]
struct SpendBook {
    transactions: BTreeMap<DbcContentHash, DbcTransaction>,
}

impl SpendBook {
    fn log(&mut self, dbc_hash: DbcContentHash, transaction: DbcTransaction) {
        self.transactions.insert(dbc_hash, transaction);
    }
}

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcContent>,
}

impl MintRequest {
    pub fn to_transaction(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: self.inputs.iter().map(|i| i.name()).collect(),
            outputs: self.outputs.iter().map(|i| i.hash()).collect(),
        }
    }
}

pub struct Mint {
    pub(crate) key_mgr: KeyManager,
    spendbook: SpendBook,
}

impl Mint {
    pub fn genesis(amount: u64) -> (Self, Dbc) {
        let key_mgr = KeyManager::new_genesis();

        let genesis_input = [0u8; 32];

        let parents = vec![genesis_input].into_iter().collect();
        let content = DbcContent::new(parents, amount, 0);

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

    pub fn reissue(&self, mint_request: MintRequest) -> Result<(DbcTransaction, Signature)> {
        let transaction = mint_request.to_transaction();
        let sig = self.key_mgr.sign(&transaction.hash());
        Ok((transaction, sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use quickcheck_macros::quickcheck;

    use crate::tests::{TinyInt, TinyVec};

    #[quickcheck]
    fn prop_genesis() {
        let (mint, genesis_dbc) = Mint::genesis(1000);
        assert_eq!(genesis_dbc.content.amount, 1000);
        assert!(genesis_dbc.confirm_valid(&mint.key_cache()).is_ok());
    }

    #[quickcheck]
    fn prop_dbc_transaction_happy_path() {
        todo!()
    }

    #[quickcheck]
    fn prop_dbc_ensure_outputs_are_numbered_uniquely() {
        todo!()
    }

    #[quickcheck]
    fn prop_in_progress_transaction_can_be_continued_across_churn() {
        todo!()
    }

    #[quickcheck]
    fn prop_reject_invalid_prefix() {
        todo!();
    }

    #[quickcheck]
    fn prop_respond_with_in_progress_transaction_if_input_spent() {
        todo!();
    }

    #[quickcheck]
    fn prop_output_parents_must_match_inputs() {
        todo!();
    }

    #[quickcheck]
    fn prop_output_amount_does_not_exceed_input() {
        todo!();
    }

    #[quickcheck]
    fn prop_input_ownership_proofs_are_checked() {
        todo!();
    }

    #[quickcheck]
    fn prop_invalid_input_dbcs() {
        todo!();
    }
}
