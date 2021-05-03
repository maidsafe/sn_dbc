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

use std::collections::BTreeMap;

use crate::{
    Dbc, DbcContent, DbcContentHash, DbcTransaction, KeyManager, PublicKey, Result, Signature,
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

pub struct Mint {
    key_mgr: KeyManager,
    spendbook: SpendBook,
}

impl Mint {
    fn genesis(amount: u64) -> Result<(Self, Dbc)> {
        let key_mgr = KeyManager::new_genesis();

        let genesis_input = [0u8; 32];

        let content = DbcContent {
            parents: vec![genesis_input].into_iter().collect(),
            amount,
        };

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

        Ok((Self { key_mgr, spendbook }, dbc))
    }

    fn public_key(&self) -> PublicKey {
        self.key_mgr.public_key()
    }

    fn reissue(
        inputs: Vec<Dbc>,
        outputs: Vec<DbcContent>,
        transaction: DbcTransaction,
        input_ownership_proofs: BTreeMap<DbcContentHash, Signature>,
    ) -> Result<()> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_genesis() {
        let (mint, genesis_dbc) = Mint::genesis(1000).unwrap();
        assert_eq!(genesis_dbc.content.amount, 1000);

        assert!(mint
            .verify(
                &genesis_dbc.transaction.hash(),
                &genesis_dbc.transaction_sigs[&[0u8; 32]].1,
            )
            .is_ok());

        assert!(genesis_dbc.confirm_valid(&[mint.current_mint()]).is_ok())
    }

    #[quickcheck]
    fn prop_dbc_transaction_happy_path() {
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
