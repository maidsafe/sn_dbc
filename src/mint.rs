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

use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier};
use std::collections::BTreeMap;

use crate::{
    threshold_crypto, Dbc, DbcContent, DbcContentHash, DbcTransaction, Result, ThresholdPublicKey,
    ThresholdSignature, VecSet,
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

pub struct ChainNode {
    mint_key: ThresholdPublicKey,
    old_mint_sig: ThresholdSignature,
}

struct MintNode {
    chain: Vec<ChainNode>,
    key_cache: VecSet<ThresholdPublicKey>,
    keypair: Keypair,
    spendbook: SpendBook,
}

enum MintEvent {
    Genesis {},
    Churn {},
    Reissue {
        inputs: Vec<Dbc>,
        outputs: Vec<DbcContent>,
        transaction: DbcTransaction,
        input_ownership_proofs: BTreeMap<DbcContentHash, Signature>,
    },
}

impl MintNode {
    fn new(chain: Vec<ChainNode>, spendbook: SpendBook) -> Self {
        let key_cache = chain.iter().map(|node| node.mint_key.clone()).collect();
        Self {
            keypair: threshold_crypto::ed25519_keypair(),
            chain,
            key_cache,
            spendbook,
        }
    }

    fn genesis(amount: u64) -> Result<(Self, Dbc)> {
        let keypair = threshold_crypto::ed25519_keypair();
        let thresh_key = ThresholdPublicKey::new(1, vec![keypair.public].into_iter().collect())?;

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

        let mut thresh_sig = ThresholdSignature::new();
        thresh_sig.add_share(keypair.public, keypair.sign(&transaction.hash()));

        let dbc = Dbc {
            content,
            transaction,
            transaction_sigs: vec![(genesis_input, (thresh_key.clone(), thresh_sig))]
                .into_iter()
                .collect(),
        };

        let mut thresh_key_sig = ThresholdSignature::new();
        thresh_key_sig.add_share(keypair.public, keypair.sign(&thresh_key.hash()));

        let mint = Self {
            keypair,
            chain: vec![ChainNode {
                mint_key: thresh_key.clone(),
                old_mint_sig: thresh_key_sig,
            }],
            key_cache: vec![thresh_key].into_iter().collect(),
            spendbook,
        };

        Ok((mint, dbc))
    }

    fn current_mint(&self) -> &ThresholdPublicKey {
        // TODO: remove this unwrap by storing current mint seperately form chain
        &self.chain.iter().rev().next().unwrap().mint_key
    }

    fn public_key(&self) -> PublicKey {
        self.keypair.public
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
        let (mint, genesis_dbc) = MintNode::genesis(1000).unwrap();
        assert_eq!(genesis_dbc.content.amount, 1000);

        assert!(mint
            .current_mint()
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
