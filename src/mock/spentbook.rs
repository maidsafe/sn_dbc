// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::transaction::{DbcTransaction, OutputProof};
use bls_bulletproofs::PedersenGens;
use blsttc::PublicKey;
use std::collections::{BTreeMap, HashMap};

use super::GenesisMaterial;
use crate::{mock, Commitment, Error, Hash, Result, SpentProofContent, SpentProofShare};

/// This is a mock SpentBook used for our test cases. A proper implementation
/// will be distributed, persistent, and auditable.
///
/// This impl attempts to be reasonably efficient.  In particular
/// it stores only a single copy of each Tx and includes indexes:
///     tx_hash    --> Tx
///     public_key  --> tx_hash
///     public_key --> OutputProof
///
/// The public_key map eliminates a full table scan when matching
/// public keys for each input of logged Tx to public key of OutputProof in
/// already-spent Txs.
///
/// This impl does duplicate the OutputProofs in the public_key index, which
/// is not ideal and should not be done for a "real" system.
///
/// Another approach would be to map public_key --> tx_hash. This eliminates
/// the need to store duplicate OutputProof. One could lookup the Tx with
/// the desired OutputProof, and then iterate through outputs to actually find it.
///
/// See the very first commit of this file For a naive impl that uses only
/// a single map<public_key, tx>.
#[derive(Debug, Clone)]
pub struct SpentBookNode {
    pub key_manager: mock::KeyManager,

    pub transactions: HashMap<Hash, DbcTransaction>,
    pub public_keys: BTreeMap<PublicKey, Hash>,
    pub outputs: BTreeMap<PublicKey, OutputProof>,

    pub genesis: (PublicKey, Commitment), // genesis input (PublicKey, public_commitment)
}

impl From<mock::KeyManager> for SpentBookNode {
    fn from(key_manager: mock::KeyManager) -> Self {
        let genesis_material = GenesisMaterial::default();
        let public_commitment = genesis_material.revealed_tx.inputs[0]
            .revealed_commitment()
            .commit(&PedersenGens::default());

        Self {
            key_manager,
            transactions: Default::default(),
            public_keys: Default::default(),
            outputs: Default::default(),
            genesis: (genesis_material.input_public_key, public_commitment),
        }
    }
}

impl SpentBookNode {
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &DbcTransaction)> + '_ {
        self.public_keys.iter().map(move |(k, h)| {
            (
                k,
                match self.transactions.get(h) {
                    Some(tx) => tx,
                    // todo: something better.
                    None => panic!("Spentbook is in an inconsistent state"),
                },
            )
        })
    }

    pub fn is_spent(&self, public_key: &PublicKey) -> bool {
        self.public_keys.contains_key(public_key)
    }

    pub fn log_spent(
        &mut self,
        public_key: PublicKey,
        tx: DbcTransaction,
    ) -> Result<SpentProofShare> {
        self.log_spent_worker(public_key, tx, true)
    }

    // This is invalid behavior, however we provide this method for test cases
    // that need to write an invalid Tx to spentbook in order to test reissue
    // behavior.
    #[cfg(test)]
    pub fn log_spent_and_skip_tx_verification(
        &mut self,
        public_key: PublicKey,
        tx: DbcTransaction,
    ) -> Result<SpentProofShare> {
        self.log_spent_worker(public_key, tx, false)
    }

    fn log_spent_worker(
        &mut self,
        public_key: PublicKey,
        tx: DbcTransaction,
        verify_tx: bool,
    ) -> Result<SpentProofShare> {
        let tx_hash = Hash::from(tx.hash());

        // If this is the very first tx logged and genesis public_key was not
        // provided, then it becomes the genesis tx.
        let (genesis_public_key, genesis_public_commitment) = &self.genesis;

        // public_commitments are not available in spentbook for genesis transaction.
        let public_commitments_info: Vec<(PublicKey, Commitment)> =
            if public_key == *genesis_public_key {
                vec![(public_key, *genesis_public_commitment)]
            } else {
                tx.inputs
                    .iter()
                    .map(|input| {
                        // look up matching OutputProof
                        let pk = input.public_key();
                        let output_proof = self.outputs.get(&pk);
                        match output_proof {
                            Some(p) => Ok((input.public_key, p.commitment())),
                            None => Err(Error::MissingCommitmentForPubkey(pk)),
                        }
                    })
                    .collect::<Result<_>>()?
            };

        // Grab all commitments, grouped by input PublicKey
        // Needed for Tx verification.
        let tx_public_commitments: Vec<Commitment> = public_commitments_info
            .clone()
            .into_iter()
            .map(|(_, c)| c)
            .collect();

        // Grab the commitment specific to the input PublicKey
        // Needed for SpentProofShare
        let public_commitments: Commitment = public_commitments_info
            .into_iter()
            .find(|(k, _)| k == &public_key)
            .map_or(
                Err(Error::MissingCommitmentForPubkey(public_key)),
                |(_, c)| Ok(c),
            )?;

        if verify_tx {
            // do not permit invalid tx to be logged.
            tx.verify(&tx_public_commitments)?;
        }

        // Add public_key:tx_hash to public_key index.
        let existing_tx_hash = self
            .public_keys
            .entry(public_key)
            .or_insert_with(|| tx_hash);

        if *existing_tx_hash == tx_hash {
            // Add tx_hash:tx to transaction entries. (primary data store)
            let existing_tx = self.transactions.entry(tx_hash).or_insert_with(|| tx);

            // Add public_key:output_proof to public_key index.
            for output in existing_tx.outputs.iter() {
                let pk = *output.public_key();
                self.outputs.entry(pk).or_insert_with(|| output.clone());
            }

            let sp_content = SpentProofContent {
                public_key,
                transaction_hash: tx_hash,
                public_commitment: public_commitments,
            };

            let spentbook_pks = self.key_manager.public_key_set();
            let spentbook_sig_share = self.key_manager.sign(&sp_content.hash());

            Ok(SpentProofShare {
                content: sp_content,
                spentbook_pks,
                spentbook_sig_share,
            })
        } else {
            Err(crate::mock::Error::PublicKeyAlreadySpent.into())
        }
    }
}
