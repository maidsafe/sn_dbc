// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls_ringct::{
    bls_bulletproofs::PedersenGens,
    group::Curve,
    ringct::{OutputProof, RingCtTransaction},
    DecoyInput,
};
use blsttc::PublicKey;
use std::collections::{BTreeMap, HashMap};

use super::GenesisMaterial;
use crate::{
    mock,
    rand::{prelude::IteratorRandom, RngCore},
    Commitment, Hash, KeyImage, Result, SpentProofContent, SpentProofShare,
};

/// This is a mock SpentBook used for our test cases. A proper implementation
/// will be distributed, persistent, and auditable.
///
/// This impl attempts to be reasonably efficient.  In particular
/// it stores only a single copy of each Tx and includes indexes:
///     tx_hash    --> Tx
///     key_image  --> tx_hash
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
/// a single map<key_image, tx>.
#[derive(Debug, Clone)]
pub struct SpentBookNode {
    pub key_manager: mock::KeyManager,

    pub transactions: HashMap<Hash, RingCtTransaction>,
    pub key_images: BTreeMap<KeyImage, Hash>,
    pub outputs: BTreeMap<PublicKey, OutputProof>,

    pub genesis: (KeyImage, Commitment), // genesis input (keyimage, public_commitment)
}

impl From<mock::KeyManager> for SpentBookNode {
    fn from(key_manager: mock::KeyManager) -> Self {
        let genesis_material = GenesisMaterial::default();
        let public_commitment = genesis_material.ringct_material.inputs[0]
            .true_input
            .revealed_commitment()
            .commit(&PedersenGens::default())
            .to_affine();

        Self {
            key_manager,
            transactions: Default::default(),
            key_images: Default::default(),
            outputs: Default::default(),
            genesis: (genesis_material.input_key_image, public_commitment),
        }
    }
}

impl SpentBookNode {
    pub fn iter(&self) -> impl Iterator<Item = (&KeyImage, &RingCtTransaction)> + '_ {
        self.key_images.iter().map(move |(k, h)| {
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

    pub fn is_spent(&self, key_image: &KeyImage) -> bool {
        self.key_images.contains_key(key_image)
    }

    pub fn log_spent(
        &mut self,
        key_image: KeyImage,
        tx: RingCtTransaction,
    ) -> Result<SpentProofShare> {
        self.log_spent_worker(key_image, tx, true)
    }

    // This is invalid behavior, however we provide this method for test cases
    // that need to write an invalid Tx to spentbook in order to test reissue
    // behavior.
    #[cfg(test)]
    pub fn log_spent_and_skip_tx_verification(
        &mut self,
        key_image: KeyImage,
        tx: RingCtTransaction,
    ) -> Result<SpentProofShare> {
        self.log_spent_worker(key_image, tx, false)
    }

    fn log_spent_worker(
        &mut self,
        key_image: KeyImage,
        tx: RingCtTransaction,
        verify_tx: bool,
    ) -> Result<SpentProofShare> {
        let tx_hash = Hash::from(tx.hash());

        // If this is the very first tx logged and genesis key_image was not
        // provided, then it becomes the genesis tx.
        let (genesis_key_image, genesis_public_commitment) = &self.genesis;

        // public_commitments are not available in spentbook for genesis transaction.
        let public_commitments_info: Vec<(KeyImage, Vec<Commitment>)> =
            if key_image == *genesis_key_image {
                vec![(key_image, vec![*genesis_public_commitment])]
            } else {
                tx.mlsags
                    .iter()
                    .map(|mlsag| {
                        // For each public key in ring, look up matching OutputProof
                        // note: We use flat_map to avoid get.unwrap()
                        let output_proofs: Vec<&OutputProof> = mlsag
                            .public_keys()
                            .iter()
                            .flat_map(|pk| self.outputs.get(&(*pk).into()))
                            .collect();

                        if output_proofs.len() != mlsag.public_keys().len() {
                            return Err(crate::Error::from(crate::mock::Error::RingSizeMismatch(
                                mlsag.public_keys().len(),
                                output_proofs.len(),
                            )));
                        }

                        // collect commitments from OutputProofs
                        let commitments: Vec<Commitment> =
                            output_proofs.iter().map(|o| o.commitment()).collect();

                        // check our assumptions.
                        assert_eq!(commitments.len(), mlsag.public_keys().len());
                        assert_eq!(commitments.len(), mlsag.ring.len());

                        Ok((mlsag.key_image.into(), commitments))
                    })
                    .collect::<Result<_>>()?
            };

        // Grab all commitments, grouped by input mlsag
        // Needed for Tx verification.
        let tx_public_commitments: Vec<Vec<Commitment>> = public_commitments_info
            .clone()
            .into_iter()
            .map(|(_, v)| v)
            .collect();

        // Grab the commitments specific to the input KeyImage
        // Needed for SpentProofShare
        let public_commitments: Vec<Commitment> = public_commitments_info
            .into_iter()
            .flat_map(|(k, v)| if k == key_image { v } else { vec![] })
            .collect();

        if verify_tx {
            // do not permit invalid tx to be logged.
            tx.verify(&tx_public_commitments)?;
        }

        // Add key_image:tx_hash to key_image index.
        let existing_tx_hash = self.key_images.entry(key_image).or_insert_with(|| tx_hash);

        if *existing_tx_hash == tx_hash {
            // Add tx_hash:tx to transaction entries. (primary data store)
            let existing_tx = self.transactions.entry(tx_hash).or_insert_with(|| tx);

            // Add public_key:output_proof to public_key index.
            for output in existing_tx.outputs.iter() {
                let pk = PublicKey::from(*output.public_key());
                self.outputs.entry(pk).or_insert_with(|| output.clone());
            }

            let sp_content = SpentProofContent {
                key_image,
                transaction_hash: tx_hash,
                public_commitments,
            };

            let spentbook_pks = self.key_manager.public_key_set()?;
            let spentbook_sig_share = self.key_manager.sign(&sp_content.hash())?;

            Ok(SpentProofShare {
                content: sp_content,
                spentbook_pks,
                spentbook_sig_share,
            })
        } else {
            Err(crate::mock::Error::KeyImageAlreadySpent.into())
        }
    }

    // return a list of DecoyInput built from randomly
    // selected OutputProof, from set of all OutputProof in Spentbook.
    pub fn random_decoys(&self, target_num: usize, rng: &mut impl RngCore) -> Vec<DecoyInput> {
        // Get a unique list of all OutputProof
        // note: Tx are duplicated in Spentbook. We use a BTreeMap
        //       with KeyImage to dedup.
        // note: Once we refactor to avoid Tx duplication, this
        //       map can go away.
        let outputs_unique: BTreeMap<PublicKey, OutputProof> = self
            .transactions
            .values()
            .flat_map(|tx| {
                tx.outputs
                    .iter()
                    .map(|o| ((*o.public_key()).into(), o.clone()))
            })
            .collect();

        let num_choose = if outputs_unique.len() > target_num {
            target_num
        } else {
            outputs_unique.len()
        };
        outputs_unique
            .into_iter()
            .choose_multiple(rng, num_choose)
            .into_iter()
            .map(|(_, o)| DecoyInput {
                public_key: *o.public_key(),
                commitment: o.commitment(),
            })
            .collect()
    }
}
