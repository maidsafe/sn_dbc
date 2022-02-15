// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blst_ringct::ringct::{OutputProof, RingCtMaterial, RingCtTransaction};
use blst_ringct::DecoyInput;
use blstrs::group::Curve;
use std::collections::{BTreeMap, HashMap};

use rand8::prelude::IteratorRandom;

use crate::{
    Commitment, Hash, KeyImage, KeyManager, PublicKeyBlstMappable, Result, SimpleKeyManager,
    SpentProofContent, SpentProofShare,
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
pub struct SpentBookNodeMock {
    pub key_manager: SimpleKeyManager,

    pub transactions: HashMap<Hash, RingCtTransaction>,
    pub key_images: BTreeMap<KeyImage, Hash>,
    pub outputs: BTreeMap<PublicKeyBlstMappable, OutputProof>,

    pub genesis: Option<(KeyImage, Commitment)>, // genesis input (keyimage, public_commitment)
}

impl From<SimpleKeyManager> for SpentBookNodeMock {
    fn from(key_manager: SimpleKeyManager) -> Self {
        Self {
            key_manager,
            transactions: Default::default(),
            key_images: Default::default(),
            outputs: Default::default(),
            genesis: None,
        }
    }
}

impl From<(SimpleKeyManager, KeyImage, Commitment)> for SpentBookNodeMock {
    fn from(params: (SimpleKeyManager, KeyImage, Commitment)) -> Self {
        let (key_manager, key_image, public_commitment) = params;

        Self {
            key_manager,
            transactions: Default::default(),
            key_images: Default::default(),
            outputs: Default::default(),
            genesis: Some((key_image, public_commitment)),
        }
    }
}

impl SpentBookNodeMock {
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
        let (genesis_key_image, genesis_public_commitment) = match &self.genesis {
            Some((k, pc)) => (k, pc),
            None => panic!("Genesis key_image and public commitments unavailable"),
        };

        // public_commitments are not available in spentbook for genesis transaction.
        let public_commitments_info: Vec<(KeyImage, Vec<Commitment>)> =
            if key_image == *genesis_key_image {
                vec![(key_image.clone(), vec![*genesis_public_commitment])]
            } else {
                tx.mlsags
                    .iter()
                    .map(|mlsag| {
                        // For each public key in ring, look up matching OutputProof
                        // note: We use flat_map to avoid get.unwrap()
                        let output_proofs: Vec<&OutputProof> = mlsag
                            .public_keys()
                            .iter()
                            .flat_map(|pk| {
                                let pkbm: PublicKeyBlstMappable = (*pk).into();
                                self.outputs.get(&pkbm)
                            })
                            .collect();

                        // collect commitments from OutputProofs
                        let commitments: Vec<Commitment> =
                            output_proofs.iter().map(|o| o.commitment()).collect();

                        // check our assumptions.
                        assert_eq!(commitments.len(), mlsag.public_keys().len());
                        assert!(commitments.len() == mlsag.ring.len());

                        (mlsag.key_image.into(), commitments)
                    })
                    .collect()
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
        let existing_tx_hash = self
            .key_images
            .entry(key_image.clone())
            .or_insert_with(|| tx_hash);

        if *existing_tx_hash == tx_hash {
            // Add tx_hash:tx to transaction entries. (primary data store)
            let existing_tx = self.transactions.entry(tx_hash).or_insert_with(|| tx);

            // Add public_key:output_proof to public_key index.
            for output in existing_tx.outputs.iter() {
                let pkbm: PublicKeyBlstMappable = (*output.public_key()).into();
                self.outputs.entry(pkbm).or_insert_with(|| output.clone());
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
            // fixme: return an error.  can wait until we refactor into a Mock feature flag.
            panic!("Attempt to Double Spend")
        }
    }

    pub fn set_genesis(&mut self, material: &RingCtMaterial) {
        let key_image = KeyImage::from(material.inputs[0].true_input.key_image().to_affine());
        let public_commitment = material.inputs[0]
            .true_input
            .revealed_commitment
            .commit(&Default::default())
            .to_affine();

        self.genesis = Some((key_image, public_commitment));
    }

    // return a list of DecoyInput built from randomly
    // selected OutputProof, from set of all OutputProof in Spentbook.
    pub fn random_decoys(
        &self,
        target_num: usize,
        rng: &mut impl rand8::RngCore,
    ) -> Vec<DecoyInput> {
        // Get a unique list of all OutputProof
        // note: Tx are duplicated in Spentbook. We use a BTreeMap
        //       with KeyImage to dedup.
        // note: Once we refactor to avoid Tx duplication, this
        //       map can go away.
        let outputs_unique: BTreeMap<PublicKeyBlstMappable, OutputProof> = self
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
