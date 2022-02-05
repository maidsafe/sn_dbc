use blst_ringct::ringct::{OutputProof, RingCtMaterial, RingCtTransaction};
use blst_ringct::DecoyInput;
use blstrs::group::Curve;
use std::collections::BTreeMap;

use rand8::prelude::IteratorRandom;

use crate::{Commitment, Hash, KeyImage, KeyManager, Result, SimpleKeyManager, SpentProofShare};

/// This is a mock SpentBook used for our test cases. A proper implementation
/// will be distributed, persistent, and auditable.
///
/// This impl has a serious inefficiency when looking up OutputProofs by
/// PublicKey.  A scan of all spent Tx is required.  This is not a problem
/// for small tests.
///
/// A real (performant) impl would need to add an additional index/map from
/// PublicKey to Tx.  Or alternatively from PublicKey to KeyImage.  This requirement
/// may add complexity to a distributed implementation.
#[derive(Debug, Clone)]
pub struct SpentBookNodeMock {
    pub key_manager: SimpleKeyManager,
    pub transactions: BTreeMap<KeyImage, RingCtTransaction>,
    pub genesis: Option<(KeyImage, Commitment)>, // genesis input (keyimage, public_commitment)
}

impl From<SimpleKeyManager> for SpentBookNodeMock {
    fn from(key_manager: SimpleKeyManager) -> Self {
        Self {
            key_manager,
            transactions: Default::default(),
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
            genesis: Some((key_image, public_commitment)),
        }
    }
}

impl SpentBookNodeMock {
    pub fn iter(&self) -> impl Iterator<Item = (&KeyImage, &RingCtTransaction)> {
        self.transactions.iter()
    }

    pub fn is_spent(&self, key_image: &KeyImage) -> bool {
        self.transactions.contains_key(key_image)
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

        let spentbook_pks = self.key_manager.public_key_set()?;
        let spentbook_sig_share = self.key_manager.sign(&tx_hash)?;

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
                // Todo: make this cleaner and more efficient.
                //       spentbook needs to also be indexed by OutputProof PublicKey.
                //       perhaps map PublicKey --> KeyImage.
                tx.mlsags
                    .iter()
                    .map(|mlsag| {
                        let commitments: Vec<Commitment> = mlsag
                            .public_keys()
                            .iter()
                            .map(|pk| {
                                let output_proofs: Vec<&OutputProof> = self
                                    .transactions
                                    .values()
                                    .filter_map(|ringct_tx| {
                                        ringct_tx
                                            .outputs
                                            .iter()
                                            .find(|proof| proof.public_key() == pk)
                                    })
                                    .collect();

                                // note: all inputs to a tx will store the same Tx.  As such,
                                // we will can get multiple matches.  But they should/must
                                // be from the same Tx.  So we use only the first one.
                                // A better impl would store only a single Tx with multiple
                                // KeyImage pointers to it.

                                assert!(!output_proofs.is_empty());
                                output_proofs[0].commitment()
                            })
                            .collect();
                        assert_eq!(commitments.len(), mlsag.public_keys().len());
                        assert!(commitments.len() == mlsag.ring.len());
                        (mlsag.key_image.into(), commitments)
                    })
                    .collect()
            };

        // Grab the commitments specific to the spent KeyImage
        let tx_public_commitments: Vec<Vec<Commitment>> = public_commitments_info
            .clone()
            .into_iter()
            .map(|(_, v)| v)
            .collect();

        let public_commitments: Vec<Commitment> = public_commitments_info
            .into_iter()
            .flat_map(|(k, v)| if k == key_image { v } else { vec![] })
            .collect();

        if verify_tx {
            // do not permit invalid tx to be logged.
            tx.verify(&tx_public_commitments)?;
        }

        let existing_tx = self
            .transactions
            .entry(key_image.clone())
            .or_insert_with(|| tx.clone());
        if existing_tx.hash() == tx.hash() {
            Ok(SpentProofShare {
                key_image,
                spentbook_pks,
                spentbook_sig_share,
                public_commitments,
            })
        } else {
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
        mut rng: impl rand8::RngCore,
    ) -> Vec<DecoyInput> {
        // Get a unique list of all OutputProof
        // note: Tx are duplicated in Spentbook. We use a BTreeMap
        //       with KeyImage to dedup.
        // note: Once we refactor to avoid Tx duplication, this
        //       map can go away.
        let outputs_unique: BTreeMap<KeyImage, OutputProof> = self
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
            .choose_multiple(&mut rng, num_choose)
            .into_iter()
            .map(|(_, o)| DecoyInput {
                public_key: *o.public_key(),
                commitment: o.commitment(),
            })
            .collect()
    }
}
