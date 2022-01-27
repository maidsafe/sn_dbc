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
    Amount, AmountSecrets, DbcContent, DerivedOwner, Error, Hash, KeyImage, KeyManager,
    NodeSignature, OwnerBase, PublicKeySet, Result, SpentProof, SpentProofShare,
};
use blst_ringct::mlsag::{MlsagMaterial, TrueInput};
use blst_ringct::ringct::{RingCtMaterial, RingCtTransaction};
use blst_ringct::{Output, RevealedCommitment};
use blstrs::group::prime::PrimeCurveAffine;
use blstrs::group::Curve;
use blstrs::{G1Affine, Scalar};
use blsttc::{poly::Poly, SecretKeySet};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::iter::FromIterator;

// note: Inputs are not guaranteed to use unique KeyImage, so we cannot
//       use it as the map key.  Instead we key by input index which
//       is the position of the MlsagSignature in RingCtTransaction.mlsags.
//       We may want to revisit this.
pub type MintNodeSignature = (PublicKeySet, NodeSignature);
pub type MintNodeSignatures = BTreeMap<KeyImage, MintNodeSignature>;

pub fn genesis_dbc_input(share: &GenesisDbcShare) -> Result<KeyImage> {
    Ok(share
        .ringct_material
        .inputs
        .get(0)
        .ok_or(Error::TransactionMustHaveAnInput)?
        .true_input
        .key_image()
        .to_affine()
        .to_compressed())
}

#[derive(Clone)]
pub struct GenesisDbcShare {
    pub ringct_material: RingCtMaterial,
    pub dbc_content: DbcContent,
    pub amount_secrets: AmountSecrets,
    pub derived_owner: DerivedOwner,
    pub transaction: RingCtTransaction,
    pub revealed_commitments: Vec<RevealedCommitment>,
    pub public_key_set: PublicKeySet,
    pub transaction_sig: NodeSignature,
    pub secret_key: Scalar,
}

// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
#[derive(Debug, Clone)]
pub struct ReissueRequest {
    pub transaction: RingCtTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
}

// #[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
#[derive(Debug, Clone)]
pub struct ReissueShare {
    pub transaction: RingCtTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
    pub mint_node_signatures: MintNodeSignatures,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MintNode<K>
where
    K: KeyManager,
{
    pub key_manager: K,
}

impl<K: KeyManager> MintNode<K> {
    pub fn new(key_manager: K) -> Self {
        Self { key_manager }
    }

    pub fn issue_genesis_dbc(
        &mut self,
        amount: Amount,
        mut rng: impl RngCore + rand_core::CryptoRng,
    ) -> Result<GenesisDbcShare> {
        // Make a secret key for the input to Genesis Tx.
        let input_poly = Poly::zero();
        let input_secret_key_set = SecretKeySet::from(input_poly);
        let input_secret_key =
            Scalar::from_bytes_be(&input_secret_key_set.secret_key().to_bytes()).unwrap();

        // Make a secret key for the output of Genesis Tx. (The Genesis Dbc)
        // temporary: we bypass KeyManager and create a deterministic
        // secret key, used by all MintNodes.
        let poly = Poly::one();
        let secret_key_set = SecretKeySet::from(poly);
        let derived_owner =
            DerivedOwner::from_owner_base(OwnerBase::from(secret_key_set.clone()), &mut rng);
        let secret_key_set_derived = secret_key_set.derive_child(&derived_owner.derivation_index);
        let public_key_set = secret_key_set_derived.public_keys();

        // create sk and derive pk.
        let secret_key =
            Scalar::from_bytes_be(&secret_key_set_derived.secret_key().to_bytes()).unwrap();
        let public_key = (G1Affine::generator() * secret_key).to_affine();

        let true_input = TrueInput {
            secret_key: input_secret_key,
            revealed_commitment: RevealedCommitment {
                value: amount,
                blinding: 5.into(), // todo: choose Genesis blinding factor.
            },
        };

        // note: no decoy inputs because no other DBCs exist prior to genesis DBC.
        let decoy_inputs = vec![];

        let ringct_material = RingCtMaterial {
            inputs: vec![MlsagMaterial::new(true_input, decoy_inputs, &mut rng)],
            outputs: vec![Output { public_key, amount }],
        };

        // Here we sign as the input DBC owner.
        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");

        let amount_secrets = AmountSecrets::from(revealed_commitments[0]);
        let dbc_content = DbcContent::from((
            derived_owner.owner_base.clone(),
            derived_owner.derivation_index,
            amount_secrets.clone(),
        ));

        // Here we sign as the mint.
        let transaction_sig = self
            .key_manager
            .sign(&Hash::from(transaction.hash()))
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(GenesisDbcShare {
            ringct_material,
            dbc_content,
            amount_secrets,
            public_key_set,
            derived_owner,
            transaction,
            revealed_commitments, // output commitments
            transaction_sig,
            secret_key,
        })
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    // This API will be called multiple times, once per input dbc, per section.
    // The key_image param comes from the true input, but cannot be linked by mint to true input.
    pub fn spend(_key_image: KeyImage, _transaction: RingCtTransaction) -> Result<SpentProofShare> {
        unimplemented!()

        // note: client is writing spentbook, so needs to write:
        //  a: key_image --> RingCtTransaction,
        //  b: public_key --> key_image   (for lookup by public key)

        // note: do decoys have to be from same section?  (for drusu to think about)

        // 1. lookup key image in spentbook, return error if not existing.
        //    (client did not write spentbook entry.).

        // 2. verify that tx in spentbook matches tx received from client.

        // 3. find mlsag in transaction that corresponds to the key_image, else return error.

        // 4. for each input in mlsag
        //       lookup tx in spentbook whose output is equal to this input.
        //         (full table scan, ouch, or multiple indexes into spentbook (key_image + public_key))
        //       obtain the public commitment from the output.
        //       verify commitment from input matches spentbook output commitment.

        // 5. verify transaction itself.   tx.verify()  (RingCtTransaction)

        // 6. create SpentProofShare and return it.
    }

    pub fn reissue(&mut self, reissue_req: ReissueRequest) -> Result<ReissueShare> {
        let ReissueRequest {
            transaction,
            spent_proofs,
        } = reissue_req;

        if transaction.mlsags.len() != spent_proofs.len() {
            return Err(Error::SpentProofInputMismatch);
        }

        // Verify that each KeyImage is unique in this tx.
        let keyimage_unique: BTreeSet<KeyImage> = transaction
            .mlsags
            .iter()
            .map(|m| m.key_image.to_compressed())
            .collect();
        if keyimage_unique.len() != transaction.mlsags.len() {
            return Err(Error::KeyImageNotUniqueAcrossInputs);
        }

        // Verify that each pubkey is unique in this transaction.
        let pubkey_unique: BTreeSet<KeyImage> = transaction
            .outputs
            .iter()
            .map(|o| o.public_key().to_compressed())
            .collect();
        if pubkey_unique.len() != transaction.outputs.len() {
            return Err(Error::PublicKeyNotUniqueAcrossOutputs);
        }

        // We must get the spent_proofs into the same order as mlsags
        // so that resulting public_commitments will be in the right order.
        // Note: we could use itertools crate to sort in one loop.
        let mut spent_proofs_found: Vec<(usize, SpentProof)> = spent_proofs
            .into_iter()
            .filter_map(|s| {
                transaction
                    .mlsags
                    .iter()
                    .position(|m| m.key_image.to_compressed() == s.key_image)
                    .map(|idx| (idx, s))
            })
            .collect();

        // note: since we already verified key_image is unique amongst
        // mlsags, this check ensures it is also unique amongst SpentProofs
        // as well as matching mlsag key images.
        if spent_proofs_found.len() != transaction.mlsags.len() {
            return Err(Error::SpentProofKeyImageMismatch);
        }
        spent_proofs_found.sort_by_key(|s| s.0);
        let spent_proofs_sorted: Vec<SpentProof> =
            spent_proofs_found.into_iter().map(|s| s.1).collect();

        let public_commitments: Vec<Vec<G1Affine>> = spent_proofs_sorted
            .iter()
            .map(|s| s.public_commitments.clone())
            .collect();

        transaction.verify(&public_commitments)?;

        let transaction_hash = Hash::from(transaction.hash());

        // Validate that each input has not yet been spent.
        // iterate over mlsags.  each has key_image()
        for proof in spent_proofs_sorted.iter() {
            // proof.validate(transaction_hash, self.key_manager())?;

            // fixme: this does not validate that signing key belongs to spentbook.
            proof.validate_unsafe(transaction_hash)?;
        }

        let transaction_sigs = self.sign_transaction(&transaction)?;

        let reissue_share = ReissueShare {
            transaction,
            spent_proofs: BTreeSet::from_iter(spent_proofs_sorted),
            mint_node_signatures: transaction_sigs,
        };

        Ok(reissue_share)
    }

    fn sign_transaction(&self, transaction: &RingCtTransaction) -> Result<MintNodeSignatures> {
        let sig = self
            .key_manager
            .sign(&Hash::from(transaction.hash()))
            .map_err(|e| Error::Signing(e.to_string()))?;

        let pks = self
            .key_manager
            .public_key_set()
            .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(transaction
            .mlsags
            .iter()
            .map(|m| (m.key_image.to_compressed(), (pks.clone(), sig.clone())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst_ringct::DecoyInput;
    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;
    use rand_core::SeedableRng as SeedableRngCore;
    use std::collections::BTreeSet;
    use std::convert::TryFrom;

    use crate::{
        tests::{SpentBookMock, TinyInt, TinyVec},
        AmountSecrets, BlsHelper, Dbc, DbcBuilder, ReissueRequestBuilder, SimpleKeyManager,
        SimpleSigner,
    };

    #[test]
    fn issue_genesis() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let mint_owner = crate::bls_dkg_id(&mut rng);
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(mint_owner.clone()),
            mint_owner.public_key_set.public_key(),
        );
        let mut mint_node = MintNode::new(key_manager);
        let genesis = mint_node.issue_genesis_dbc(1000, &mut rng8).unwrap();

        let spentbook_owner = crate::bls_dkg_id(&mut rng);
        let spentbook_key_manager = SimpleKeyManager::new(
            SimpleSigner::from(spentbook_owner),
            genesis.public_key_set.public_key(),
        );
        let input_key_image = genesis_dbc_input(&genesis)?;
        let mut spentbook = SpentBookMock::from((spentbook_key_manager, input_key_image));

        let mint_sig = mint_owner
            .public_key_set
            .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])?;

        let spent_proof_share =
            spentbook.log_spent(input_key_image, genesis.transaction.clone())?;

        let spentbook_sig =
            spent_proof_share
                .spentbook_pks
                .combine_signatures(vec![spent_proof_share
                    .spentbook_sig_share
                    .threshold_crypto()])?;

        let tx_hash = Hash::from(genesis.transaction.hash());
        assert!(spent_proof_share
            .spentbook_pks
            .public_key()
            .verify(&spentbook_sig, &tx_hash));

        let spent_proofs = BTreeSet::from_iter(vec![SpentProof {
            key_image: spent_proof_share.key_image,
            spentbook_pub_key: spent_proof_share.spentbook_pks.public_key(),
            spentbook_sig,
            public_commitments: spent_proof_share.public_commitments,
        }]);

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            transaction: genesis.transaction.clone(),
            transaction_sigs: BTreeMap::from_iter([(
                input_key_image,
                (mint_owner.public_key_set.public_key(), mint_sig),
            )]),
            spent_proofs,
        };

        let validation = genesis_dbc.confirm_valid(
            &genesis.derived_owner.base_secret_key()?,
            &mint_node.key_manager,
            &spentbook.key_manager,
        );
        assert!(validation.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));
        let n_outputs = output_amounts.len();
        let output_amount = output_amounts.iter().sum();

        let mint_owner = crate::bls_dkg_id(&mut rng);
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(mint_owner.clone()),
            mint_owner.public_key_set.public_key(),
        );
        let mut mint_node = MintNode::new(key_manager);
        let genesis = mint_node
            .issue_genesis_dbc(output_amount, &mut rng8)
            .unwrap();

        let spentbook_owner = crate::bls_dkg_id(&mut rng);
        let spentbook_key_manager = SimpleKeyManager::new(
            SimpleSigner::from(spentbook_owner),
            genesis.public_key_set.public_key(),
        );
        let input_key_image = genesis_dbc_input(&genesis)?;
        let mut spentbook = SpentBookMock::from((spentbook_key_manager, input_key_image));

        let _genesis_spent_proof_share =
            spentbook.log_spent(input_key_image, genesis.transaction.clone())?;

        let owners: Vec<DerivedOwner> = (0..output_amounts.len())
            .map(|_| {
                DerivedOwner::from_owner_base(
                    OwnerBase::from_random_secret_key(&mut rng),
                    &mut rng8,
                )
            })
            .collect();

        let (reissue_tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(
                    genesis.secret_key,
                    AmountSecrets::from(genesis.revealed_commitments[0]),
                    vec![], // genesis is only input, so no decoys.
                    &mut rng8,
                )
                .add_outputs(output_amounts.iter().enumerate().map(|(idx, a)| {
                    (
                        crate::Output {
                            amount: *a,
                            public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                                &owners[idx].derive_public_key(),
                            ),
                        },
                        owners[idx].clone(),
                    )
                }))
                .build(&mut rng8)?;

        let genesis_key_image = reissue_tx.mlsags[0].key_image.to_compressed();
        let spent_proof_share = spentbook.log_spent(genesis_key_image, reissue_tx.clone())?;

        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(0, spent_proof_share)
            .build()?;

        let reissue_share = match mint_node.reissue(rr) {
            Ok(rs) => {
                // Verify that at least one output was present.
                assert_ne!(n_outputs, 0);
                rs
            }
            Err(Error::RingCt(
                blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
            )) => {
                // Verify that no outputs were present and we got correct validation error.
                assert_eq!(n_outputs, 0);
                return Ok(());
            }
            Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {
                // Verify that no outputs were present and we got correct validation error.
                assert_eq!(n_outputs, 0);
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        for (dbc, derived_owner, amount_secrets) in output_dbcs.iter() {
            let dbc_amount = amount_secrets.amount();
            assert!(output_amounts.iter().any(|a| *a == dbc_amount));
            assert!(dbc
                .confirm_valid(
                    &derived_owner.base_secret_key().unwrap(),
                    mint_node.key_manager(),
                    &spentbook.key_manager
                )
                .is_ok());
        }

        assert_eq!(
            output_dbcs
                .iter()
                .map(
                    |(dbc, derived_owner, _amount_secrets)| AmountSecrets::try_from((
                        &derived_owner.derive_secret_key().unwrap(),
                        &dbc.content.amount_secrets_cipher
                    ))
                    .unwrap()
                    .amount()
                )
                .sum::<Amount>(),
            output_amount
        );

        Ok(())
    }

    #[quickcheck]
    fn prop_dbc_transaction_many_to_many(
        // the amount of each input transaction
        input_amounts: TinyVec<TinyInt>,
        // The amount for each transaction output
        output_amounts: TinyVec<TinyInt>,
        // Include an invalid SpentProofs for the following inputs
        invalid_spent_proofs: TinyVec<TinyInt>,
        // The number of decoy inputs
        num_decoy_inputs: TinyInt,
    ) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let input_amounts =
            Vec::from_iter(input_amounts.into_iter().map(TinyInt::coerce::<Amount>));

        let output_amounts =
            Vec::from_iter(output_amounts.into_iter().map(TinyInt::coerce::<Amount>));

        let invalid_spent_proofs = BTreeSet::from_iter(
            invalid_spent_proofs
                .into_iter()
                .map(TinyInt::coerce::<usize>),
        );

        let genesis_amount: Amount = input_amounts.iter().sum();

        // We apply mod 2 because there is only one available decoy (genesis pubkey)
        // in the spentbook.  To test decoys further, we would need to devise a test
        // something like:  genesis --> 100 outputs --> x outputs --> y outputs.
        let num_decoy_inputs: usize = num_decoy_inputs.coerce::<usize>() % 2;

        let mint_owner = crate::bls_dkg_id(&mut rng);
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(mint_owner.clone()),
            mint_owner.public_key_set.public_key(),
        );
        let mut mint_node = MintNode::new(key_manager);
        let genesis = mint_node
            .issue_genesis_dbc(genesis_amount, &mut rng8)
            .unwrap();

        let spentbook_owner = crate::bls_dkg_id(&mut rng);
        let spentbook_key_manager = SimpleKeyManager::new(
            SimpleSigner::from(spentbook_owner),
            genesis.public_key_set.public_key(),
        );
        let input_key_image = genesis_dbc_input(&genesis)?;
        let mut spentbook = SpentBookMock::from((spentbook_key_manager, input_key_image));

        let _genesis_spent_proof_share =
            spentbook.log_spent(input_key_image, genesis.transaction.clone())?;

        let (reissue_tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(
                    genesis.secret_key,
                    AmountSecrets::from(genesis.revealed_commitments[0]),
                    vec![], // genesis is input, no decoys possible.
                    &mut rng8,
                )
                .add_outputs(input_amounts.iter().copied().map(|amount| {
                    let derived_owner = DerivedOwner::from_owner_base(
                        OwnerBase::from_random_secret_key(&mut rng),
                        &mut rng8,
                    );
                    (
                        crate::Output {
                            amount,
                            public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                                &derived_owner.derive_public_key(),
                            ),
                        },
                        derived_owner,
                    )
                }))
                .build(&mut rng8)?;

        let genesis_key_image = reissue_tx.mlsags[0].key_image.to_compressed();
        let spent_proof_share = spentbook.log_spent(genesis_key_image, reissue_tx.clone())?;

        let rr1 = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(0, spent_proof_share)
            .build()?;

        let reissue_share = match mint_node.reissue(rr1) {
            Ok(rs) => {
                // Verify that at least one input (output in this tx) was present.
                assert!(!input_amounts.is_empty());
                rs
            }
            Err(Error::RingCt(
                blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
            )) => {
                // Verify that no outputs were present and we got correct validation error.
                assert!(input_amounts.is_empty());
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let input_dbcs = dbc_builder.build()?;

        let input_dbc_secrets = input_dbcs
            .iter()
            .map(|(_dbc, derived_owner, amount_secrets)| {
                let secret_key_blstrs =
                    BlsHelper::blsttc_to_blstrs_sk(derived_owner.derive_secret_key().unwrap());
                let public_key_blstrs =
                    BlsHelper::blsttc_to_blstrs_pubkey(&derived_owner.derive_public_key());

                // note: decoy inputs can be created from OutputProof + dbc owner's pubkey.
                let decoy_inputs =
                    gen_decoy_inputs(&spentbook, &public_key_blstrs, num_decoy_inputs);
                Ok((secret_key_blstrs, amount_secrets.clone(), decoy_inputs))
            })
            .collect::<Result<Vec<(Scalar, crate::AmountSecrets, Vec<DecoyInput>)>>>()?;

        let owners: Vec<DerivedOwner> = (0..=output_amounts.len())
            .map(|_| {
                DerivedOwner::from_owner_base(
                    OwnerBase::from_random_secret_key(&mut rng),
                    &mut rng8,
                )
            })
            .collect();

        let outputs: Vec<(Output, DerivedOwner)> = output_amounts
            .iter()
            .zip(owners)
            .map(|(amount, derived_owner)| {
                (
                    crate::Output {
                        amount: *amount,
                        public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                            &derived_owner.derive_public_key(),
                        ),
                    },
                    derived_owner,
                )
            })
            .collect();

        let (reissue_tx2, revealed_commitments, material, output_owners) =
            crate::TransactionBuilder::default()
                .add_inputs_by_secrets(input_dbc_secrets, &mut rng8)
                .add_outputs(outputs.clone())
                .build(&mut rng8)?;

        let dbc_output_amounts: Vec<Amount> = outputs.iter().map(|(o, _)| o.amount).collect();
        let output_total_amount: Amount = dbc_output_amounts.iter().sum();

        let mut rr2_builder = ReissueRequestBuilder::new(reissue_tx2.clone());

        assert_eq!(input_dbcs.len(), reissue_tx2.mlsags.len());

        for (i, (in_mlsag, _in_material)) in reissue_tx2
            .mlsags
            .iter()
            .zip(material.inputs.iter())
            .enumerate()
        {
            let is_invalid_spent_proof = invalid_spent_proofs.contains(&i);

            let spent_proof_share = match i % 2 {
                0 if is_invalid_spent_proof => {
                    // drop this spent proof
                    continue;
                }
                1 if is_invalid_spent_proof => {
                    let spent_proof_share = spentbook
                        .log_spent(in_mlsag.key_image.to_compressed(), reissue_tx2.clone())?;
                    SpentProofShare {
                        key_image: spent_proof_share.key_image,
                        public_commitments: spent_proof_share.public_commitments,
                        spentbook_pks: spent_proof_share.spentbook_pks,
                        spentbook_sig_share: NodeSignature::new(
                            0,
                            SecretKeySet::random(1, &mut rng)
                                .secret_key_share(1)
                                .sign(&[0u8; 32]),
                        ),
                    }
                }
                _ => {
                    spentbook.log_spent(in_mlsag.key_image.to_compressed(), reissue_tx2.clone())?
                }
            };

            rr2_builder = rr2_builder.add_spent_proof_share(i, spent_proof_share);
        }

        let rr2 = rr2_builder.build()?;
        let many_to_many_result = mint_node.reissue(rr2);

        match many_to_many_result {
            Ok(rs) => {
                assert_eq!(genesis_amount, output_total_amount);
                assert!(invalid_spent_proofs
                    .iter()
                    .all(|i| i >= &reissue_tx2.mlsags.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts.clone()),
                    BTreeSet::from_iter(output_amounts)
                );

                // Aggregate ReissueShare to build output DBCs
                let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
                dbc_builder = dbc_builder.add_reissue_share(rs);
                let output_dbcs = dbc_builder.build()?;

                for (dbc, derived_owner, _amount_secrets) in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.confirm_valid(
                        &derived_owner.base_secret_key()?,
                        &mint_node.key_manager,
                        &spentbook.key_manager,
                    );
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs
                        .iter()
                        .enumerate()
                        .map(|(idx, _dbc)| { dbc_output_amounts[idx] })
                        .sum::<Amount>(),
                    output_total_amount
                );
            }
            Err(Error::SpentProofInputMismatch) => {
                assert!(!invalid_spent_proofs.is_empty());
            }
            Err(Error::RingCt(
                blst_ringct::Error::InputPseudoCommitmentsDoNotSumToOutputCommitments,
            )) => {
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
            Err(Error::RingCt(blst_ringct::Error::InvalidHiddenCommitmentInRing)) => {
                assert!(!invalid_spent_proofs.is_empty());
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(input_amounts.len(), 0);
            }
            Err(Error::FailedSignature) => {
                assert!(!invalid_spent_proofs.is_empty());
            }
            Err(Error::InvalidSpentProofSignature(key)) => {
                let idx = reissue_tx2
                    .mlsags
                    .iter()
                    .position(|i| i.key_image.to_compressed() == key)
                    .unwrap();
                assert!(invalid_spent_proofs.contains(&idx));
            }
            err => panic!("Unexpected reissue err {:#?}", err),
        }

        Ok(())
    }

    fn gen_decoy_inputs(
        spentbook: &SpentBookMock,
        pubkey: &G1Affine,
        num: usize,
    ) -> Vec<DecoyInput> {
        let mut decoys: Vec<DecoyInput> = Default::default();

        for (_key_image, tx) in spentbook.iter() {
            for op in tx.outputs.iter() {
                if op.public_key() != pubkey && decoys.len() < num {
                    decoys.push(DecoyInput {
                        public_key: *op.public_key(),
                        commitment: op.commitment(),
                    })
                }
            }
        }
        if decoys.len() != num {
            panic!("Not enough decoys found in spentbook");
        }
        decoys
    }

    /*
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
    */
    /*
        #[test]
        fn test_inputs_are_validated() -> Result<(), Error> {
            let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
            let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

            let genesis_owner = crate::bls_dkg_id(&mut rng);
            let key_manager = SimpleKeyManager::new(
                SimpleSigner::from(genesis_owner.clone()),
                genesis_owner.public_key_set.public_key(),
            );
            let mut genesis_node = MintNode::new(key_manager);

            let input_owner = crate::bls_dkg_id(&mut rng);
            let owner_pubkey =
                BlsHelper::blsttc_to_blstrs_pubkey(&input_owner.public_key_set.public_key());

            let output = Output {
                public_key: owner_pubkey,
                amount: 100,
            };
            let (_transaction, revealed_commitments, _material) = crate::TransactionBuilder::default()
                .add_output(output)
                .build(&mut rng8)?;
            let amount_secrets = AmountSecrets::from(revealed_commitments[0]);
            let secret_key = Scalar::default(); // fixme
            let decoy_inputs = vec![]; // genesis is only available input, so no decoys.

            let (fraud_tx, ..) = crate::TransactionBuilder::default()
                .add_input_by_secrets(secret_key, amount_secrets, decoy_inputs, &mut rng8)
                .add_output(Output {
                    public_key: owner_pubkey,
                    amount: 100,
                })
                .build(&mut rng8)?;

            let fraud_rr = ReissueRequestBuilder::new(fraud_tx).build()?;

            let fraudulant_reissue_result = genesis_node.reissue(fraud_rr);

            // fixme: more/better assertions.
            assert!(fraudulant_reissue_result.is_err());

            Ok(())
        }
    */
    /*

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
                let genesis_owner = crate::bls_dkg_id(&mut rng);
                let genesis_key = genesis_owner.public_key_set.public_key();

                let key_manager = SimpleKeyManager::new(
                    SimpleSigner::from(genesis_owner.clone()),
                    genesis_owner.public_key_set.public_key(),
                );
                let mut genesis_node = MintNode::new(key_manager.clone());

                let genesis = genesis_node.issue_genesis_dbc(1000)?;
                let genesis_sig = genesis
                    .public_key_set
                    .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])?;

                let genesis_dbc = Dbc {
                    content: genesis.dbc_content,
                    transaction: genesis.transaction,
                    transaction_sigs: BTreeMap::from_iter([(
                        genesis_dbc_input(),
                        (genesis_key, genesis_sig),
                    )]),
                };

                let genesis_secrets =
                    DbcHelper::decrypt_amount_secrets(&genesis_owner, &genesis_dbc.content)?;

                let outputs_owner = crate::bls_dkg_id(&mut rng);
                let outputs_owner_pk = outputs_owner.public_key_set.public_key();
                let output_amount = 1000;

                let mut tx = crate::TransactionBuilder::default()
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
                let mut out_dbc_content = std::mem::take(&mut tx.outputs)
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
                tx.outputs.insert(out_dbc_content);

                // The mint should reissue this without error because the output commitment sum matches the
                // input commitment sum.  However the recipient will be unable to spend it using the received
                // secret amount.  The only way to spend it would be receive the true amount from the sender,
                // or guess it.  And that's assuming the secret blinding_factor is correct, which it is in this
                // case, but might not be in the wild.  So the output DBC could be considered to be in a
                // semi-unspendable state.
                let spent_sig = genesis_owner.public_key_set.combine_signatures(vec![(
                    genesis_owner.index,
                    genesis_owner
                        .secret_key_share
                        .derive_child(&genesis_dbc.spend_key_index())
                        .sign(tx.blinded().hash()),
                )])?;
                let spentbook_pks = genesis_node.key_manager.public_key_set()?;
                let spentbook_sig_share = genesis_node
                    .key_manager
                    .sign(&SpentProof::proof_msg(&tx.blinded().hash(), &spent_sig))?;
                let rr = ReissueRequestBuilder::new(tx.clone())
                    .add_spent_proof_share(
                        genesis_dbc.spend_key(),
                        SpentProofShare {
                            spent_sig,
                            spentbook_pks,
                            spentbook_sig_share,
                        },
                    )
                    .build()?;

                let reissue_share = genesis_node.reissue(rr)?;

                // Aggregate ReissueShare to build output DBCs
                let mut dbc_builder = DbcBuilder::new(tx);
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

                let tx = crate::TransactionBuilder::default()
                    .add_input(input_dbc.clone(), input_secrets)
                    .add_output(crate::Output {
                        amount: input_secrets.amount,
                        owner: outputs_owner_pk,
                    })
                    .build()?;

                let spent_sig = genesis_owner.public_key_set.combine_signatures(vec![(
                    genesis_owner.index,
                    genesis_owner
                        .secret_key_share
                        .derive_child(&genesis_dbc.spend_key_index())
                        .sign(tx.blinded().hash()),
                )])?;
                let spentbook_pks = genesis_node.key_manager.public_key_set()?;
                let spentbook_sig_share = genesis_node
                    .key_manager
                    .sign(&SpentProof::proof_msg(&tx.blinded().hash(), &spent_sig))?;
                let rr = ReissueRequestBuilder::new(tx)
                    .add_spent_proof_share(
                        genesis_dbc.spend_key(),
                        SpentProofShare {
                            spent_sig,
                            spentbook_pks,
                            spentbook_sig_share,
                        },
                    )
                    .build()?;

                // The mint should give an error on reissue because the sum(inputs) does not equal sum(outputs)
                let result = genesis_node.reissue(rr);

                match result {
                    Err(Error::DbcReissueRequestDoesNotBalance) => {}
                    _ => panic!("Expecting Error::DbcReissueRequestDoesNotBalance"),
                }

                // ----------
                // Phase 4. Successful reissue of mis-matched DBC using true committed amount.
                // ----------

                let tx = crate::TransactionBuilder::default()
                    .add_input(input_dbc.clone(), input_secrets)
                    .add_output(crate::Output {
                        amount: output_amount,
                        owner: outputs_owner_pk,
                    })
                    .build()?;

                let spent_sig = outputs_owner.public_key_set.combine_signatures(vec![(
                    outputs_owner.index,
                    outputs_owner
                        .secret_key_share
                        .derive_child(&input_dbc.spend_key_index())
                        .sign(tx.blinded().hash()),
                )])?;

                let spentbook_pks = genesis_node.key_manager.public_key_set()?;
                let spentbook_sig_share = genesis_node
                    .key_manager
                    .sign(&SpentProof::proof_msg(&tx.blinded().hash(), &spent_sig))?;
                let rr = ReissueRequestBuilder::new(tx)
                    .add_spent_proof_share(
                        input_dbc.spend_key(),
                        SpentProofShare {
                            spent_sig,
                            spentbook_pks,
                            spentbook_sig_share,
                        },
                    )
                    .build()?;

                // The mint should reissue without error because the sum(inputs) does equal sum(outputs)
                let result = genesis_node.reissue(rr);
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
    */
}
