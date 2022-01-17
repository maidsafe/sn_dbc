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
    Amount, AmountSecrets, DbcContent, Error, Hash, KeyImage, KeyManager, NodeSignature,
    PublicKeySet, Result, SpentProof, SpentProofShare,
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

pub fn genesis_dbc_input() -> KeyImage {
    use blsttc::group::CurveProjective;
    blsttc::convert::g1_to_be_bytes(blsttc::G1::one())
}

#[derive(Clone)]
pub struct GenesisDbcShare {
    pub ringct_material: RingCtMaterial,
    pub dbc_content: DbcContent,
    pub transaction: RingCtTransaction,
    pub revealed_commitments: Vec<RevealedCommitment>,
    pub public_key_set: PublicKeySet,
    pub transaction_sig: NodeSignature,
    pub secret_key: Scalar,
    pub spent_proofs: BTreeSet<SpentProof>,
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
        // temporary: we bypass KeyManager and create a deterministic
        // secret key, used by all MintNodes.
        let poly = Poly::one();
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&poly.to_bytes());

        let secret_key_set_ttc = SecretKeySet::from(poly);

        // create sk and derive pk.
        let secret_key = Scalar::from_bytes_le(&sk_bytes).unwrap();
        let public_key = (G1Affine::generator() * secret_key).to_affine();

        let true_input = TrueInput {
            secret_key,
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

        // Here we sign as the DBC owner.
        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");

        let dbc_content =
            DbcContent::from((public_key, AmountSecrets::from(revealed_commitments[0])));

        // Here we sign as the mint.
        let transaction_sig = self
            .key_manager
            .sign(&Hash::from(transaction.hash()))
            .map_err(|e| Error::Signing(e.to_string()))?;

        let spent_proofs: BTreeSet<SpentProof> = Default::default();

        Ok(GenesisDbcShare {
            ringct_material,
            dbc_content,
            transaction,
            revealed_commitments, // output commitments
            public_key_set: secret_key_set_ttc.public_keys(),
            transaction_sig,
            secret_key,
            spent_proofs,
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

        let keyimage_unique: BTreeSet<KeyImage> = transaction
            .mlsags
            .iter()
            .map(|m| m.key_image.to_compressed())
            .collect();
        if keyimage_unique.len() != transaction.mlsags.len() {
            return Err(Error::KeyImageNotUniqueAcrossInputs);
        }

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
        for mlsag in transaction.mlsags.iter() {
            let key_image = mlsag.key_image.to_compressed();
            match spent_proofs_sorted
                .iter()
                .find(|s| s.key_image == key_image)
            {
                Some(proof) => proof.validate(transaction_hash, self.key_manager())?,
                None => return Err(Error::MissingSpentProof(key_image)),
            }
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
    use blstrs::{group::Group, G1Projective};
    use quickcheck_macros::quickcheck;
    use rand::SeedableRng;
    use rand_core::SeedableRng as SeedableRngCore;
    use std::collections::BTreeSet;
    use std::convert::TryFrom;

    use crate::{
        tests::{TinyInt, TinyVec},
        BlsHelper, Dbc, DbcBuilder, DbcHelper, ReissueRequestBuilder, SimpleKeyManager,
        SimpleSigner, SpentProofShare,
    };

    #[quickcheck]
    fn prop_genesis() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let genesis_owner = crate::bls_dkg_id(&mut rng);
        let genesis_key = genesis_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis = genesis_node.issue_genesis_dbc(1000, &mut rng8).unwrap();

        let genesis_sig = genesis
            .public_key_set
            .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            transaction: genesis.transaction,
            transaction_sigs: BTreeMap::from_iter([(
                genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
            spent_proofs: genesis.spent_proofs,
        };

        let validation = genesis_dbc.confirm_valid(genesis_node.key_manager());
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

        let genesis_owner = crate::bls_dkg_id(&mut rng);
        let genesis_key = genesis_owner.public_key_set.public_key();
        let key_manager = SimpleKeyManager::new(SimpleSigner::from(genesis_owner), genesis_key);
        let mut genesis_node = MintNode::new(key_manager.clone());

        let genesis = genesis_node.issue_genesis_dbc(output_amount, &mut rng8)?;
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
            spent_proofs: genesis.spent_proofs,
        };

        let output_owners: Vec<bls_dkg::outcome::Outcome> = (0..output_amounts.len())
            .map(|_| crate::bls_dkg_id(&mut rng))
            .collect();
        let output_owner_pks: Vec<G1Affine> = output_owners
            .iter()
            .map(|o| BlsHelper::blsttc_to_blstrs_pubkey(&o.public_key_set.public_key()))
            .collect();

        let (reissue_tx, revealed_commitments, _material) = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis.secret_key,
                AmountSecrets::from(genesis.revealed_commitments[0]),
                vec![], // genesis is only input, so no decoys.
                &mut rng8,
            )
            .add_outputs(
                output_amounts
                    .iter()
                    .enumerate()
                    .map(|(idx, a)| crate::Output {
                        amount: *a,
                        public_key: output_owner_pks[idx],
                    }),
            )
            .build(&mut rng8)?;
        let tx_hash = &Hash::from(reissue_tx.hash());

        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node.key_manager.sign(tx_hash)?;

        // there is only one input (genesis), so no decoys are available.
        let public_commitments: Vec<G1Affine> = genesis_dbc
            .transaction
            .outputs
            .iter()
            .map(|o| o.commitment())
            .collect();

        let rr = ReissueRequestBuilder::new(reissue_tx.clone())
            .add_spent_proof_share(
                0,
                SpentProofShare {
                    key_image: reissue_tx.mlsags[0].key_image.to_compressed(),
                    spentbook_pks,
                    spentbook_sig_share,
                    public_commitments,
                },
            )
            .build()?;

        let reissue_share = match genesis_node.reissue(rr) {
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
        let mut dbc_builder = DbcBuilder::new(revealed_commitments);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        for (idx, dbc) in output_dbcs.iter().enumerate() {
            let dbc_amount =
                DbcHelper::decrypt_amount(&output_owners[idx], &dbc.content.amount_secrets_cipher)?;
            assert!(output_amounts.iter().any(|a| *a == dbc_amount));
            assert!(dbc.confirm_valid(&key_manager).is_ok());
        }

        assert_eq!(
            output_dbcs
                .iter()
                .enumerate()
                .map(|(idx, dbc)| {
                    DbcHelper::decrypt_amount(
                        &output_owners[idx],
                        &dbc.content.amount_secrets_cipher,
                    )
                })
                .sum::<Result<Amount, _>>()?,
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

        let num_decoy_inputs: usize = num_decoy_inputs.coerce();

        let genesis_owner = crate::bls_dkg_id(&mut rng);
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis_amount: Amount = input_amounts.iter().sum();
        let genesis = genesis_node.issue_genesis_dbc(genesis_amount, &mut rng8)?;
        let genesis_owner = genesis.dbc_content.owner;

        let owner_amounts_and_keys = BTreeMap::from_iter(input_amounts.iter().copied().map(|a| {
            let sks = SecretKeySet::random(1, &mut rng);
            (sks.public_keys().public_key(), (a, sks))
        }));

        let (reissue_tx, revealed_commitments, _material) = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis.secret_key,
                AmountSecrets::from(genesis.revealed_commitments[0]),
                vec![], // genesis is input, no decoys possible.
                &mut rng8,
            )
            .add_outputs(owner_amounts_and_keys.clone().into_iter().map(
                |(public_key, (amount, _))| crate::Output {
                    amount,
                    public_key: BlsHelper::blsttc_to_blstrs_pubkey(&public_key),
                },
            ))
            .build(&mut rng8)
            .unwrap();
        let tx_hash = &Hash::from(reissue_tx.hash());

        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node.key_manager.sign(tx_hash)?;

        // there is only one input (genesis), so no decoys are available.
        let public_commitments: Vec<G1Affine> = genesis
            .transaction
            .outputs
            .iter()
            .filter(|o| *o.public_key() == genesis_owner)
            .map(|o| o.commitment())
            .collect();

        let key_image = reissue_tx.mlsags[0].key_image.to_compressed();
        let rr1 = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(
                0,
                SpentProofShare {
                    key_image,
                    spentbook_pks,
                    spentbook_sig_share,
                    public_commitments,
                },
            )
            .build()?;

        let reissue_share = match genesis_node.reissue(rr1) {
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
        let mut dbc_builder = DbcBuilder::new(revealed_commitments);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let input_dbcs = dbc_builder.build()?;

        let input_dbc_secrets = input_dbcs
            .iter()
            .map(|dbc| {
                let (_, sks) =
                    &owner_amounts_and_keys[&BlsHelper::blstrs_to_blsttc_pubkey(&dbc.owner())];
                let amount_secrets = AmountSecrets::try_from((
                    &sks.secret_key(),
                    &dbc.content.amount_secrets_cipher,
                ))?;
                let secret_key_blstrs = BlsHelper::blsttc_to_blstrs_sk(sks.secret_key());

                // note: decoy inputs can be created from OutputProof + dbc owner's pubkey.
                let decoy_inputs = gen_decoy_inputs(num_decoy_inputs, &mut rng8);
                Ok((secret_key_blstrs, amount_secrets, decoy_inputs))
            })
            .collect::<Result<Vec<(Scalar, crate::AmountSecrets, Vec<DecoyInput>)>>>()?;

        let outputs_owners: Vec<bls_dkg::outcome::Outcome> = (0..=output_amounts.len())
            .map(|_| crate::bls_dkg_id(&mut rng))
            .collect();

        let outputs: Vec<Output> = output_amounts
            .iter()
            .enumerate()
            .map(|(idx, amount)| crate::Output {
                amount: *amount,
                public_key: BlsHelper::blsttc_to_blstrs_pubkey(
                    &outputs_owners[idx].public_key_set.public_key(),
                ),
            })
            .collect();

        let (reissue_tx2, revealed_commitments, material) = crate::TransactionBuilder::default()
            .add_inputs_by_secrets(input_dbc_secrets, &mut rng8)
            .add_outputs(outputs.clone())
            .build(&mut rng8)?;

        let dbc_output_amounts: Vec<Amount> = outputs.iter().map(|o| o.amount).collect();
        let output_total_amount: Amount = dbc_output_amounts.iter().sum();

        let mut rr2_builder = ReissueRequestBuilder::new(reissue_tx2.clone());

        assert_eq!(input_dbcs.len(), reissue_tx2.mlsags.len());

        for (i, (in_mlsag, in_material)) in reissue_tx2
            .mlsags
            .iter()
            .zip(material.inputs.iter())
            .enumerate()
        {
            let is_invalid_spent_proof = invalid_spent_proofs.contains(&i);

            if is_invalid_spent_proof && i % 2 == 0 {
                // drop this spent proof
                continue;
            }

            let tx_hash = if is_invalid_spent_proof && i % 2 == 1 {
                crate::Hash([0u8; 32])
            } else {
                crate::Hash(reissue_tx2.hash())
            };

            let spentbook_pks = genesis_node.key_manager.public_key_set()?;
            let spentbook_sig_share = genesis_node.key_manager.sign(&tx_hash)?;

            let public_commitments = in_material.commitments(&Default::default());

            // note: alternate way to obtain public_commitments without RingCtMaterial
            // exists as comment in commit: b1502a050967f3b04659be96ea8ba745d7b49f2b

            rr2_builder = rr2_builder.add_spent_proof_share(
                i,
                SpentProofShare {
                    key_image: in_mlsag.key_image.to_compressed(),
                    public_commitments,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            );
        }

        let rr2 = rr2_builder.build()?;
        let many_to_many_result = genesis_node.reissue(rr2);

        match many_to_many_result {
            Ok(rs) => {
                assert_eq!(genesis_amount, output_total_amount);
                assert!(invalid_spent_proofs
                    .iter()
                    .all(|i| i >= &reissue_tx2.mlsags.len()));

                // The output amounts (from params) should correspond to the actual output_amounts
                assert_eq!(
                    BTreeSet::from_iter(dbc_output_amounts),
                    BTreeSet::from_iter(output_amounts)
                );

                // Aggregate ReissueShare to build output DBCs
                let mut dbc_builder = DbcBuilder::new(revealed_commitments);
                dbc_builder = dbc_builder.add_reissue_share(rs);
                let output_dbcs = dbc_builder.build()?;

                for dbc in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.confirm_valid(&genesis_node.key_manager);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    output_dbcs
                        .iter()
                        .enumerate()
                        .map(|(idx, dbc)| {
                            DbcHelper::decrypt_amount(
                                &outputs_owners[idx],
                                &dbc.content.amount_secrets_cipher,
                            )
                        })
                        .sum::<Result<Amount, _>>()?,
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
            Err(Error::MissingSpentProof(key)) => {
                let idx = reissue_tx2
                    .mlsags
                    .iter()
                    .position(|i| i.key_image.to_compressed() == key)
                    .unwrap();
                assert!(invalid_spent_proofs.contains(&idx));
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

    fn gen_decoy_inputs(num: usize, mut rng: impl RngCore) -> Vec<DecoyInput> {
        (0..num)
            .map(|_| DecoyInput {
                public_key: G1Projective::random(&mut rng).to_affine(),
                commitment: G1Projective::random(&mut rng).to_affine(),
            })
            .collect()
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
