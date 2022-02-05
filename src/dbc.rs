// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    AmountSecrets, KeyImage, PublicKeyBlst, SecretKeyBlst, SpentProof, TransactionValidator,
};
use crate::{DbcContent, DerivationIndex, DerivedOwner, Error, KeyManager, Owner, Result};
use blst_ringct::ringct::{OutputProof, RingCtTransaction};
use blst_ringct::RevealedCommitment;
use blstrs::group::Curve;
use blstrs::G1Projective;
use blsttc::{PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Dbc {
    pub content: DbcContent,
    pub transaction: RingCtTransaction,
    pub transaction_sigs: BTreeMap<KeyImage, (PublicKey, Signature)>,
    pub spent_proofs: BTreeSet<SpentProof>,
}

impl Dbc {
    /// returns owner base from which one-time-use keypair is derived.
    pub fn owner_base(&self) -> &Owner {
        &self.content.owner_base
    }

    /// returns derived_owner
    pub fn derived_owner(&self, base_sk: &SecretKey) -> Result<DerivedOwner> {
        Ok(DerivedOwner {
            owner_base: self.owner_base().clone(),
            derivation_index: self.derivation_index(base_sk)?,
        })
    }

    /// returns derivation index used to derive one-time-use keypair from owner base
    pub fn derivation_index(&self, base_sk: &SecretKey) -> Result<DerivationIndex> {
        self.content.derivation_index(base_sk)
    }

    /// returns owner base SecretKey if available.
    pub fn owner_base_secret_key(&self) -> Result<SecretKey> {
        self.content.owner_base.secret_key()
    }

    /// returbs owner base PublicKey.
    pub fn owner_base_public_key(&self) -> PublicKey {
        self.content.owner_base.public_key()
    }

    /// returns owner SecretKey derived from supplied owner base SecretKey
    pub fn owner_secret_key(&self, base_sk: &SecretKey) -> Result<SecretKey> {
        Ok(base_sk.derive_child(&self.derivation_index(base_sk)?))
    }

    /// returns owner PublicKey derived from owner base PublicKey
    pub fn owner_public_key(&self, base_sk: &SecretKey) -> Result<PublicKey> {
        Ok(self
            .content
            .owner_base
            .derive(&self.derivation_index(base_sk)?)
            .public_key())
    }

    /// returns owner BLST SecretKey derived from owner base SecrtKey, if available.
    // note: can go away once blsttc integrated with blst_ringct.
    pub fn owner_secret_key_blst(&self, base_sk: &SecretKey) -> Result<SecretKeyBlst> {
        self.derived_owner(base_sk)?.derive_secret_key_blst()
    }

    /// returns owner BLST PublicKey derived from owner base PublicKey
    // note: can go away once blsttc integrated with blst_ringct.
    pub fn owner_public_key_blst(&self, base_sk: &SecretKey) -> Result<PublicKeyBlst> {
        Ok(self.derived_owner(base_sk)?.derive_public_key_blst())
    }

    /// returns true if owner base includes a SecretKey.
    ///
    /// If the SecretKey is present, this Dbc can be spent by anyone in
    /// possession of it, making it a true "Bearer" instrument.
    ///
    /// If the SecretKey is not present, then only the person(s) holding
    /// the SecretKey matching the PublicKey can spend it.
    pub fn has_secret_key(&self) -> bool {
        self.content.owner_base.has_secret_key()
    }

    /// decypts and returns the AmountSecrets
    pub fn amount_secrets(&self, base_sk: &SecretKey) -> Result<AmountSecrets> {
        let sk = self.owner_secret_key(base_sk)?;
        AmountSecrets::try_from((&sk, &self.content.amount_secrets_cipher))
    }

    /// returns KeyImage for the owner's derived public key
    /// This is useful for checking if a Dbc has been spent.
    pub fn key_image(&self, base_sk: &SecretKey) -> Result<KeyImage> {
        let public_key: G1Projective = self.owner_public_key_blst(base_sk)?.into();
        let secret_key = self.owner_secret_key_blst(base_sk)?;
        Ok((blst_ringct::hash_to_curve(public_key) * secret_key)
            .to_affine()
            .into())
    }

    /// Generate hash of this DBC
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.to_bytes());
        sha3.update(&self.transaction.hash());

        for (in_key, (mint_key, mint_sig)) in self.transaction_sigs.iter() {
            sha3.update(&in_key.to_bytes());
            sha3.update(&mint_key.to_bytes());
            sha3.update(&mint_sig.to_bytes());
        }

        for sp in self.spent_proofs.iter() {
            sha3.update(&sp.to_bytes());
        }

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    // Check there exists a Transaction with the output containing this Dbc
    // note: common validation logic is shared by MintNode::reissue() and Dbc::confirm_valid()
    //
    // note: for spent_proofs to validate, the mint_verifier must have/know the spentbook section's public key.
    pub fn confirm_valid<K: KeyManager>(
        &self,
        base_sk: &SecretKey,
        mint_verifier: &K,
    ) -> Result<(), Error> {
        TransactionValidator::validate(
            mint_verifier,
            &self.transaction,
            &self.transaction_sigs,
            &self.spent_proofs,
        )?;

        let owner = self.owner_public_key_blst(base_sk)?;

        if !self
            .transaction
            .outputs
            .iter()
            .any(|o| *o.public_key() == owner)
        {
            Err(Error::DbcContentNotPresentInTransactionOutput)
        } else {
            Ok(())
        }
    }

    /// Checks if the provided AmountSecrets matches the amount commitment.
    /// note that both the amount and blinding_factor must be correct.
    ///
    /// Note that the mint cannot perform this check.  Only the Dbc
    /// recipient can.
    ///
    /// A Dbc recipient should call this immediately upon receipt.
    /// If the commitments do not match, then the Dbc cannot be spent
    /// using the AmountSecrets provided.
    ///
    /// To clarify, the Dbc is still spendable, however the correct
    /// AmountSecrets need to be obtained from the sender somehow.
    ///
    /// As an example, if the Dbc recipient is a merchant, they typically
    /// would not provide goods to the purchaser if this check fails.
    /// However the purchaser may still be able to remedy the situation by
    /// providing the correct AmountSecrets to the merchant.
    ///
    /// If the merchant were to send the goods without first performing
    /// this check, then they could be stuck with an unspendable Dbc
    /// and no recourse.
    pub fn confirm_provided_amount_matches_commitment(
        &self,
        base_sk: &SecretKey,
        amount: &AmountSecrets,
    ) -> Result<()> {
        let tx_commitment = self.my_output_proof(base_sk)?.commitment();
        let secrets_commitment = RevealedCommitment {
            value: amount.amount(),
            blinding: amount.blinding_factor(),
        }
        .commit(&Default::default())
        .to_affine();

        match secrets_commitment == tx_commitment {
            true => Ok(()),
            false => Err(Error::AmountCommitmentsDoNotMatch),
        }
    }

    fn my_output_proof(&self, base_sk: &SecretKey) -> Result<&OutputProof> {
        let owner = self.owner_public_key_blst(base_sk)?;
        self.transaction
            .outputs
            .iter()
            .find(|o| *o.public_key() == owner)
            .ok_or(Error::OutputProofNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{init_genesis, NonZeroTinyInt, SpentBookMock, TinyInt};
    use crate::{
        Amount, AmountSecrets, DbcBuilder, DerivedOwner, Hash, KeyManager, Owner, ReissueRequest,
        ReissueRequestBuilder, SecretKeyBlst, SimpleKeyManager, SimpleSigner,
    };
    use blst_ringct::ringct::RingCtMaterial;
    use blst_ringct::{Output, RevealedCommitment};
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rand_core::SeedableRng as SeedableRngCore;

    fn divide(amount: Amount, n_ways: u8) -> impl Iterator<Item = Amount> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as Amount);
            let leftover = amount % (n_ways as Amount);

            let odd_compensation = if (i as Amount) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(
        dbc_owner_blst: SecretKeyBlst,
        amount_secrets: AmountSecrets,
        n_ways: u8,
        output_owners: Vec<DerivedOwner>,
        spentbook: &mut SpentBookMock,
        mut rng8: impl RngCore + rand_core::CryptoRng,
    ) -> Result<(
        ReissueRequest,
        Vec<RevealedCommitment>,
        BTreeMap<KeyImage, DerivedOwner>,
    )> {
        let amount = amount_secrets.amount();

        let decoy_inputs = vec![]; // for now.

        let (reissue_tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(dbc_owner_blst, amount_secrets, decoy_inputs, &mut rng8)
                .add_outputs(divide(amount, n_ways).zip(output_owners.into_iter()).map(
                    |(amount, derived_owner)| {
                        (
                            Output {
                                amount,
                                public_key: derived_owner.derive_public_key_blst(),
                            },
                            derived_owner,
                        )
                    },
                ))
                .build(&mut rng8)?;

        let key_image = reissue_tx.mlsags[0].key_image.into();
        let spent_proof_share = spentbook.log_spent(key_image, reissue_tx.clone())?;

        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(0, spent_proof_share)
            .build()?;

        Ok((rr, revealed_commitments, output_owners))
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let amount = 100;

        let derived_owner =
            DerivedOwner::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);

        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output {
                public_key: derived_owner.derive_public_key_blst(),
                amount,
            }],
        };

        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng8)
            .expect("Failed to sign transaction");

        assert_eq!(revealed_commitments.len(), 1);

        let input_content = DbcContent::from((
            derived_owner.owner_base.clone(),
            derived_owner.derivation_index,
            AmountSecrets::from(revealed_commitments[0]),
        ));

        let dbc = Dbc {
            content: input_content,
            transaction,
            transaction_sigs: Default::default(),
            spent_proofs: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let mint_key_manager = SimpleKeyManager::from(SimpleSigner::from(id));

        assert!(matches!(
            dbc.confirm_valid(&derived_owner.base_secret_key()?, &mint_key_manager,),
            Err(Error::TransactionMustHaveAnInput)
        ));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[quickcheck]
    fn prop_dbc_validation(
        n_inputs: NonZeroTinyInt,     // # of input DBC's
        n_valid_sigs: TinyInt,        // # of valid sigs
        n_wrong_signer_sigs: TinyInt, // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,    // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,  // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt, // Artifically increase output dbc value
    ) -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let amount = 100;

        let (mint_node, mut spentbook, genesis, _genesis_dbc) =
            init_genesis(&mut rng, &mut rng8, amount)?;

        let input_owners: Vec<DerivedOwner> = (0..=n_inputs.coerce())
            .map(|_| {
                DerivedOwner::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8)
            })
            .collect();

        let (reissue_request, revealed_commitments, output_owners) = prepare_even_split(
            genesis.secret_key,
            genesis.amount_secrets,
            n_inputs.coerce(),
            input_owners,
            &mut spentbook,
            &mut rng8,
        )?;

        let sp = reissue_request.spent_proofs.iter().next().unwrap();
        assert!(sp.spentbook_pub_key.verify(
            &sp.spentbook_sig,
            Hash::from(reissue_request.transaction.hash())
        ));

        let split_reissue_share = mint_node.reissue(reissue_request)?;

        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(split_reissue_share);
        let output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next reissue.
        let inputs: Vec<(SecretKeyBlst, AmountSecrets, Vec<blst_ringct::DecoyInput>)> = output_dbcs
            .into_iter()
            .map(|(_dbc, derived_owner, amount_secrets)| {
                let decoy_inputs = vec![]; // todo
                (
                    derived_owner.derive_secret_key_blst().unwrap(),
                    amount_secrets,
                    decoy_inputs,
                )
            })
            .collect();

        let derived_owner =
            DerivedOwner::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);

        let (reissue_tx, _revealed_commitments, material, _output_owners) =
            crate::TransactionBuilder::default()
                .add_inputs_by_secrets(inputs, &mut rng8)
                .add_output(
                    Output {
                        amount,
                        public_key: derived_owner.derive_public_key_blst(),
                    },
                    derived_owner.clone(),
                )
                .build(&mut rng8)?;

        let mut rr_builder = ReissueRequestBuilder::new(reissue_tx.clone());
        for (i, (mlsag, _mlsag_material)) in reissue_tx
            .mlsags
            .iter()
            .zip(material.inputs.iter())
            .enumerate()
        {
            let spent_proof_share =
                spentbook.log_spent(mlsag.key_image.into(), reissue_tx.clone())?;
            rr_builder = rr_builder.add_spent_proof_share(i, spent_proof_share);
        }

        let rr = rr_builder.build()?;
        let reissue_share = mint_node.reissue(rr)?;
        assert_eq!(reissue_tx.hash(), reissue_share.transaction.hash());

        let (mint_key_set, mint_sig_share) =
            &reissue_share.mint_node_signatures.values().next().unwrap();

        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let fuzzed_amt_secrets =
            AmountSecrets::from_amount(amount + extra_output_amount.coerce::<Amount>(), &mut rng8);
        let dbc_amount = fuzzed_amt_secrets.amount();

        let fuzzed_content = DbcContent::from((
            derived_owner.owner_base.clone(),
            derived_owner.derivation_index,
            fuzzed_amt_secrets.clone(),
        ));

        let mut fuzzed_transaction_sigs: BTreeMap<KeyImage, (PublicKey, Signature)> =
            BTreeMap::new();

        let mint_pk = mint_node.key_manager().public_key_set()?.public_key();
        fuzzed_transaction_sigs.extend(
            reissue_share
                .mint_node_signatures
                .into_iter()
                .take(n_valid_sigs.coerce())
                .map(|(in_owner, _)| (in_owner, (mint_pk, mint_sig.clone()))),
        );

        let mut repeating_inputs = reissue_tx
            .mlsags
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Invalid mint signatures BUT signing correct message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let id = crate::bls_dkg_id(&mut rng);
                let key_manager = SimpleKeyManager::from(SimpleSigner::from(id));
                let trans_sig_share = key_manager
                    .sign(&Hash::from(reissue_share.transaction.hash()))
                    .unwrap();
                let trans_sig = key_manager
                    .public_key_set()?
                    .combine_signatures(vec![trans_sig_share.threshold_crypto()])
                    .unwrap();
                fuzzed_transaction_sigs.insert(
                    input.key_image.into(),
                    (key_manager.public_key_set()?.public_key(), trans_sig),
                );
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = mint_node.key_manager.sign(&Hash([0u8; 32])).unwrap();
                let wrong_msg_mint_sig = mint_node
                    .key_manager()
                    .public_key_set()?
                    .combine_signatures(vec![wrong_msg_sig.threshold_crypto()])
                    .unwrap();

                fuzzed_transaction_sigs.insert(
                    input.key_image.into(),
                    (
                        mint_node.key_manager.public_key_set()?.public_key(),
                        wrong_msg_mint_sig,
                    ),
                );
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs.insert(
                Default::default(),
                (
                    mint_node.key_manager().public_key_set()?.public_key(),
                    mint_sig.clone(),
                ),
            );
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: reissue_share.transaction.clone(),
            transaction_sigs: fuzzed_transaction_sigs,
            spent_proofs: reissue_share.spent_proofs.clone(), // todo: fuzz spent proofs.
        };

        let key_manager = mint_node.key_manager();
        let validation_res = dbc.confirm_valid(&derived_owner.base_secret_key()?, key_manager);

        let dbc_owner = dbc.owner_public_key_blst(&derived_owner.base_secret_key()?)?;

        // Check if commitment in AmountSecrets matches the commitment in tx OutputProof
        let commitments_match = dbc
            .confirm_provided_amount_matches_commitment(
                &derived_owner.base_secret_key()?,
                &fuzzed_amt_secrets,
            )
            .is_ok();

        match validation_res {
            Ok(()) => {
                assert!(dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| *o.public_key() == dbc_owner));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);

                // note: reissue can succeed even though amount_secrets_cipher amount does not
                // match tx commited amount.
                assert!(dbc_amount == amount || !commitments_match);
                assert!(extra_output_amount.coerce::<u8>() == 0 || !commitments_match);
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs.coerce::<u8>() < n_inputs.coerce::<u8>());
            }
            Err(Error::SpentProofInputMismatch) => {
                // todo: fuzz spent proofs.
                assert!(dbc.spent_proofs.len() < dbc.transaction.mlsags.len());
            }
            Err(Error::UnknownInput) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
                assert_ne!(
                    Vec::from_iter(dbc.transaction_sigs.keys().cloned()),
                    dbc.transaction
                        .mlsags
                        .iter()
                        .map(|m| m.key_image.into())
                        .collect::<Vec<KeyImage>>()
                );
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| *o.public_key() == dbc_owner));
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::FailedSignature) => {
                assert_ne!(n_wrong_msg_sigs.coerce::<u8>(), 0);
            }
            Err(Error::Signing(s)) if s == Error::FailedSignature.to_string() => {
                assert_ne!(n_wrong_msg_sigs.coerce::<u8>(), 0);
            }
            Err(Error::UnrecognisedAuthority) => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            Err(Error::Signing(s)) if s == Error::UnrecognisedAuthority.to_string() => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        Ok(())
    }
}
