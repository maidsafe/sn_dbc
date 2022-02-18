// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{AmountSecrets, KeyImage, Owner, SpentProof, TransactionValidator};
use crate::{DbcContent, DerivationIndex, Error, KeyManager, Result};
use blst_ringct::ringct::{OutputProof, RingCtTransaction};
use blst_ringct::{RevealedCommitment, TrueInput};
use blstrs::group::Curve;
use blsttc::{PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents a Digital Bearer Certificate (Dbc).
///
/// A Dbc may be owned or bearer.
///
/// An owned Dbc is like a check.  Only the recipient can spend it.
/// A bearer Dbc is like cash.  Anyone in possession of it can spend it.
///
/// An owned Dbc includes a PublicKey representing the Owner.
/// A bearer Dbc includes a SecretKey representing the Owner.
///
/// An Owner consists of either a SecretKey (with implicit PublicKey) or a PublicKey.
///
/// The included Owner is called an Owner Base.  The public key can be
/// given out to multiple parties and thus multiple Dbc can share
/// the same Owner Base.
///
/// The Mint and Spentbook never see the Owner Base.  Instead, when a
/// transaction Output is created for a given Owner Base, a random derivation
/// index is generated and used to derive a one-time-use Owner Once.
///
/// The Owner Once is used for a single transaction only and must be unique
/// within the transaction as well as globally for the output DBC's to be spendable.
///
/// Separate methods are available for Owned and Bearer DBCs.
///
/// To spend or work with an Owned Dbc, wallet software must obtain the corresponding
/// SecretKey from the user, and then call an API function that accepts a SecretKey for
/// the Owner Base.
///
/// To spend or work with a Bearer Dbc, wallet software can either:
///  1. use the bearer API methods that do not require a SecretKey, eg:
///        `dbc.amount_secrets_bearer()`
///
///  -- or --
///
///  2. obtain the Owner Base SecretKey from the Dbc and then call
///     the Owner API methods that require a SecretKey.   eg:
///       `dbc.amount_secrets(&dbc.dbc.owner_base().secret_key()?)`
///
/// Sometimes the latter method can be better when working with mixed
/// types of Dbcs.  A useful pattern is to check up-front if the Dbc is bearer
/// or not and obtain the SecretKey from the Dbc itself (bearer) or
/// from the user (owned).  Subsequent code is then the same for both
/// types.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Dbc {
    pub content: DbcContent,
    pub transaction: RingCtTransaction,
    pub mint_sigs: BTreeMap<KeyImage, (PublicKey, Signature)>,
    pub spent_proofs: BTreeSet<SpentProof>,
}

impl Dbc {
    // returns owner base from which one-time-use keypair is derived.
    pub fn owner_base(&self) -> &Owner {
        &self.content.owner_base
    }

    /// returns derived one-time-use owner using SecretKey supplied by caller.
    /// will return an error if the supplied SecretKey does not match the
    /// Dbc owner's public key.
    pub fn owner_once(&self, base_sk: &SecretKey) -> Result<Owner> {
        if base_sk.public_key() != self.owner_base().public_key() {
            return Err(Error::SecretKeyDoesNotMatchPublicKey);
        }

        Ok(Owner::from(
            base_sk.derive_child(&self.derivation_index(base_sk)?),
        ))
    }

    /// returns derived one-time-use owner using SecretKey stored in bearer Dbc.
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn owner_once_bearer(&self) -> Result<Owner> {
        self.owner_once(&self.owner_base().secret_key()?)
    }

    /// returns derivation index used to derive one-time-use keypair from owner base
    pub fn derivation_index(&self, base_sk: &SecretKey) -> Result<DerivationIndex> {
        self.content.derivation_index(base_sk)
    }

    /// returns derivation index used to derive one-time-use keypair from owner base
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn derivation_index_bearer(&self) -> Result<DerivationIndex> {
        self.derivation_index(&self.owner_base().secret_key()?)
    }

    /// returns true if owner base includes a SecretKey.
    ///
    /// If the SecretKey is present, this Dbc can be spent by anyone in
    /// possession of it, making it a true "Bearer" instrument.
    ///
    /// If the SecretKey is not present, then only the person(s) holding
    /// the SecretKey matching the PublicKey can spend it.
    pub fn is_bearer(&self) -> bool {
        self.owner_base().has_secret_key()
    }

    /// decypts and returns the AmountSecrets
    pub fn amount_secrets(&self, base_sk: &SecretKey) -> Result<AmountSecrets> {
        let sk = self.owner_once(base_sk)?.secret_key()?;
        AmountSecrets::try_from((&sk, &self.content.amount_secrets_cipher))
    }

    /// decypts and returns the AmountSecrets
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn amount_secrets_bearer(&self) -> Result<AmountSecrets> {
        self.amount_secrets(&self.owner_base().secret_key()?)
    }

    /// returns KeyImage for the owner's derived public key
    /// This is useful for checking if a Dbc has been spent.
    pub fn key_image(&self, base_sk: &SecretKey) -> Result<KeyImage> {
        let owner_once = self.owner_once(base_sk)?;
        let secret_key = owner_once.secret_key_blst()?;
        Ok(blst_ringct::key_image(secret_key).to_affine().into())
    }

    /// returns KeyImage for the owner's derived public key
    /// This is useful for checking if a Dbc has been spent.
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn key_image_bearer(&self) -> Result<KeyImage> {
        self.key_image(&self.owner_base().secret_key()?)
    }

    /// returns a TrueInput that represents this Dbc for use as
    /// a transaction input.
    pub fn as_true_input(&self, base_sk: &SecretKey) -> Result<TrueInput> {
        Ok(TrueInput {
            secret_key: self.owner_once(base_sk)?.secret_key_blst()?,
            revealed_commitment: self.amount_secrets(base_sk)?.into(),
        })
    }

    /// returns a TrueInput that represents this Dbc for use as
    /// a transaction input.
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn as_true_input_bearer(&self) -> Result<TrueInput> {
        self.as_true_input(&self.owner_base().secret_key()?)
    }

    /// Generate hash of this DBC
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.to_bytes());
        sha3.update(&self.transaction.hash());

        for (in_key, (mint_key, mint_sig)) in self.mint_sigs.iter() {
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
            &self.mint_sigs,
            &self.spent_proofs,
        )?;

        let owner = self.owner_once(base_sk)?.public_key_blst();

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

    /// bearer version of confirm_valid()
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn confirm_valid_bearer<K: KeyManager>(&self, mint_verifier: &K) -> Result<(), Error> {
        self.confirm_valid(&self.owner_base().secret_key()?, mint_verifier)
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

    /// bearer version of confirm_provided_amount_matches_commitment()
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn confirm_provided_amount_matches_commitment_bearer(
        &self,
        amount: &AmountSecrets,
    ) -> Result<()> {
        self.confirm_provided_amount_matches_commitment(&self.owner_base().secret_key()?, amount)
    }

    fn my_output_proof(&self, base_sk: &SecretKey) -> Result<&OutputProof> {
        let owner = self.owner_once(base_sk)?.public_key_blst();
        self.transaction
            .outputs
            .iter()
            .find(|o| *o.public_key() == owner)
            .ok_or(Error::OutputProofNotFound)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::{
        Amount, AmountSecrets, DbcBuilder, GenesisBuilderMock, Hash, KeyManager, MintNode,
        OutputOwnerMap, Owner, OwnerOnce, ReissueRequest, ReissueRequestBuilder, SecretKeyBlst,
        SimpleKeyManager, SimpleSigner, SpentBookNodeMock,
    };
    use blst_ringct::ringct::RingCtMaterial;
    use blst_ringct::{DecoyInput, Output, RevealedCommitment};
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rand_core::SeedableRng as SeedableRngCore;

    const STD_NUM_DECOYS: usize = 3;

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
        output_owners: Vec<OwnerOnce>,
        spentbook: &mut SpentBookNodeMock,
        rng8: &mut (impl RngCore + rand_core::CryptoRng),
    ) -> Result<(ReissueRequest, Vec<RevealedCommitment>, OutputOwnerMap)> {
        let amount = amount_secrets.amount();

        let decoy_inputs = spentbook.random_decoys(STD_NUM_DECOYS, rng8);

        let (reissue_tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(dbc_owner_blst, amount_secrets, decoy_inputs, rng8)
                .add_outputs(divide(amount, n_ways).zip(output_owners.into_iter()).map(
                    |(amount, owner_once)| {
                        (
                            Output {
                                amount,
                                public_key: owner_once.as_owner().public_key_blst(),
                            },
                            owner_once,
                        )
                    },
                ))
                .build(rng8)?;

        let key_image = reissue_tx.mlsags[0].key_image.into();
        let spent_proof_share = spentbook.log_spent(key_image, reissue_tx.clone())?;

        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(spent_proof_share)
            .build()?;

        Ok((rr, revealed_commitments, output_owners))
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let mut rng8 = rand8::rngs::StdRng::from_seed([0u8; 32]);
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let amount = 100;

        let owner_once =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);

        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output {
                public_key: owner_once.as_owner().public_key_blst(),
                amount,
            }],
        };

        let (transaction, revealed_commitments) = ringct_material
            .sign(&mut rng8)
            .expect("Failed to sign transaction");

        assert_eq!(revealed_commitments.len(), 1);

        let input_content = DbcContent::from((
            owner_once.owner_base.clone(),
            owner_once.derivation_index,
            AmountSecrets::from(revealed_commitments[0]),
        ));

        let dbc = Dbc {
            content: input_content,
            transaction,
            mint_sigs: Default::default(),
            spent_proofs: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let mint_key_manager = SimpleKeyManager::from(SimpleSigner::from(id));

        assert!(matches!(
            dbc.confirm_valid(&owner_once.owner_base().secret_key()?, &mint_key_manager),
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

        // first we will reissue genesis into outputs (100, GENESIS-100).
        // The 100 output will be our starting_dbc.
        //
        // we do this instead of just using GENESIS_AMOUNT as our starting amount
        // because GENESIS_AMOUNT is u64::MAX (or could be) and later in the test
        // we add extra_output_amount to amount, which would otherwise
        // cause an integer overflow.
        let (mint_node, mut spentbook, _genesis_dbc, starting_dbc, _change_dbc) =
            generate_dbc_of_value(amount, &mut rng, &mut rng8)?;

        let input_owners: Vec<OwnerOnce> = (0..n_inputs.coerce())
            .map(|_| OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8))
            .collect();

        let (reissue_request, revealed_commitments, output_owners) = prepare_even_split(
            starting_dbc.owner_once_bearer()?.secret_key_blst()?,
            starting_dbc.amount_secrets_bearer()?,
            n_inputs.coerce(),
            input_owners,
            &mut spentbook,
            &mut rng8,
        )?;

        let sp = reissue_request.spent_proofs.iter().next().unwrap();
        assert!(sp
            .spentbook_pub_key
            .verify(&sp.spentbook_sig, sp.content.hash()));
        let split_reissue_share = mint_node.reissue(reissue_request)?;

        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(split_reissue_share);
        let output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next reissue.
        let inputs: Vec<(Dbc, SecretKey, Vec<DecoyInput>)> = output_dbcs
            .into_iter()
            .map(|(dbc, owner_once, _amount_secrets)| {
                (
                    dbc,
                    owner_once.owner_base().secret_key().unwrap(),
                    spentbook.random_decoys(STD_NUM_DECOYS, &mut rng8),
                )
            })
            .collect();

        let owner_once =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng8);

        let (reissue_tx, _revealed_commitments, _material, _output_owners) =
            crate::TransactionBuilder::default()
                .add_inputs_dbc(inputs, &mut rng8)?
                .add_output(
                    Output {
                        amount,
                        public_key: owner_once.as_owner().public_key_blst(),
                    },
                    owner_once.clone(),
                )
                .build(&mut rng8)?;

        let mut rr_builder = ReissueRequestBuilder::new(reissue_tx.clone());
        for mlsag in reissue_tx.mlsags.iter() {
            let spent_proof_share =
                spentbook.log_spent(mlsag.key_image.into(), reissue_tx.clone())?;
            rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
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
            owner_once.owner_base.clone(),
            owner_once.derivation_index,
            fuzzed_amt_secrets.clone(),
        ));

        let mut fuzzed_mint_sigs: BTreeMap<KeyImage, (PublicKey, Signature)> = BTreeMap::new();

        let mint_pk = mint_node.key_manager().public_key_set()?.public_key();
        fuzzed_mint_sigs.extend(
            reissue_share
                .mint_node_signatures
                .into_keys()
                .take(n_valid_sigs.coerce())
                .map(|in_owner| (in_owner, (mint_pk, mint_sig.clone()))),
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
                fuzzed_mint_sigs.insert(
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

                fuzzed_mint_sigs.insert(
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
            fuzzed_mint_sigs.insert(
                KeyImage::random(&mut rng8),
                (
                    mint_node.key_manager().public_key_set()?.public_key(),
                    mint_sig.clone(),
                ),
            );
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: reissue_share.transaction.clone(),
            mint_sigs: fuzzed_mint_sigs,
            spent_proofs: reissue_share.spent_proofs.clone(), // todo: fuzz spent proofs.
        };

        let key_manager = mint_node.key_manager();
        let validation_res = dbc.confirm_valid(&owner_once.owner_base().secret_key()?, key_manager);

        let dbc_owner = dbc
            .owner_once(&owner_once.owner_base().secret_key()?)?
            .public_key_blst();

        // Check if commitment in AmountSecrets matches the commitment in tx OutputProof
        let commitments_match = dbc
            .confirm_provided_amount_matches_commitment(
                &owner_once.owner_base().secret_key()?,
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
                    Vec::from_iter(dbc.mint_sigs.keys().cloned()),
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
                    .mint_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            Err(Error::Signing(s)) if s == Error::UnrecognisedAuthority.to_string() => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .mint_sigs
                    .values()
                    .any(|(pk, _)| key_manager.verify_known_key(pk).is_err()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        Ok(())
    }

    pub(crate) fn generate_dbc_of_value(
        amount: Amount,
        rng: &mut impl rand::RngCore,
        rng8: &mut (impl rand8::RngCore + rand_core::CryptoRng),
    ) -> Result<(MintNode<SimpleKeyManager>, SpentBookNodeMock, Dbc, Dbc, Dbc)> {
        let (mint_node, mut spentbook_node, genesis_dbc, _genesis_material, _amount_secrets) =
            GenesisBuilderMock::init_genesis_single(rng, rng8)?;

        let output_amounts = vec![amount, sn_dbc::GenesisMaterial::GENESIS_AMOUNT - amount];

        let (tx, revealed_commitments, _material, output_owners) =
            crate::TransactionBuilder::default()
                .add_input_by_secrets(
                    genesis_dbc.owner_once_bearer()?.secret_key_blst()?,
                    genesis_dbc.amount_secrets_bearer()?,
                    vec![], // never any decoys for genesis
                    rng8,
                )
                .add_outputs(output_amounts.into_iter().map(|amount| {
                    let owner_once =
                        OwnerOnce::from_owner_base(Owner::from_random_secret_key(rng), rng8);
                    (
                        Output {
                            amount,
                            public_key: owner_once.as_owner().public_key_blst(),
                        },
                        owner_once,
                    )
                }))
                .build(rng8)?;

        // Build ReissuRequest
        let mut rr_builder = ReissueRequestBuilder::new(tx.clone());
        for mlsag in tx.mlsags.iter() {
            let spent_proof_share = spentbook_node.log_spent(mlsag.key_image.into(), tx.clone())?;
            rr_builder = rr_builder.add_spent_proof_share(spent_proof_share);
        }
        let rr = rr_builder.build()?;

        let reissue_share = mint_node.reissue(rr)?;
        let mut dbc_builder = DbcBuilder::new(revealed_commitments, output_owners);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);

        let mut iter = dbc_builder.build()?.into_iter();
        let (starting_dbc, ..) = iter.next().unwrap();
        let (change_dbc, ..) = iter.next().unwrap();

        Ok((
            mint_node,
            spentbook_node,
            genesis_dbc,
            starting_dbc,
            change_dbc,
        ))
    }
}
