// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{DbcContent, Denomination, Error, KeyManager, PublicKey, Result, Signature, SpendKey};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Dbc {
    pub content: DbcContent,
    pub mint_public_key: PublicKey,
    pub mint_signature: Signature,
}

impl Dbc {
    /// Derive the (public) spend key for this DBC.
    pub fn spend_key(&self) -> SpendKey {
        let index = self.spend_key_index();
        SpendKey(self.owner().derive_child(&index))
    }

    /// Read the DBC owner
    pub fn owner(&self) -> PublicKey {
        self.content.owner()
    }

    /// Calculate the spend key index, this index is used to derive the spend key.
    pub fn spend_key_index(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.hash().0);
        sha3.update(&self.mint_public_key.to_bytes());
        sha3.update(&self.mint_signature.to_bytes());

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    pub fn denomination(&self) -> Denomination {
        self.content.denomination()
    }

    // Check that signature matches pubkey for content
    pub fn confirm_valid<K: KeyManager>(&self, verifier: &K) -> Result<(), Error> {
        verifier
            .verify_slip(
                &self.content.slip(),
                &self.content.denomination().to_be_bytes(),
                &self.mint_public_key,
                &self.mint_signature,
            )
            .map_err(|e| Error::Signing(e.to_string()))
    }
}
/*
#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::{
        Amount, DbcBuilder, DbcHelper, Hash, KeyManager, Mint, ReissueRequest,
        ReissueRequestBuilder, SimpleKeyManager, SimpleSigner, SimpleSpendBook,
    };

    fn divide(amount: Amount, n_ways: u8) -> impl Iterator<Item = Amount> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as Amount);
            let leftover = amount % (n_ways as Amount);

            let odd_compensation = if (i as Amount) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    fn prepare_even_split(
        dbc_owner: &bls_dkg::outcome::Outcome,
        dbc: Dbc,
        n_ways: u8,
        output_owner: &blsttc::PublicKeySet,
    ) -> Result<ReissueRequest, Error> {
        let amount_secrets = DbcHelper::decrypt_amount_secrets(dbc_owner, &dbc.content)?;

        let reissue_tx = crate::TransactionBuilder::default()
            .add_input(dbc.clone(), amount_secrets)
            .add_outputs(
                divide(amount_secrets.amount, n_ways).map(|amount| crate::Output {
                    amount,
                    owner: output_owner.public_key(),
                }),
            )
            .build()?;

        let rr = ReissueRequestBuilder::new(reissue_tx)
            .add_dbc_signer(
                dbc.spend_key(),
                dbc_owner.public_key_set.clone(),
                (dbc_owner.index, dbc_owner.secret_key_share.clone()),
            )
            .build()?;

        Ok(rr)
    }

    #[test]
    fn test_dbc_without_inputs_is_invalid() -> Result<(), Error> {
        let input_content = DbcContent::new(
            BTreeSet::new(),
            100,
            crate::bls_dkg_id().public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;

        let input_owners = BTreeSet::from_iter([input_content.owner]);

        let dbc = Dbc {
            content: input_content,
            transaction: DbcTransaction {
                inputs: BTreeSet::new(),
                outputs: input_owners,
            },
            transaction_sigs: Default::default(),
        };

        let id = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(id.clone()),
            id.public_key_set.public_key(),
        );

        assert!(matches!(
            dbc.confirm_valid(&key_manager),
            Err(Error::TransactionMustHaveAnInput)
        ));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[quickcheck]
    fn prop_dbc_validation(
        n_inputs: NonZeroTinyInt,      // # of input DBC's
        n_valid_sigs: TinyInt,         // # of valid sigs
        n_wrong_signer_sigs: TinyInt,  // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,     // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,   // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt,  // Artifically increase output dbc value
        n_add_random_parents: TinyInt, // # of random parents to add to output DBC
        n_drop_parents: TinyInt,       // # of valid parents to drop from output DBC
    ) -> Result<(), Error> {
        let amount = 100;
        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = Mint::new(key_manager, SimpleSpendBook::new());

        let genesis = genesis_node.issue_genesis_dbc(amount).unwrap();

        let genesis_sig = genesis
            .public_key_set
            .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])
            .unwrap();

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            transaction: genesis.transaction,
            transaction_sigs: BTreeMap::from_iter([(
                crate::genesis_dbc_input(),
                (genesis_key, genesis_sig),
            )]),
        };

        let input_owner = crate::bls_dkg_id();
        let reissue_request = prepare_even_split(
            &genesis_owner,
            genesis_dbc,
            n_inputs.coerce(),
            &input_owner.public_key_set,
        )?;

        let split_reissue_share = genesis_node
            .reissue(
                reissue_request.clone(),
                reissue_request.transaction.blinded().inputs,
            )
            .unwrap();

        let mut dbc_builder = DbcBuilder::new(reissue_request.transaction);
        dbc_builder = dbc_builder.add_reissue_share(split_reissue_share);
        let output_dbcs = dbc_builder.build()?;

        // The outputs become inputs for next reissue.
        let inputs = output_dbcs.into_iter().map(|dbc| {
            let amount_secrets =
                DbcHelper::decrypt_amount_secrets(&input_owner, &dbc.content).unwrap();
            (dbc, amount_secrets)
        });

        let reissue_tx = crate::TransactionBuilder::default()
            .add_inputs(inputs)
            .add_output(crate::Output {
                amount,
                owner: crate::bls_dkg_id().public_key_set.public_key(),
            })
            .build()?;

        let mut rr_builder = ReissueRequestBuilder::new(reissue_tx.clone());
        for input in reissue_tx.inputs.iter() {
            rr_builder = rr_builder.add_dbc_signer(
                input.spend_key(),
                input_owner.public_key_set.clone(),
                (input_owner.index, input_owner.secret_key_share.clone()),
            );
        }

        let rr = rr_builder.build()?;

        let reissue_share = genesis_node
            .reissue(rr.clone(), rr.transaction.blinded().inputs)
            .unwrap();
        assert_eq!(rr.transaction.blinded(), reissue_share.dbc_transaction);

        let (mint_key_set, mint_sig_share) =
            reissue_share.mint_node_signatures.values().next().unwrap();
        let mint_sig = mint_key_set
            .combine_signatures(vec![mint_sig_share.threshold_crypto()])
            .unwrap();

        let fuzzed_parents = BTreeSet::from_iter(
            reissue_share
                .dbc_transaction
                .inputs
                .iter()
                .copied()
                .skip(n_drop_parents.coerce()) // drop some parents
                .chain(
                    // add some random parents
                    (0..n_add_random_parents.coerce())
                        .into_iter()
                        .map(|_| rand::random::<SpendKey>()),
                ),
        );

        let fuzzed_content = DbcContent::new(
            fuzzed_parents,
            amount + extra_output_amount.coerce::<Amount>(),
            crate::bls_dkg_id().public_key_set.public_key(),
            DbcContent::random_blinding_factor(),
        )?;

        let mut fuzzed_transaction_sigs: BTreeMap<SpendKey, (PublicKey, Signature)> =
            BTreeMap::new();

        // Add valid sigs
        fuzzed_transaction_sigs.extend(
            reissue_share
                .mint_node_signatures
                .keys()
                .take(n_valid_sigs.coerce())
                .map(|in_owner| (*in_owner, (genesis_key, mint_sig.clone()))),
        );
        let mut repeating_inputs = rr
            .transaction
            .inputs
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Invalid mint signatures BUT signing correct message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let id = crate::bls_dkg_id();
                let key_manager =
                    SimpleKeyManager::new(SimpleSigner::from(id.clone()), genesis_key);
                let trans_sig_share = key_manager
                    .sign(&reissue_share.dbc_transaction.hash())
                    .unwrap();
                let trans_sig = id
                    .public_key_set
                    .combine_signatures(vec![trans_sig_share.threshold_crypto()])
                    .unwrap();
                fuzzed_transaction_sigs.insert(
                    input.spend_key(),
                    (id.public_key_set.public_key(), trans_sig),
                );
            }
        }

        // Valid mint signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(input) = repeating_inputs.next() {
                let wrong_msg_sig = genesis_node.key_manager.sign(&Hash([0u8; 32])).unwrap();
                let wrong_msg_mint_sig = genesis_node
                    .key_manager
                    .public_key_set()
                    .unwrap()
                    .combine_signatures(vec![wrong_msg_sig.threshold_crypto()])
                    .unwrap();

                fuzzed_transaction_sigs
                    .insert(input.spend_key(), (genesis_key, wrong_msg_mint_sig));
            }
        }

        // Valid mint signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            fuzzed_transaction_sigs
                .insert(rand::random::<SpendKey>(), (genesis_key, mint_sig.clone()));
        }

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: reissue_share.dbc_transaction,
            transaction_sigs: fuzzed_transaction_sigs,
        };

        let id = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(SimpleSigner::from(id), genesis_key);
        let validation_res = dbc.confirm_valid(&key_manager);

        let dbc_amount = DbcHelper::decrypt_amount(&input_owner, &dbc.content)?;

        match validation_res {
            Ok(()) => {
                assert!(dbc.transaction.outputs.contains(&dbc.owner()));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(dbc_amount, amount);
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);
                assert_eq!(extra_output_amount.coerce::<u8>(), 0);
                assert_eq!(n_add_random_parents.coerce::<u8>(), 0);
                assert_eq!(n_drop_parents.coerce::<u8>(), 0);
            }
            Err(Error::MissingSignatureForInput) => {
                assert!(n_valid_sigs.coerce::<u8>() < n_inputs.coerce::<u8>());
            }
            Err(Error::UnknownInput) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
                assert_ne!(
                    BTreeSet::from_iter(dbc.transaction_sigs.keys().copied()),
                    dbc.transaction.inputs
                );
            }
            Err(Error::DbcContentParentsDifferentFromTransactionInputs) => {
                assert!(
                    n_add_random_parents.coerce::<u8>() > 0 || n_drop_parents.coerce::<u8>() > 0
                );
                assert!(dbc.transaction.inputs != dbc.content.parents);
                assert!(!dbc.transaction.outputs.contains(&dbc.owner()));
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc.transaction.outputs.contains(&dbc.owner()));
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
                    .any(|(k, _)| key_manager.verify_known_key(k).is_err()));
            }
            Err(Error::Signing(s)) if s == Error::UnrecognisedAuthority.to_string() => {
                assert!(n_wrong_signer_sigs.coerce::<u8>() > 0);
                assert!(dbc
                    .transaction_sigs
                    .values()
                    .any(|(k, _)| key_manager.verify_known_key(k).is_err()));
            }
            res => panic!("Unexpected verification result {:?}", res),
        }
        Ok(())
    }
}
*/
