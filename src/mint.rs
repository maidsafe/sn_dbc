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
    Amount, Dbc, DbcContent, DbcEnvelope, DbcTransaction, Denomination, Error, KeyManager,
    PublicKey, PublicKeySet, Result, SpendKey, SpentProof,
};
use blsbs::{SignedEnvelopeShare, SlipPreparer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    iter::FromIterator,
};

pub fn genesis_dbc_input() -> SpendKey {
    use blsttc::group::CurveProjective;
    let gen_bytes = blsttc::convert::g1_to_be_bytes(blsttc::G1::one());
    SpendKey(PublicKey::from_bytes(gen_bytes).unwrap())
}

#[derive(Debug, Clone)]
pub struct GenesisDbcShare {
    pub dbc_content: DbcContent,
    pub transaction: DbcTransaction,
    pub slip_preparer: SlipPreparer,
    pub public_key_set: PublicKeySet,
    pub signed_envelope_share: SignedEnvelopeShare,
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueTransaction {
    pub inputs: HashSet<Dbc>,
    pub outputs: HashSet<DbcEnvelope>,
}

impl ReissueTransaction {
    pub fn blinded(&self) -> DbcTransaction {
        DbcTransaction {
            inputs: BTreeSet::from_iter(self.inputs.iter().map(Dbc::spend_key)),
            outputs: self.outputs.clone(),
        }
    }

    pub fn validate<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        // notes:
        //  1. validate_balance() ensures that sum(input.denomination) = sum(output.denomination)
        //  2. validate_input_dbcs() ensures that each input dbc has signature corresponding to
        //         mint_master_pk.derive_child(input.denomination).
        //         In other words: that the input denomination is correct and that the mint signed
        //         the Dbc.
        //  3. Because of (2) we can trust (1)
        self.validate_balance()?;
        self.validate_input_dbcs(verifier)?;
        Ok(())
    }

    fn validate_balance(&self) -> Result<()> {
        let i_amounts = self.inputs.iter().map(|d| d.denomination().amount());
        let inputs = Amount::checked_sum(i_amounts)?;

        let o_amounts = self.outputs.iter().map(|o| o.denomination.amount());
        let outputs = Amount::checked_sum(o_amounts)?;

        if inputs != outputs {
            Err(Error::DbcReissueRequestDoesNotBalance)
        } else {
            Ok(())
        }
    }

    fn validate_input_dbcs<K: KeyManager>(&self, verifier: &K) -> Result<()> {
        if self.inputs.is_empty() {
            return Err(Error::TransactionMustHaveAnInput);
        }

        for input in self.inputs.iter() {
            input.confirm_valid(verifier)?;
        }

        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueRequest {
    pub transaction: ReissueTransaction,
    pub spent_proofs: BTreeMap<SpendKey, SpentProof>,
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct ReissueShare {
    pub dbc_transaction: DbcTransaction,
    pub signed_envelope_shares: Vec<SignedEnvelopeShare>, // fixme: Vec does not guarantee uniqueness.
    pub public_key_set: PublicKeySet,
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

    pub fn issue_genesis_dbc(&mut self, denomination: Denomination) -> Result<GenesisDbcShare> {
        let slip_preparer = SlipPreparer::from_fr(1); // deterministic/known
        let dbc_content = DbcContent::new(
            self.key_manager
                .public_key_set()
                .map_err(|e| Error::Signing(e.to_string()))?
                .public_key(),
            denomination,
        );

        let envelope = slip_preparer.place_slip_in_envelope(&dbc_content.slip());
        let dbc_envelope = DbcEnvelope {
            envelope,
            denomination: dbc_content.denomination(),
        };

        let transaction = DbcTransaction {
            inputs: BTreeSet::from_iter([genesis_dbc_input()]),
            outputs: HashSet::from_iter([dbc_envelope.clone()]),
        };

        let signed_envelope_share = self.sign_output_envelope(dbc_envelope)?;

        Ok(GenesisDbcShare {
            dbc_content,
            transaction,
            slip_preparer,
            public_key_set: self
                .key_manager
                .public_key_set()
                .map_err(|e| Error::Signing(e.to_string()))?,
            signed_envelope_share,
        })
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    pub fn reissue(&mut self, reissue_req: ReissueRequest) -> Result<ReissueShare> {
        reissue_req.transaction.validate(self.key_manager())?;
        let transaction = reissue_req.transaction.blinded();
        let transaction_hash = transaction.hash();

        // Validate that each input has not yet been spent.
        for input in reissue_req.transaction.inputs.iter() {
            match reissue_req.spent_proofs.get(&input.spend_key()) {
                Some(proof) => proof.validate(input, transaction_hash, self.key_manager())?,
                None => return Err(Error::MissingSpentProof(input.spend_key())),
            }
        }

        let signed_envelope_shares = self.sign_output_envelopes(transaction.outputs.clone())?;

        let public_key_set = self
            .key_manager
            .public_key_set()
            .map_err(|e| Error::Signing(e.to_string()))?;

        let reissue_share = ReissueShare {
            dbc_transaction: transaction,
            signed_envelope_shares,
            public_key_set,
        };

        Ok(reissue_share)
    }

    fn sign_output_envelope(&self, output: DbcEnvelope) -> Result<SignedEnvelopeShare> {
        self.key_manager
            .sign_envelope(output.envelope, output.denomination)
            .map_err(|e| Error::Signing(e.to_string()))
    }

    fn sign_output_envelopes(
        &self,
        outputs: impl IntoIterator<Item = DbcEnvelope>,
    ) -> Result<Vec<SignedEnvelopeShare>> {
        outputs
            .into_iter()
            .map(|e| self.sign_output_envelope(e))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use serde::Serialize;

    use crate::{
        tests::{TinyInt, TinyUint, TinyVec},
        Amount, DbcBuilder, Output, PowerOfTen, ReissueRequestBuilder, SimpleKeyManager,
        SimpleSigner, SpentProofShare, TransactionBuilder,
    };

    const GENESIS_DENOMINATION: Denomination = Denomination::One(8);

    /// Serialize anything serializable as big endian bytes
    fn to_be_bytes<T: Serialize>(sk: &T) -> Vec<u8> {
        bincode::serialize(&sk).unwrap()
    }

    #[quickcheck]
    fn prop_genesis() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis = genesis_node.issue_genesis_dbc(GENESIS_DENOMINATION)?;

        let ses = &genesis.signed_envelope_share;

        // note: logically speaking, it seems we should derive the denomination
        //       pubkey here (and it works) however that turns out not to be
        //       necessary, so we skip the extra ::derive_child() call.
        let mint_denomination_signature = genesis.public_key_set.combine_signatures(vec![(
            ses.signature_share_index(),
            &ses.signature_share_for_slip(genesis.slip_preparer.blinding_factor())?,
        )])?;

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            mint_public_key: genesis.public_key_set.public_key(),
            mint_denomination_signature,
        };

        assert_eq!(genesis_dbc.denomination(), GENESIS_DENOMINATION);
        let validation = genesis_dbc.confirm_valid(genesis_node.key_manager());
        assert!(validation.is_ok());

        Ok(())
    }

    #[quickcheck]
    fn prop_splitting_the_genesis_dbc(output_amounts: TinyVec<TinyInt>) -> Result<(), Error> {
        let output_denominations = Vec::from_iter(
            output_amounts
                .into_iter()
                .map(TinyInt::coerce::<PowerOfTen>)
                .map(Denomination::One),
        );
        let output_amount =
            Amount::checked_sum(output_denominations.iter().map(Denomination::amount))?;

        let genesis_owner = crate::bls_dkg_id();
        let genesis_key = genesis_owner.public_key_set.public_key();
        let key_manager =
            SimpleKeyManager::new(SimpleSigner::from(genesis_owner.clone()), genesis_key);
        let mut genesis_node = MintNode::new(key_manager.clone());

        let genesis_denomination = Denomination::least_upper_bound(output_amount).unwrap();

        let genesis = genesis_node.issue_genesis_dbc(genesis_denomination)?;
        let ses = &genesis.signed_envelope_share;

        let genesis_sig = genesis.public_key_set.combine_signatures(vec![(
            ses.signature_share_index(),
            &ses.signature_share_for_slip(genesis.slip_preparer.blinding_factor())?,
        )])?;

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            mint_public_key: genesis.public_key_set.public_key(),
            mint_denomination_signature: genesis_sig,
        };

        let output_owner = crate::bls_dkg_id();
        let output_owner_pk = output_owner.public_key_set.public_key();

        let mut tx_builder = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_outputs(output_denominations.iter().map(|d| crate::Output {
                denomination: *d,
                owner: output_owner_pk,
            }));

        let mut change_amount = Amount::new_unchecked(0, 1);
        let change_denominations = if genesis_denomination.amount() > output_amount {
            change_amount = genesis_denomination.amount().checked_sub(output_amount)?;
            let change_denominations = Denomination::make_change(change_amount);
            let change_outputs =
                Vec::from_iter(change_denominations.iter().map(|d| crate::Output {
                    denomination: *d,
                    owner: genesis_key,
                }));
            tx_builder = tx_builder.add_outputs(change_outputs);
            change_denominations
        } else {
            Default::default()
        };

        let (reissue_tx, output_secrets) = tx_builder.build()?;
        let tx_hash = reissue_tx.blinded().hash();

        let spent_sig = genesis_owner.public_key_set.combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(tx_hash),
        )])?;
        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node
            .key_manager
            .sign(&SpentProof::proof_msg(&tx_hash, &spent_sig))?;

        let rr = ReissueRequestBuilder::new(reissue_tx.clone())
            .add_spent_proof_share(
                genesis_dbc.spend_key(),
                SpentProofShare {
                    spent_sig,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            )
            .build()?;

        let reissue_share = match genesis_node.reissue(rr) {
            Ok(rs) => {
                // Verify that at least one output was present.
                assert_ne!(reissue_tx.outputs.len(), 0);
                rs
            }
            Err(e) => return Err(e),
        };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(reissue_tx);
        dbc_builder = dbc_builder.add_output_secrets(output_secrets);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        let mut expected_denom_count: BTreeMap<Denomination, i64> = Default::default();

        for d in output_denominations.into_iter().chain(change_denominations) {
            let c = expected_denom_count.entry(d).or_default();
            *c += 1;
        }

        for dbc in output_dbcs.iter() {
            let count = expected_denom_count.entry(dbc.denomination()).or_default();
            *count -= 1;

            assert!(dbc.confirm_valid(&key_manager).is_ok());
        }

        for (_, count) in expected_denom_count {
            assert_eq!(count, 0)
        }

        assert_eq!(
            Amount::checked_sum(output_dbcs.iter().map(|dbc| dbc.denomination().amount()))?
                .checked_sub(change_amount)?,
            output_amount
        );

        Ok(())
    }

    #[test]
    fn reissue_genesis_multi_output() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis = genesis_node.issue_genesis_dbc(GENESIS_DENOMINATION)?;

        let ses = &genesis.signed_envelope_share;

        let genesis_sig = genesis.public_key_set.combine_signatures(vec![(
            ses.signature_share_index(),
            &ses.signature_share_for_slip(genesis.slip_preparer.blinding_factor())?,
        )])?;

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            mint_public_key: genesis.public_key_set.public_key(),
            mint_denomination_signature: genesis_sig,
        };

        assert!(genesis_dbc
            .confirm_valid(genesis_node.key_manager())
            .is_ok());

        let pay_amt = Amount::new(1, 1)?;
        let pay_denoms = Denomination::make_change(pay_amt);
        let pay_outputs: Vec<Output> = pay_denoms
            .iter()
            .map(|d| Output {
                denomination: *d,
                owner: genesis_owner.public_key_set.public_key(),
            })
            .collect();
        let change_amt = GENESIS_DENOMINATION.amount().checked_sub(pay_amt)?;
        let change_denoms = Denomination::make_change(change_amt);
        let change_outputs: Vec<Output> = change_denoms
            .iter()
            .map(|d| Output {
                denomination: *d,
                owner: genesis_owner.public_key_set.public_key(),
            })
            .collect();

        let num_outputs = pay_outputs.len() + change_outputs.len();

        let (reissue_tx, output_secrets) = TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_outputs(pay_outputs)
            .add_outputs(change_outputs)
            .build()?;
        let tx_hash = reissue_tx.blinded().hash();

        let spent_sig = genesis_owner.public_key_set.combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(tx_hash),
        )])?;
        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node
            .key_manager
            .sign(&SpentProof::proof_msg(&tx_hash, &spent_sig))?;

        let rr = ReissueRequestBuilder::new(reissue_tx.clone())
            .add_spent_proof_share(
                genesis_dbc.spend_key(),
                SpentProofShare {
                    spent_sig,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            )
            .build()?;

        let rs = genesis_node.reissue(rr)?;

        let dbcs = DbcBuilder::new(reissue_tx)
            .add_output_secrets(output_secrets)
            .add_reissue_share(rs)
            .build()?;

        // Just to give us a rough idea of the DBC size.
        // note that bincode typically adds some bytes.
        // todo: add a Dbc::to_bytes() method.
        let bytes = to_be_bytes(&dbcs[0]);
        println!("Dbc outputs count: {:?}", dbcs.len());
        println!("Dbc size: {:?}", bytes.len());

        let outputs_sum = Amount::checked_sum(dbcs.iter().map(|d| d.denomination().amount()))?;

        assert_eq!(dbcs.len(), num_outputs);
        assert_ne!(dbcs[0].spend_key(), genesis_dbc.spend_key());
        assert_eq!(outputs_sum, GENESIS_DENOMINATION.amount());

        Ok(())
    }

    #[test]
    fn reissue_genesis_and_child() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();

        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis = genesis_node.issue_genesis_dbc(GENESIS_DENOMINATION)?;

        let ses = &genesis.signed_envelope_share;

        let genesis_sig = genesis.public_key_set.combine_signatures(vec![(
            ses.signature_share_index(),
            &ses.signature_share_for_slip(genesis.slip_preparer.blinding_factor())?,
        )])?;

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            mint_public_key: genesis.public_key_set.public_key(),
            mint_denomination_signature: genesis_sig,
        };

        // 1. Reissue Genesis DBC to A

        let (tx, output_secrets) = TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_output(Output {
                denomination: GENESIS_DENOMINATION,
                owner: genesis_owner.public_key_set.public_key(),
            })
            .build()?;

        let tx_hash = tx.blinded().hash();

        let spent_sig = genesis_owner.public_key_set.combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(tx_hash),
        )])?;
        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node
            .key_manager
            .sign(&SpentProof::proof_msg(&tx_hash, &spent_sig))?;

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

        let rs = genesis_node.reissue(rr)?;

        let dbcs = DbcBuilder::new(tx)
            .add_output_secrets(output_secrets)
            .add_reissue_share(rs)
            .build()?;

        // 2. Reissue A to B

        let dbc_a = &dbcs[0];

        let (tx, output_secrets) = TransactionBuilder::default()
            .add_input(dbc_a.clone())
            .add_output(Output {
                denomination: GENESIS_DENOMINATION,
                owner: genesis_owner.public_key_set.public_key(),
            })
            .build()?;

        let tx_hash = tx.blinded().hash();

        let spent_sig = genesis_owner.public_key_set.combine_signatures([(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&dbc_a.spend_key_index())
                .sign(tx_hash),
        )])?;
        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node
            .key_manager
            .sign(&SpentProof::proof_msg(&tx_hash, &spent_sig))?;

        let rr = ReissueRequestBuilder::new(tx.clone())
            .add_spent_proof_share(
                dbc_a.spend_key(),
                SpentProofShare {
                    spent_sig,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            )
            .build()?;

        let rs = genesis_node.reissue(rr)?;

        let dbcs = DbcBuilder::new(tx)
            .add_output_secrets(output_secrets)
            .add_reissue_share(rs)
            .build()?;

        assert_eq!(dbcs.len(), 1);
        assert_eq!(dbcs[0].denomination(), genesis_dbc.denomination());

        Ok(())
    }

    #[quickcheck]
    #[ignore]
    fn prop_dbc_transaction_many_to_many(
        // the amount of each input transaction
        input_amounts: TinyVec<TinyInt>,
        // The amount for each transaction output
        output_amounts: TinyVec<TinyInt>,
        // Include a valid SpentProof for the following inputs
        valid_spent_proofs: TinyVec<TinyUint>,
        // Include an invalid SpentProofs for the following inputs
        invalid_spent_proofs: TinyVec<TinyUint>,
    ) -> Result<(), Error> {
        let input_denominations = Vec::from_iter(
            input_amounts
                .into_iter()
                .map(TinyInt::coerce::<PowerOfTen>)
                .map(Denomination::One),
        );

        let output_denominations = Vec::from_iter(
            output_amounts
                .into_iter()
                .map(TinyInt::coerce::<PowerOfTen>)
                .map(Denomination::One),
        );

        let valid_spent_proofs = BTreeSet::from_iter(
            valid_spent_proofs
                .into_iter()
                .map(TinyUint::coerce::<usize>),
        );

        let invalid_spent_proofs = BTreeSet::from_iter(
            invalid_spent_proofs
                .into_iter()
                .map(TinyUint::coerce::<usize>),
        );

        let genesis_owner = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let genesis_amount =
            Amount::checked_sum(input_denominations.iter().map(Denomination::amount))?;
        let genesis_denomination = Denomination::least_upper_bound(genesis_amount).unwrap();
        let genesis = genesis_node.issue_genesis_dbc(genesis_denomination)?;

        let ses = &genesis.signed_envelope_share;

        let genesis_sig = genesis.public_key_set.combine_signatures(vec![(
            ses.signature_share_index(),
            &ses.signature_share_for_slip(genesis.slip_preparer.blinding_factor())?,
        )])?;

        let genesis_dbc = Dbc {
            content: genesis.dbc_content,
            mint_public_key: genesis_node.key_manager.public_key_set()?.public_key(),
            mint_denomination_signature: genesis_sig,
        };

        let owner_denominations_and_keys =
            BTreeMap::from_iter(input_denominations.iter().copied().map(|d| {
                let owner = crate::bls_dkg_id();
                (owner.public_key_set.public_key(), (d, owner))
            }));

        let (reissue_tx, _) = crate::TransactionBuilder::default()
            .add_input(genesis_dbc.clone())
            .add_outputs(
                owner_denominations_and_keys
                    .iter()
                    .map(|(o, (d, _))| crate::Output {
                        denomination: *d,
                        owner: *o,
                    }),
            )
            .build()?;

        let spent_sig = genesis_owner.public_key_set.combine_signatures(vec![(
            genesis_owner.index,
            genesis_owner
                .secret_key_share
                .derive_child(&genesis_dbc.spend_key_index())
                .sign(reissue_tx.blinded().hash()),
        )])?;
        let spentbook_pks = genesis_node.key_manager.public_key_set()?;
        let spentbook_sig_share = genesis_node.key_manager.sign(&SpentProof::proof_msg(
            &reissue_tx.blinded().hash(),
            &spent_sig,
        ))?;

        let rr1 = ReissueRequestBuilder::new(reissue_tx)
            .add_spent_proof_share(
                genesis_dbc.spend_key(),
                SpentProofShare {
                    spent_sig,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            )
            .build()?;

        let reissue_share = match genesis_node.reissue(rr1.clone()) {
            Ok(rs) => {
                // Verify that at least one input (output in this tx) was present.
                assert!(!input_denominations.is_empty());
                rs
            }
            Err(Error::DbcReissueRequestDoesNotBalance) => {
                // Verify that no inputs (outputs in this tx) were present and we got correct validation error.
                assert!(input_denominations.is_empty());
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        // Aggregate ReissueShare to build output DBCs
        let mut dbc_builder = DbcBuilder::new(rr1.transaction);
        dbc_builder = dbc_builder.add_reissue_share(reissue_share);
        let output_dbcs = dbc_builder.build()?;

        let input_dbcs = output_dbcs;

        let outputs_owner = crate::bls_dkg_id();

        let (reissue_tx, _) = crate::TransactionBuilder::default()
            .add_inputs(input_dbcs)
            .add_outputs(output_denominations.iter().map(|d| crate::Output {
                denomination: *d,
                owner: outputs_owner.public_key_set.public_key(),
            }))
            .build()?;

        let dbc_output_denominations =
            Vec::from_iter(reissue_tx.outputs.iter().map(|o| o.denomination));
        let output_total_amount =
            Amount::checked_sum(dbc_output_denominations.iter().map(Denomination::amount))?;

        let mut rr2_builder = ReissueRequestBuilder::new(reissue_tx.clone());

        for (_, in_dbc) in reissue_tx
            .inputs
            .iter()
            .enumerate()
            .filter(|(i, _)| valid_spent_proofs.contains(i))
        {
            let (_, input_owner) = &owner_denominations_and_keys[&in_dbc.owner()];

            let spent_sig = input_owner.public_key_set.combine_signatures([(
                input_owner.index,
                input_owner
                    .secret_key_share
                    .derive_child(&in_dbc.spend_key_index())
                    .sign(reissue_tx.blinded().hash()),
            )])?;
            let spentbook_pks = genesis_node.key_manager.public_key_set()?;
            let spentbook_sig_share = genesis_node.key_manager.sign(&SpentProof::proof_msg(
                &reissue_tx.blinded().hash(),
                &spent_sig,
            ))?;

            rr2_builder = rr2_builder.add_spent_proof_share(
                in_dbc.spend_key(),
                SpentProofShare {
                    spent_sig,
                    spentbook_pks,
                    spentbook_sig_share,
                },
            );
        }

        for (i, in_dbc) in reissue_tx
            .inputs
            .iter()
            .enumerate()
            .filter(|(i, _)| invalid_spent_proofs.contains(i))
        {
            let input_owner = if i % 2 == 0 {
                let (_, input_owner) = &owner_denominations_and_keys[&in_dbc.owner()];
                input_owner.clone()
            } else {
                crate::bls_dkg_id()
            };

            let spent_sig = input_owner.public_key_set.combine_signatures([(
                input_owner.index,
                input_owner
                    .secret_key_share
                    .derive_child(&in_dbc.spend_key_index())
                    .sign(reissue_tx.blinded().hash()),
            )])?;

            let tx_hash = if i % 2 == 1 {
                reissue_tx.blinded().hash()
            } else {
                crate::Hash([0u8; 32])
            };

            let spentbook_pks = genesis_node.key_manager.public_key_set()?;
            let spentbook_sig_share = genesis_node
                .key_manager
                .sign(&SpentProof::proof_msg(&tx_hash, &spent_sig))?;

            rr2_builder = rr2_builder.add_spent_proof_share(
                in_dbc.spend_key(),
                SpentProofShare {
                    spent_sig,
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
                    .all(|i| i >= &reissue_tx.inputs.len()));
                assert!(
                    BTreeSet::from_iter(0..reissue_tx.inputs.len()).is_subset(&valid_spent_proofs)
                );

                assert_eq!(
                    BTreeSet::from_iter(dbc_output_denominations),
                    BTreeSet::from_iter(output_denominations)
                );

                // Aggregate ReissueShare to build output DBCs
                let mut dbc_builder = DbcBuilder::new(reissue_tx);
                dbc_builder = dbc_builder.add_reissue_share(rs);
                let output_dbcs = dbc_builder.build()?;

                for dbc in output_dbcs.iter() {
                    let dbc_confirm_result = dbc.confirm_valid(&genesis_node.key_manager);
                    assert!(dbc_confirm_result.is_ok());
                }

                assert_eq!(
                    Amount::checked_sum(output_dbcs.iter().map(|dbc| dbc.denomination().amount()))?,
                    output_total_amount
                );
            }
            Err(Error::DbcReissueRequestDoesNotBalance { .. }) => {
                if genesis_amount == output_total_amount {
                    // This can correctly occur if there are 0 outputs and inputs sum to zero.
                    //
                    // The error occurs because there is no output with a commitment
                    // to match against the input commitment, and also no way to
                    // know that the input amount is zero.
                    assert!(output_denominations.is_empty());
                    assert_eq!(
                        Amount::checked_sum(input_denominations.iter().map(Denomination::amount))?,
                        Amount::new_unchecked(0, 1)
                    );
                    assert!(!input_denominations.is_empty());
                }
            }
            Err(Error::TransactionMustHaveAnInput) => {
                assert_eq!(input_denominations.len(), 0);
            }
            Err(Error::MissingSpentProof(key)) => {
                let idx = reissue_tx
                    .inputs
                    .iter()
                    .position(|i| i.spend_key() == key)
                    .unwrap();
                assert!(!valid_spent_proofs.contains(&idx));
            }
            Err(Error::InvalidSpentProofSignature(key)) => {
                let idx = reissue_tx
                    .inputs
                    .iter()
                    .position(|i| i.spend_key() == key)
                    .unwrap();
                assert!(invalid_spent_proofs.contains(&idx));
            }
            err => panic!("Unexpected reissue err {:#?}", err),
        }

        Ok(())
    }

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

    #[test]
    fn test_inputs_are_validated() -> Result<(), Error> {
        let genesis_owner = crate::bls_dkg_id();
        let key_manager = SimpleKeyManager::new(
            SimpleSigner::from(genesis_owner.clone()),
            genesis_owner.public_key_set.public_key(),
        );
        let mut genesis_node = MintNode::new(key_manager);

        let input_owner = crate::bls_dkg_id();
        let input_content = DbcContent::new(
            input_owner.public_key_set.public_key(),
            Denomination::One(100),
        );

        let in_dbc = Dbc {
            content: input_content,
            mint_public_key: input_owner.public_key_set.public_key(),
            mint_denomination_signature: input_owner
                .public_key_set
                .combine_signatures([(0, input_owner.secret_key_share.sign(&[0u8; 32]))])?,
        };

        let preparer = SlipPreparer::from_fr(1);
        let fraudulant_reissue_result = genesis_node.reissue(ReissueRequest {
            transaction: ReissueTransaction {
                inputs: HashSet::from_iter([in_dbc]),
                outputs: HashSet::from_iter([DbcEnvelope {
                    envelope: preparer.place_slip_in_envelope(
                        &DbcContent::new(
                            crate::bls_dkg_id().public_key_set.public_key(),
                            Denomination::One(100),
                        )
                        .slip(),
                    ),
                    denomination: Denomination::One(100),
                }]),
            },
            spent_proofs: Default::default(),
        });
        assert!(fraudulant_reissue_result.is_err());

        Ok(())
    }
}
