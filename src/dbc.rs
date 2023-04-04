// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::{collections::BTreeSet, convert::TryFrom};
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::dbc_id::PublicAddress;
use crate::transaction::{BlindedOutput, DbcTransaction, RevealedAmount, RevealedInput};
use crate::{
    BlindedAmount, DbcContent, DbcId, DerivationIndex, DerivedKey, Error, Hash, MainKey, Result,
    SpentProof, SpentProofKeyVerifier, TransactionVerifier,
};

/// Represents a Digital Bearer Certificate (Dbc).
///
/// A Dbc is like a check. Only the recipient can spend it.
///
/// A Dbc has a PublicAddress representing the recipient of the Dbc.
///
/// An PublicAddress consists of a PublicKey.
/// The user who receives payments to this PublicAddress, will be holding
/// a MainKey - a secret key, which corresponds to the PublicAddress.
///
/// The PublicAddress can be given out to multiple parties and
/// multiple Dbcs can share the same PublicAddress.
///
/// The Spentbook never sees the PublicAddress. Instead, when a
/// transaction output dbc is created for a given PublicAddress, a random
/// derivation index is generated and used to derive a DbcId, which will be
/// used for this new dbc.
///
/// The DbcId is a unique identifier of a Dbc.
/// So there can only ever be one Dbc with that id, previously, now and forever.
/// The DbcId consists of a PublicKey. To unlock the tokens of the Dbc,
/// the corresponding DerivedKey (consists of a SecretKey) must be used.
/// It is derived from the MainKey, in the same way as the DbcId was derived
/// from the PublicAddress to get the DbcId.
///
/// So, there are two important pairs to conceptually be aware of.
/// The MainKey and PublicAddress is a unique pair of a user, where the MainKey
/// is held secret, and the PublicAddress is given to all and anyone who wishes to send tokens to you.
/// A sender of tokens will derive the DbcId from the PublicAddress, which will identify the Dbc that
/// holds the tokens going to the recipient. The sender does this using a derivation index.
/// The recipient of the tokens, will use the same derivation index, to derive the DerivedKey
/// from the MainKey. The DerivedKey and DbcId pair is the second important pair.
/// For an outsider, there is no way to associate either the DerivedKey or the DbcId to the PublicAddress
/// (or for that matter to the MainKey, if they were ever to see it, which they shouldn't of course).
/// Only by having the derivation index, which is only known to sender and recipient, can such a connection be made.
///
/// To spend or work with a Dbc, wallet software must obtain the corresponding
/// MainKey from the user, and then call an API function that accepts a MainKey,
/// eg: `dbc.revealed_amount(&main_key)`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dbc {
    /// The id of this Dbc. It is unique, and there can never
    /// be another Dbc with the same id. It used in SpentProofs.
    pub id: DbcId,
    /// Encrypted information for and about the recipient of this Dbc.
    pub content: DbcContent,
    /// The transaction where this DBC was created
    pub transaction: DbcTransaction,
    /// The transaction's input's SpentProofs
    pub inputs_spent_proofs: BTreeSet<SpentProof>,
    /// The transactions for each inputs
    pub inputs_spent_transactions: BTreeSet<DbcTransaction>,
}

impl Dbc {
    /// Return the id of this Dbc.
    pub fn id(&self) -> DbcId {
        self.id
    }

    // returns public address from which dbc id is derived.
    pub fn public_address(&self) -> &PublicAddress {
        &self.content.public_address
    }

    /// Returns derived dbc key using MainKey supplied by caller.
    /// Will return an error if the supplied MainKey does not match the
    /// Dbc PublicAddress.
    pub fn derived_key(&self, main_key: &MainKey) -> Result<DerivedKey> {
        if &main_key.public_address() != self.public_address() {
            return Err(Error::MainKeyDoesNotMatchPublicAddress);
        }
        Ok(main_key.derive_key(&self.derivation_index(main_key)?))
    }

    /// Return the derivation index that was used to derive DbcId and corresponding DerivedKey of a Dbc.
    pub fn derivation_index(&self, main_key: &MainKey) -> Result<DerivationIndex> {
        self.content.derivation_index(main_key)
    }

    /// Decrypt and return the revealed amount.
    pub fn revealed_amount(&self, main_key: &MainKey) -> Result<RevealedAmount> {
        let derived_key = self.derived_key(main_key)?;
        RevealedAmount::try_from((&derived_key, &self.content.revealed_amount_cipher))
    }

    /// Return the reason (if any) why this Dbc was spent.
    pub fn reason(&self) -> Option<Hash> {
        let reason = self.inputs_spent_proofs.iter().next()?.reason();
        if reason == Hash::default() {
            None
        } else {
            Some(reason)
        }
    }

    /// Return the blinded amount for this Dbc.
    pub fn blinded_amount(&self) -> Result<BlindedAmount> {
        Ok(self
            .transaction
            .outputs
            .iter()
            .find(|o| &self.id() == o.dbc_id())
            .ok_or(Error::BlindedOutputNotFound)?
            .blinded_amount())
    }

    /// Return the input that represents this Dbc for use as
    /// a transaction input.
    pub fn as_revealed_input(&self, main_key: &MainKey) -> Result<RevealedInput> {
        Ok(RevealedInput::new(
            self.derived_key(main_key)?,
            self.revealed_amount(main_key)?,
        ))
    }

    /// Generate the hash of this Dbc
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.to_bytes());
        sha3.update(&self.transaction.hash());

        for sp in self.inputs_spent_proofs.iter() {
            sha3.update(&sp.to_bytes());
        }

        for st in self.inputs_spent_transactions.iter() {
            sha3.update(&st.to_bytes());
        }

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    /// Verifies that this Dbc is valid.
    ///
    /// A Dbc recipient should call this immediately upon receipt.
    ///
    /// important: this will verify there is a matching transaction provided
    /// for each SpentProof, although this does not check if the Dbc has been spent.
    /// For that, one must query the SpentBook.
    ///
    /// Note that the spentbook cannot perform this check.  Only the Dbc
    /// recipient (private key holder) can.
    ///
    /// see TransactionVerifier::verify() for a description of
    /// verifier requirements.
    ///
    /// see comments for Dbc::verify_amounts() for a
    /// description of how to handle Error::BlindedAmountsDoNotMatch
    pub fn verify<K: SpentProofKeyVerifier>(
        &self,
        main_key: &MainKey,
        verifier: &K,
    ) -> Result<(), Error> {
        TransactionVerifier::verify(verifier, &self.transaction, &self.inputs_spent_proofs)?;

        let dbc_id = self.derived_key(main_key)?.dbc_id();

        if !self
            .transaction
            .outputs
            .iter()
            .any(|o| dbc_id.eq(o.dbc_id()))
        {
            return Err(Error::DbcContentNotPresentInTransactionOutput);
        }

        // verify there is a maching transaction for each spent proof
        if !self.inputs_spent_proofs.iter().all(|proof| {
            self.inputs_spent_transactions
                .iter()
                .any(|tx| Hash::from(tx.hash()) == proof.transaction_hash())
        }) {
            return Err(Error::MissingSpentTransaction);
        }

        // verify that all spent_proofs reasons are equal
        let reason = self.reason();
        let reasons_are_equal = |s: &SpentProof| match reason {
            Some(r) => r == s.reason(),
            None => s.reason() == Hash::default(),
        };
        if !self.inputs_spent_proofs.iter().all(reasons_are_equal) {
            return Err(Error::SpentProofShareReasonMismatch(dbc_id));
        }

        self.verify_amounts(main_key)
    }

    /// Deserializes a `Dbc` represented as a hex string to a `Dbc`.
    #[cfg(feature = "serde")]
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let mut bytes =
            hex::decode(hex).map_err(|e| Error::HexDeserializationFailed(e.to_string()))?;
        bytes.reverse();
        let dbc: Dbc = bincode::deserialize(&bytes)
            .map_err(|e| Error::HexDeserializationFailed(e.to_string()))?;
        Ok(dbc)
    }

    /// Serialize this `Dbc` instance to a hex string.
    #[cfg(feature = "serde")]
    pub fn to_hex(&self) -> Result<String, Error> {
        let mut serialized =
            bincode::serialize(&self).map_err(|e| Error::HexSerializationFailed(e.to_string()))?;
        serialized.reverse();
        Ok(hex::encode(serialized))
    }

    /// Checks if the encrypted amount + blinding factor in the Dbc equals
    /// the blinded amount in the transaction.
    /// This is done by
    /// 1. Decrypting the `revealed_amount_cipher` into a RevealedAmount.
    /// 2. Forming a BlindedAmount out of the RevealedAmount.
    /// 3. Comparing that instance with the one in the dbc blinded output in the tx.
    ///
    /// If the blinded amounts do not match, then the Dbc cannot be spent
    /// using the RevealedAmount provided.
    ///
    /// To clarify, the Dbc is still spendable, however the correct
    /// RevealedAmount need to be obtained from the sender somehow.
    ///
    /// As an example, if the Dbc recipient is a merchant, they typically
    /// would not provide goods to the purchaser if this check fails.
    /// However the purchaser may still be able to remedy the situation by
    /// providing the correct RevealedAmount to the merchant.
    ///
    /// If the merchant were to send the goods without first performing
    /// this check, then they could be stuck with an unspendable Dbc
    /// and no recourse.
    pub(crate) fn verify_amounts(&self, main_key: &MainKey) -> Result<()> {
        let revealed_amount: RevealedAmount = self.revealed_amount(main_key)?;
        let blinded_amount = revealed_amount.blinded_amount(&Default::default());
        let blinded_amount_in_tx = self.blinded_output(main_key)?.blinded_amount();

        match blinded_amount == blinded_amount_in_tx {
            true => Ok(()),
            false => Err(Error::BlindedAmountsDoNotMatch),
        }
    }

    /// The blinded output for this Dbc, is found in
    /// the transaction that gave rise to this Dbc.
    fn blinded_output(&self, main_key: &MainKey) -> Result<&BlindedOutput> {
        let dbc_id = self.derived_key(main_key)?.dbc_id();
        self.transaction
            .outputs
            .iter()
            .find(|o| dbc_id.eq(o.dbc_id()))
            .ok_or(Error::BlindedOutputNotFound)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::dbc_id::{random_derivation_index, DbcIdSource};
    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::transaction::{Output, RevealedTransaction};
    use crate::{
        mock,
        rand::{CryptoRng, RngCore},
        DbcBuilder, Hash, SpentProofContent, Token,
    };
    use blsttc::{PublicKey, SecretKey};
    use bulletproofs::PedersenGens;
    use quickcheck_macros::quickcheck;
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    fn divide(amount: Token, n_ways: u8) -> impl Iterator<Item = Token> {
        (0..n_ways).map(move |i| {
            let equal_parts = amount.as_nano() / n_ways as u64;
            let leftover = amount.as_nano() % n_ways as u64;
            let odd_compensation = u64::from((i as u64) < leftover);
            Token::from_nano(equal_parts + odd_compensation)
        })
    }

    fn prepare_even_split(
        derived_key: DerivedKey,
        revealed_amount: RevealedAmount,
        n_ways: u8,
        output_recipients: Vec<DbcIdSource>,
        spentbook_node: &mut mock::SpentBookNode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DbcBuilder> {
        let amount = Token::from_nano(revealed_amount.value());

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_input_by_secrets(derived_key, revealed_amount)
            .add_outputs(divide(amount, n_ways).zip(output_recipients.into_iter()))
            .build(rng)?;

        for (input_id, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(
                    input_id,
                    tx.clone(),
                    Hash::default(),
                )?)
                .add_spent_transaction(tx);
        }

        Ok(dbc_builder)
    }

    #[test]
    fn from_hex_should_deserialize_a_hex_encoded_string_to_a_dbc() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 1_530_000_000;
        let main_key = MainKey::random_from_rng(&mut rng);
        let derivation_index = random_derivation_index(&mut rng);
        let derived_key = main_key.derive_key(&derivation_index);
        let tx_material = RevealedTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
        };
        let (transaction, revealed_amounts) = tx_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");
        let input_content = DbcContent::from((
            &main_key.public_address(),
            &derivation_index,
            revealed_amounts[0].revealed_amount,
        ));
        let dbc = Dbc {
            content: input_content,
            id: derived_key.dbc_id(),
            transaction,
            inputs_spent_proofs: Default::default(),
            inputs_spent_transactions: Default::default(),
        };

        let hex = dbc.to_hex()?;

        let dbc = Dbc::from_hex(&hex)?;
        let amount = dbc.revealed_amount(&main_key)?.value();
        assert_eq!(amount, 1_530_000_000);
        Ok(())
    }

    #[test]
    fn to_hex_should_serialize_a_dbc_to_a_hex_encoded_string() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 100;
        let main_key = MainKey::random_from_rng(&mut rng);
        let derivation_index = random_derivation_index(&mut rng);
        let derived_key = main_key.derive_key(&derivation_index);
        let tx_material = RevealedTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
        };
        let (transaction, revealed_amounts) = tx_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");
        let input_content = DbcContent::from((
            &main_key.public_address(),
            &derivation_index,
            revealed_amounts[0].revealed_amount,
        ));
        let dbc = Dbc {
            id: derived_key.dbc_id(),
            content: input_content,
            transaction,
            inputs_spent_proofs: Default::default(),
            inputs_spent_transactions: Default::default(),
        };

        let hex = dbc.to_hex()?;

        let dbc_from_hex = Dbc::from_hex(&hex)?;
        let left = dbc.revealed_amount(&main_key)?.value();
        let right = dbc_from_hex.revealed_amount(&main_key)?.value();
        assert_eq!(left, right);
        Ok(())
    }

    #[test]
    fn as_revealed_input_should_error_if_dbc_id_is_not_derived_from_main_key() -> Result<(), Error>
    {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let (_, _, (dbc, _)) = generate_dbc_of_value_from_pk_hex(
            100,
            "a14a1887c61f95d5bdf6d674da3032dad77f2168fe6bf5e282aa02394bd45f41f0\
            fe722b61fa94764da42a9b628701db",
            &mut rng,
        )?;
        let sk = get_secret_key_from_hex(
            "d823b03be25ad306ce2c2ef8f67d8a49322ed2a8636de5dbf01f6cc3467dc91e",
        )?;
        let main_key = MainKey::new(sk);
        let result = dbc.as_revealed_input(&main_key);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Main key does not match public address."
        );
        Ok(())
    }

    #[test]
    fn test_dbc_without_inputs_fails_verification() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 100;

        let main_key = MainKey::random_from_rng(&mut rng);
        let derivation_index = random_derivation_index(&mut rng);
        let derived_key = main_key.derive_key(&derivation_index);

        let tx_material = RevealedTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
        };

        let (transaction, revealed_amounts) = tx_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");

        assert_eq!(revealed_amounts.len(), 1);

        let input_content = DbcContent::from((
            &main_key.public_address(),
            &derivation_index,
            revealed_amounts[0].revealed_amount,
        ));

        let dbc = Dbc {
            id: derived_key.dbc_id(),
            content: input_content,
            transaction,
            inputs_spent_proofs: Default::default(),
            inputs_spent_transactions: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let key_manager = mock::KeyManager::from(mock::Signer::from(id));

        assert!(matches!(
            dbc.verify(&main_key, &key_manager),
            Err(Error::Transaction(
                crate::transaction::Error::TransactionMustHaveAnInput
            ))
        ));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[quickcheck]
    fn prop_dbc_verification(
        n_inputs: NonZeroTinyInt,     // # of input DBC's
        n_valid_sigs: TinyInt,        // # of valid sigs
        n_wrong_signer_sigs: TinyInt, // # of valid sigs from unrecognized authority
        n_wrong_msg_sigs: TinyInt,    // # of sigs from recognized authority signing wrong message
        n_extra_input_sigs: TinyInt,  // # of sigs for inputs not part of the transaction
        extra_output_amount: TinyInt, // Artifically increase output dbc value
    ) -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);

        let amount = 100;

        // uncomment to run with specific args.
        // let n_inputs = NonZeroTinyInt(std::num::NonZeroU8::new(3).unwrap());     // # of input DBC's
        // let n_valid_sigs = TinyInt(0);        // # of valid sigs
        // let n_wrong_signer_sigs = TinyInt(0); // # of valid sigs from unrecognized authority
        // let n_wrong_msg_sigs = TinyInt(0);    // # of sigs from recognized authority signing wrong message
        // let n_extra_input_sigs = TinyInt(0);  // # of sigs for inputs not part of the transaction
        // let extra_output_amount = TinyInt(0); // Artifically increase output dbc value

        // first we will issue genesis into outputs (100, GENESIS-100).
        // The 100 output will be our starting_dbc.
        //
        // we do this instead of just using GENESIS_AMOUNT as our starting amount
        // because GENESIS_AMOUNT is u64::MAX (or could be) and later in the test
        // we add extra_output_amount to amount, which would otherwise
        // cause an integer overflow.
        let (mut spentbook_node, _genesis_dbc, starting_dbc, starting_main_key) =
            generate_dbc_and_its_main_key(amount, &mut rng)?;

        let mut output_main_keys: BTreeMap<DbcId, (MainKey, DerivationIndex)> = (0..n_inputs
            .coerce())
            .map(|_| (MainKey::random(), random_derivation_index(&mut rng)))
            .map(|(main_key, derivation_index)| {
                (
                    main_key.derive_key(&derivation_index).dbc_id(),
                    (main_key, derivation_index),
                )
            })
            .collect();
        let output_recipients = output_main_keys
            .values()
            .map(|(main_key, derivation_index)| DbcIdSource {
                public_address: main_key.public_address(),
                derivation_index: *derivation_index,
            })
            .collect();

        let dbc_builder = prepare_even_split(
            starting_dbc.derived_key(&starting_main_key)?,
            starting_dbc.revealed_amount(&starting_main_key)?,
            n_inputs.coerce(),
            output_recipients,
            &mut spentbook_node,
            &mut rng,
        )?;

        let output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        let spent_proofs = output_dbcs
            .iter()
            .map(|x| x.0.inputs_spent_proofs.clone())
            .next()
            .unwrap();
        let sp_first = spent_proofs.iter().next().unwrap();
        assert!(sp_first
            .spentbook_pub_key
            .verify(&sp_first.spentbook_sig, sp_first.content.hash()));

        // The outputs become inputs for next tx.
        let next_inputs: Vec<(Dbc, MainKey)> = output_dbcs
            .into_iter()
            .map(|(dbc, _revealed_amount)| {
                let (main_key, _) = output_main_keys.remove(&dbc.id()).unwrap();
                (dbc, main_key)
            })
            .collect();

        let next_output_main_key = MainKey::random_from_rng(&mut rng);
        let next_output_derivation_index = random_derivation_index(&mut rng);
        let next_output_derived_key =
            next_output_main_key.derive_key(&next_output_derivation_index);

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_inputs_dbc(next_inputs)?
            .add_output(
                Token::from_nano(amount),
                DbcIdSource {
                    public_address: next_output_main_key.public_address(),
                    derivation_index: next_output_derivation_index,
                },
            )
            .build(&mut rng)?;

        for (input_id, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(
                    input_id,
                    tx.clone(),
                    Hash::default(),
                )?)
                .add_spent_transaction(tx);
        }

        // We must obtain the RevealedAmount for our output in order to
        // know the correct blinding factor when creating fuzzed_amt_secrets.
        let next_output = dbc_builder.transaction.outputs.get(0).unwrap();
        let pc_gens = PedersenGens::default();
        let next_output_blinded_and_revealed_amounts: Vec<(BlindedAmount, RevealedAmount)> =
            dbc_builder
                .revealed_outputs
                .iter()
                .map(|next_output| next_output.revealed_amount)
                .map(|r| (r.blinded_amount(&pc_gens), r))
                .collect();
        let revealed_amount_list: Vec<RevealedAmount> = next_output_blinded_and_revealed_amounts
            .iter()
            .filter(|(c, _)| *c == next_output.blinded_amount())
            .map(|(_, r)| *r)
            .collect();

        let fuzzed_revealed_amount = RevealedAmount::from((
            amount + extra_output_amount.coerce::<u64>(),
            revealed_amount_list[0].blinding_factor(),
        ));
        let dbc_amount = fuzzed_revealed_amount.value();

        let fuzzed_content = DbcContent::from((
            &next_output_main_key.public_address(),
            &next_output_derivation_index,
            fuzzed_revealed_amount,
        ));

        let mut next_input_fuzzed_spent_proofs: BTreeSet<SpentProof> = BTreeSet::new();

        let next_input_spent_proofs = dbc_builder.spent_proofs()?;
        next_input_fuzzed_spent_proofs.extend(
            next_input_spent_proofs
                .iter()
                .take(n_valid_sigs.coerce())
                .cloned(),
        );

        let mut repeating_inputs = next_input_spent_proofs
            .iter()
            .cycle()
            // skip the valid sigs so that we don't immediately overwrite them
            .skip(n_valid_sigs.coerce());

        // Invalid spentbook signatures BUT signing correct message
        for _ in 0..n_wrong_signer_sigs.coerce() {
            if let Some(spent_proof) = repeating_inputs.next() {
                let id = crate::bls_dkg_id(&mut rng);
                let key_manager = mock::KeyManager::from(mock::Signer::from(id));
                let sig_share = key_manager.sign(&spent_proof.content.hash());
                let sig = key_manager
                    .public_key_set()
                    .combine_signatures(vec![sig_share.threshold_crypto()])
                    .unwrap();

                let fuzzed_spent_proof = SpentProof {
                    content: spent_proof.content.clone(),
                    spentbook_pub_key: key_manager.public_key_set().public_key(),
                    spentbook_sig: sig,
                };
                // note: existing items may be replaced.
                println!("added wrong signer");
                next_input_fuzzed_spent_proofs.insert(fuzzed_spent_proof);
            }
        }

        // Valid spentbook signatures BUT signing wrong message
        for _ in 0..n_wrong_msg_sigs.coerce() {
            if let Some(spent_proof) = repeating_inputs.next() {
                let wrong_msg_sig_share = spentbook_node.key_manager.sign(&Hash([0u8; 32]));
                let wrong_msg_sig = spentbook_node
                    .key_manager
                    .public_key_set()
                    .combine_signatures(vec![wrong_msg_sig_share.threshold_crypto()])
                    .unwrap();

                let fuzzed_spent_proof = SpentProof {
                    content: spent_proof.content.clone(),
                    spentbook_pub_key: spent_proof.spentbook_pub_key,
                    spentbook_sig: wrong_msg_sig,
                };
                // note: existing items may be replaced.
                next_input_fuzzed_spent_proofs.insert(fuzzed_spent_proof);
            }
        }

        use crate::rand::distributions::{Distribution, Standard};

        // Valid spentbook signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            if let Some(spent_proof) = repeating_inputs.next() {
                let secret_key: SecretKey = Standard.sample(&mut rng);
                let derived_key = DerivedKey::new(secret_key);

                let content = SpentProofContent {
                    dbc_id: derived_key.dbc_id(),
                    transaction_hash: spent_proof.transaction_hash(),
                    reason: Hash::default(),
                    blinded_amount: *spent_proof.blinded_amount(),
                };

                let sig_share = spentbook_node.key_manager.sign(&content.hash());
                let sig = spentbook_node
                    .key_manager
                    .public_key_set()
                    .combine_signatures(vec![sig_share.threshold_crypto()])
                    .unwrap();

                let fuzzed_sp = SpentProof {
                    content,
                    spentbook_pub_key: spent_proof.spentbook_pub_key,
                    spentbook_sig: sig,
                };
                next_input_fuzzed_spent_proofs.insert(fuzzed_sp);
            }
        }

        let next_inputs_spent_transactions =
            dbc_builder.spent_transactions.values().cloned().collect();
        let dbcs = dbc_builder.build(&spentbook_node.key_manager)?;
        let (dbc_valid, ..) = &dbcs[0];

        let dbc = Dbc {
            id: next_output_derived_key.dbc_id(),
            content: fuzzed_content,
            transaction: dbc_valid.transaction.clone(),
            inputs_spent_proofs: next_input_fuzzed_spent_proofs,
            inputs_spent_transactions: next_inputs_spent_transactions,
        };

        let key_manager = &spentbook_node.key_manager;
        let verification_res = dbc.verify(&next_output_main_key, key_manager);

        let dbc_id = dbc.derived_key(&next_output_main_key)?.dbc_id();

        match verification_res {
            Ok(()) => {
                assert!(dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| dbc_id.eq(o.dbc_id())));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);

                assert_eq!(dbc_amount, amount);
                assert_eq!(extra_output_amount.coerce::<u8>(), 0);
            }
            Err(Error::SpentProofInputLenMismatch { current, expected }) => {
                assert_ne!(dbc.inputs_spent_proofs.len(), dbc.transaction.inputs.len());
                assert_eq!(dbc.inputs_spent_proofs.len(), current);
                assert_eq!(dbc.transaction.inputs.len(), expected);
            }
            Err(Error::SpentProofInputIdMismatch) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| dbc_id.eq(o.dbc_id())));
            }
            Err(Error::Transaction(crate::transaction::Error::TransactionMustHaveAnInput)) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::BlindedAmountsDoNotMatch) => {
                assert_ne!(amount, dbc_amount);
                assert_ne!(extra_output_amount, TinyInt(0));
            }
            Err(Error::InvalidSpentProofSignature(_) | Error::FailedKnownKeyCheck(_)) => {
                // could be a wrong signer (unrecognized authority) or wrong msg.
                assert!(n_wrong_signer_sigs.coerce::<u8>() + n_wrong_msg_sigs.coerce::<u8>() > 0);

                // if we are certain it was wrong signer, then we can verify spentbook's key manager
                // does not trust the signer.
                if n_wrong_signer_sigs.coerce::<u8>() > 0 && n_wrong_msg_sigs.coerce::<u8>() == 0 {
                    for sp in dbc.inputs_spent_proofs.iter() {
                        println!("pk: {:?}", sp.spentbook_pub_key);
                    }
                    assert!(dbc
                        .inputs_spent_proofs
                        .iter()
                        .any(|sp| key_manager.verify_known_key(&sp.spentbook_pub_key).is_err()));
                }
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        Ok(())
    }

    pub(crate) fn generate_dbc_of_value_from_pk_hex(
        amount: u64,
        pk_hex: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, (Dbc, Dbc))> {
        let pk_bytes =
            hex::decode(pk_hex).map_err(|e| Error::HexDeserializationFailed(e.to_string()))?;
        let pk_bytes: [u8; blsttc::PK_SIZE] = pk_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
            panic!(
                "Expected vec of length {} but received vec of length {}",
                blsttc::PK_SIZE,
                v.len()
            )
        });
        let pk = PublicKey::from_bytes(pk_bytes)?;
        let public_address = PublicAddress::new(pk);
        generate_dbc_of_value(amount, public_address, rng)
    }

    pub(crate) fn generate_dbc_and_its_main_key(
        amount: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, Dbc, MainKey)> {
        let output_main_key = MainKey::random_from_rng(rng);
        let output_public_address = output_main_key.public_address();
        let (sb_node, genesis_dbc, (output_dbc, _change)) =
            generate_dbc_of_value(amount, output_public_address, rng)?;
        Ok((sb_node, genesis_dbc, output_dbc, output_main_key))
    }

    fn generate_dbc_of_value(
        amount: u64,
        recipient: PublicAddress,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, (Dbc, Dbc))> {
        let (mut spentbook_node, genesis_dbc, genesis_material, _revealed_amount) =
            mock::GenesisBuilder::init_genesis_single(rng)?;

        let output_amounts = vec![
            Token::from_nano(amount),
            Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount),
        ];

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis_material.derived_key,
                genesis_dbc.revealed_amount(&genesis_material.main_key)?,
            )
            .add_outputs(output_amounts.into_iter().map(|amount| {
                (
                    amount,
                    DbcIdSource {
                        public_address: recipient,
                        derivation_index: random_derivation_index(rng),
                    },
                )
            }))
            .build(rng)?;

        for (input_id, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(
                    input_id,
                    tx.clone(),
                    Hash::default(),
                )?)
                .add_spent_transaction(tx);
        }

        let mut iter = dbc_builder.build(&spentbook_node.key_manager)?.into_iter();
        let (starting_dbc, ..) = iter.next().unwrap();
        let (change_dbc, ..) = iter.next().unwrap();

        Ok((spentbook_node, genesis_dbc, (starting_dbc, change_dbc)))
    }

    fn get_secret_key_from_hex(sk_hex: &str) -> Result<SecretKey, Error> {
        let sk_bytes =
            hex::decode(sk_hex).map_err(|e| Error::HexDeserializationFailed(e.to_string()))?;
        let mut sk_bytes: [u8; blsttc::SK_SIZE] =
            sk_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
                panic!(
                    "Expected vec of length {} but received vec of length {}",
                    blsttc::SK_SIZE,
                    v.len()
                )
            });
        sk_bytes.reverse();
        Ok(SecretKey::from_bytes(sk_bytes)?)
    }
}
