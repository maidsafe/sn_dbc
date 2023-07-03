// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dbc_id::PublicAddress, transaction::DbcTransaction, DbcCiphers, DbcId, DerivationIndex,
    DerivedKey, Error, FeeOutput, Hash, MainKey, Result, SignedSpend, Token,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tiny_keccak::{Hasher, Sha3};

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
/// The spentbook nodes never sees the PublicAddress. Instead, when a
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
/// eg: `dbc.derivation_index(&main_key)`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(custom_debug::Debug, Clone, Eq, PartialEq)]
pub struct Dbc {
    /// The id of this Dbc. It is unique, and there can never
    /// be another Dbc with the same id. It used in SignedSpends.
    pub id: DbcId,
    /// The transaction where this DBC was created.
    #[debug(skip)]
    pub src_tx: DbcTransaction,
    /// Encrypted information for and about the recipient of this Dbc.
    #[debug(skip)]
    pub ciphers: DbcCiphers,
    /// The transaction's input's SignedSpends
    pub signed_spends: BTreeSet<SignedSpend>,
}

impl Dbc {
    /// Return the id of this Dbc.
    pub fn id(&self) -> DbcId {
        self.id
    }

    // Return PublicAddress from which DbcId is derived.
    pub fn public_address(&self) -> &PublicAddress {
        &self.ciphers.public_address
    }

    /// Return DerivedKey using MainKey supplied by caller.
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
        self.ciphers.derivation_index(main_key)
    }

    /// Return the fee output used in the source transaction
    pub fn fee_output(&self) -> &FeeOutput {
        &self.src_tx.fee
    }

    /// Return the reason why this Dbc was spent.
    /// Will be the default Hash (empty) if reason is none.
    pub fn reason(&self) -> Hash {
        self.signed_spends
            .iter()
            .next()
            .map(|c| c.reason())
            .unwrap_or_default()
    }

    /// Return the Tokens for this Dbc.
    pub fn token(&self) -> Result<Token> {
        Ok(self
            .src_tx
            .outputs
            .iter()
            .find(|o| &self.id() == o.dbc_id())
            .ok_or(Error::OutputNotFound)?
            .token)
    }

    /// Generate the hash of this Dbc
    pub fn hash(&self) -> Hash {
        let mut sha3 = Sha3::v256();
        sha3.update(self.src_tx.hash().as_ref());
        sha3.update(&self.ciphers.to_bytes());

        for sp in self.signed_spends.iter() {
            sha3.update(&sp.to_bytes());
        }

        sha3.update(self.reason().as_ref());
        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        Hash::from(hash)
    }

    /// Verifies that this Dbc is valid.
    ///
    /// A Dbc recipient should call this immediately upon receipt.
    ///
    /// important: this will verify there is a matching transaction provided
    /// for each SignedSpend, although this does not check if the Dbc has been spent.
    /// For that, one must query the spentbook nodes.
    ///
    /// Note that the spentbook nodes cannot perform this check.  Only the Dbc
    /// recipient (private key holder) can.
    ///
    /// see TransactionVerifier::verify() for a description of
    /// verifier requirements.
    pub fn verify(&self, main_key: &MainKey) -> Result<(), Error> {
        self.src_tx
            .verify_against_inputs_spent(&self.signed_spends)?;

        let dbc_id = self.derived_key(main_key)?.dbc_id();
        if !self.src_tx.outputs.iter().any(|o| dbc_id.eq(o.dbc_id())) {
            return Err(Error::DbcCiphersNotPresentInTransactionOutput);
        }

        // verify that all signed_spend reasons are equal
        let reason = self.reason();
        let reasons_are_equal = |s: &SignedSpend| reason == s.reason();
        if !self.signed_spends.iter().all(reasons_are_equal) {
            return Err(Error::SignedSpendReasonMismatch(dbc_id));
        }
        Ok(())
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
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::{
        dbc_id::random_derivation_index,
        mock,
        rand::{CryptoRng, RngCore},
        transaction::Output,
        FeeOutput, Hash, Token,
    };
    use blsttc::{PublicKey, SecretKey};
    use std::convert::TryInto;

    #[test]
    fn from_hex_should_deserialize_a_hex_encoded_string_to_a_dbc() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 1_530_000_000;
        let main_key = MainKey::random_from_rng(&mut rng);
        let derivation_index = random_derivation_index(&mut rng);
        let derived_key = main_key.derive_key(&derivation_index);
        let tx = DbcTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
            fee: FeeOutput::new(Hash::default(), 3_500, Hash::default()),
        };
        let ciphers = DbcCiphers::from((&main_key.public_address(), &derivation_index));
        let dbc = Dbc {
            id: derived_key.dbc_id(),
            src_tx: tx,
            ciphers,
            signed_spends: Default::default(),
        };

        let hex = dbc.to_hex()?;

        let dbc = Dbc::from_hex(&hex)?;
        assert_eq!(dbc.token()?.as_nano(), 1_530_000_000);

        let fee_amount = dbc.fee_output().token;
        assert_eq!(fee_amount, Token::from_nano(3_500));

        Ok(())
    }

    #[test]
    fn to_hex_should_serialize_a_dbc_to_a_hex_encoded_string() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 100;
        let main_key = MainKey::random_from_rng(&mut rng);
        let derivation_index = random_derivation_index(&mut rng);
        let derived_key = main_key.derive_key(&derivation_index);
        let tx = DbcTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
            fee: FeeOutput::new(Hash::default(), 2_500, Hash::default()),
        };
        let ciphers = DbcCiphers::from((&main_key.public_address(), &derivation_index));
        let dbc = Dbc {
            id: derived_key.dbc_id(),
            src_tx: tx,
            ciphers,
            signed_spends: Default::default(),
        };

        let hex = dbc.to_hex()?;
        let dbc_from_hex = Dbc::from_hex(&hex)?;

        assert_eq!(dbc.token()?, dbc_from_hex.token()?);

        let fee_amount = dbc.fee_output().token;
        assert_eq!(fee_amount, Token::from_nano(2_500));

        Ok(())
    }

    #[test]
    fn input_should_error_if_dbc_id_is_not_derived_from_main_key() -> Result<(), Error> {
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
        let result = dbc.derived_key(&main_key);
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

        let tx = DbcTransaction {
            inputs: vec![],
            outputs: vec![Output::new(derived_key.dbc_id(), amount)],
            fee: FeeOutput::default(),
        };

        let ciphers = DbcCiphers::from((&main_key.public_address(), &derivation_index));
        let dbc = Dbc {
            id: derived_key.dbc_id(),
            src_tx: tx,
            ciphers,
            signed_spends: Default::default(),
        };

        assert!(matches!(dbc.verify(&main_key), Err(Error::MissingTxInputs)));

        Ok(())
    }

    pub(crate) fn generate_dbc_of_value_from_pk_hex(
        amount: u64,
        pk_hex: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentbookNode, Dbc, (Dbc, Dbc))> {
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

    fn generate_dbc_of_value(
        amount: u64,
        recipient: PublicAddress,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentbookNode, Dbc, (Dbc, Dbc))> {
        let (mut spentbook_node, genesis_dbc, genesis_material, _) =
            mock::GenesisBuilder::init_genesis_single()?;

        let output_tokens = vec![
            Token::from_nano(amount),
            Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount),
        ];

        let derived_key = genesis_dbc.derived_key(&genesis_material.main_key)?;
        let dbc_builder = crate::TransactionBuilder::default()
            .add_input_dbc(&genesis_dbc, &derived_key)
            .unwrap()
            .add_outputs(
                output_tokens
                    .into_iter()
                    .map(|token| (token, recipient, random_derivation_index(rng))),
            )
            .build(Hash::default())?;

        let tx = &dbc_builder.spent_tx;
        for signed_spend in dbc_builder.signed_spends() {
            spentbook_node.log_spent(tx, signed_spend)?
        }

        let mut iter = dbc_builder.build()?.into_iter();
        let (starting_dbc, _) = iter.next().unwrap();
        let (change_dbc, _) = iter.next().unwrap();

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
