// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use blsttc::{PublicKey, SecretKey};
use std::{collections::BTreeSet, convert::TryFrom};
use tiny_keccak::{Hasher, Sha3};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::transaction::{DbcTransaction, OutputProof, RevealedCommitment, RevealedInput};
use crate::{
    AmountSecrets, DbcContent, DerivationIndex, Error, Hash, Owner, Result, SpentProof,
    SpentProofKeyVerifier, TransactionVerifier,
};

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
/// The Spentbook never sees the Owner Base.  Instead, when a
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
    pub transaction: DbcTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
    pub spent_transactions: BTreeSet<DbcTransaction>,
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

    /// returns PublicKey for the owner's derived public key
    /// This is useful for checking if a Dbc has been spent.
    pub fn public_key(&self, base_sk: &SecretKey) -> Result<PublicKey> {
        let secret_key = self.owner_once(base_sk)?.secret_key()?;
        Ok(secret_key.public_key())
    }

    /// returns PublicKey for the owner's derived public key
    /// This is useful for checking if a Dbc has been spent.
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn key_image_bearer(&self) -> Result<PublicKey> {
        self.public_key(&self.owner_base().secret_key()?)
    }

    /// returns a TrueInput that represents this Dbc for use as
    /// a transaction input.
    pub fn as_revealed_input(&self, base_sk: &SecretKey) -> Result<RevealedInput> {
        Ok(RevealedInput::new(
            self.owner_once(base_sk)?.secret_key()?,
            self.amount_secrets(base_sk)?.into(),
        ))
    }

    /// returns a TrueInput that represents this Dbc for use as
    /// a transaction input.
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn as_revealed_input_bearer(&self) -> Result<RevealedInput> {
        self.as_revealed_input(&self.owner_base().secret_key()?)
    }

    /// Generate hash of this DBC
    pub fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::v256();

        sha3.update(&self.content.to_bytes());
        sha3.update(&self.transaction.hash());

        for sp in self.spent_proofs.iter() {
            sha3.update(&sp.to_bytes());
        }

        for st in self.spent_transactions.iter() {
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
    /// see comments for Dbc::verify_amount_matches_commitment() for a
    /// description of how to handle Error::AmountCommitmentsDoNotMatch
    pub fn verify<K: SpentProofKeyVerifier>(
        &self,
        base_sk: &SecretKey,
        verifier: &K,
    ) -> Result<(), Error> {
        TransactionVerifier::verify(verifier, &self.transaction, &self.spent_proofs)?;

        let owner = self.owner_once(base_sk)?.public_key();

        if !self
            .transaction
            .outputs
            .iter()
            .any(|o| owner.eq(o.public_key()))
        {
            return Err(Error::DbcContentNotPresentInTransactionOutput);
        }

        // verify there is a maching transaction for each spent proof
        if !self.spent_proofs.iter().all(|proof| {
            self.spent_transactions
                .iter()
                .any(|tx| Hash::from(tx.hash()) == proof.transaction_hash())
        }) {
            return Err(Error::MissingSpentTransaction);
        }

        self.verify_amount_matches_commitment(base_sk)
    }

    /// bearer version of verify()
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn verify_bearer<K: SpentProofKeyVerifier>(&self, verifier: &K) -> Result<(), Error> {
        self.verify(&self.owner_base().secret_key()?, verifier)
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

    /// Convert this instance from owned to bearer by supplying the secret key for the
    /// corresponding public key.
    ///
    /// Will return an error if this instance is already bearer or if the supplied secret key
    /// doesn't match the public key.
    pub fn to_bearer(&mut self, base_sk: &SecretKey) -> Result<(), Error> {
        if self.is_bearer() {
            return Err(Error::DbcBearerConversionFailed(
                "this DBC is already bearer".to_string(),
            ));
        }
        if base_sk.public_key() != self.owner_base().public_key() {
            return Err(Error::DbcBearerConversionFailed(
                "supplied secret key does not match the public key".to_string(),
            ));
        }
        let owner = Owner::from(base_sk.clone());
        self.content.owner_base = owner;
        Ok(())
    }

    /// Checks if the provided AmountSecrets matches the amount commitment.
    /// note that both the amount and blinding_factor must be correct.
    ///
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
    pub(crate) fn verify_amount_matches_commitment(&self, base_sk: &SecretKey) -> Result<()> {
        let rc: RevealedCommitment = self.amount_secrets(base_sk)?.into();
        let secrets_commitment = rc.commit(&Default::default());
        let tx_commitment = self.my_output_proof(base_sk)?.commitment();

        match secrets_commitment == tx_commitment {
            true => Ok(()),
            false => Err(Error::AmountCommitmentsDoNotMatch),
        }
    }

    fn my_output_proof(&self, base_sk: &SecretKey) -> Result<&OutputProof> {
        let owner = self.owner_once(base_sk)?.public_key();
        self.transaction
            .outputs
            .iter()
            .find(|o| owner.eq(o.public_key()))
            .ok_or(Error::OutputProofNotFound)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::tests::{NonZeroTinyInt, TinyInt};
    use crate::transaction::{Output, RevealedTransaction};
    use crate::{
        mock,
        rand::{CryptoRng, RngCore},
        AmountSecrets, DbcBuilder, Hash, Owner, OwnerOnce, SpentProofContent, Token,
    };
    use bls_bulletproofs::PedersenGens;
    use blsttc::PublicKey;
    use quickcheck_macros::quickcheck;
    use std::convert::TryInto;

    fn divide(amount: Token, n_ways: u8) -> impl Iterator<Item = Token> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount.as_nano() / n_ways as u64;
            let leftover = amount.as_nano() % n_ways as u64;

            let odd_compensation = u64::from((i as u64) < leftover);
            Token::from_nano(equal_parts + odd_compensation)
        })
    }

    const DBC_WITH_1_530_000_000: &str = "00000000000000000000000000000000b1d460d064d48592edc071c0ee40966eec954cdc0151a40d4445240a256cf73498da8f7693a58869079da8789403789652de1fc623c1b727925b5c0bbafcc3c06e6c7f2eda587320597c76ec0a797d15313ac18c9b4c4364789bc8e033c33c6512a659bf6be3166ff0c4a5f47cf2dfee2747b0a24172061926835e77aa2f4b415b04c1117c39011a66d4e68c53d3ab86f57a6237391374eca465d85e5a15c7b7df3484ac6879e96bbdc25a7355585af69ec5b10ef0585ff2e7b9bf4d2225bfa7c8c17974223995561e460ce524b9b5b5d5a70dbe88e7a9c08a05961d5430ccea53a5ed5a6bd01e151152ec5952a8abc35e926031239f426b3018fbd470d82f936bbb66b70284b8b45151d65491ab7b8474ad4eefd916c107f40cc8cb6a222ea57569640b96a75f45f78f9960990bef82192693271679e9b3cb859b9252bc76171cd5a55f2fafcd399249c7bd6a1e674e563114e312208b350aa99c6d30036fa66bce803dcd69d197701a19563d8a8d8420ed9967714ce8a17613dbe765e135f0429f0c05a0745e24162e492fe2ceb8b8b2ec07abf0e8f451dab46b2d85d00545beaefebf7be2d88556f32091c4cc255016e0203109dbfff4a2100435e26a7c920c9fc63fffac221bc44aca14557b87c830e0be5862d3ff279c7722c3722d46b34b87abd868501ce92cd105bf58676da1cc9224667ff1a3415d3fe55784788a4881cd0830664ba6270b4f1336f1917e848a6719609b84de20ff868d2f18ad65949ce3d1faa1c63e274a0ccd151bd826c02f53bbc62b6f6fa54232892840e884cefe3ee2e73db31a8825d98f0bfc1c1e9543fc7e50b98c9be093dda808672957847b7b8589a69de583d242ac096c73e4026ef8fd2edcc6775a17e97331f3ee3880122e83ff1048543e1c6f1145d17c950afaaba67cfa8bb8da0b4b8ca42e65f8b5c12988d5df261e3441023678e7958fb44cf33011912487e888ceab7909efd9ae6e100e042c2cfc027aaeed187a542f1958adbb52e193364171f1914b3b699b5f663a4d664d792e5aa36825feb9dd7c0c07d46094811b89903b5740fc71f662ea3a5df377e62458025e0a45f7e974ef786d0699b9b8d10d10f99ae127ef3fd649dd018fc2414b161840fa617aed0d03703d2ccb6e0841a3b75bc313eca9547587abbd7985f6714c6f9b409ee4792555523585c69dd3b8f6926d9e4a62456812cbebec89dd0d668831f19b88230f89dfb22bbecdc534cd3964c5aad33984614351e0342278e99a836bc5d1fac4ca5b5ab696f09c3461e51cae3f238679fb9002b7106300eefe46e093fc41ad3ef2d494306ab526d679f39c8610174ea4fc8f3a867b5f9e3fb1d3e957b119269b3080bd9000000000000003a0e1efaa9f098cf6af927d2a03b6b6735e23725f60a6412123f4b7c08c42e8d8067a2e00fd8c3b3af67d2929e1f7c739a300000000000000010000000000000000aef10b40280f6ff9b27cb4ff7c11211c3eac99bf8b4bfc8606fe3991a394dec3673ecb383ca63491b8ac1b294193250bd2d5fe3d8036ec140ee420adf9ebb9e56be5ef3824f3173f4f1a045bd9a082155986ac0305d269dc0fe32c2037b11bada69121f9ff8da8484f91f4ad6f00b63ef04d4d3985c93404411b052a3a6e549e5ba198863c9413bf00000000000000289dde07f9368f6e9e494bcbe35fffcef22ecfeb2beffa55af98778d08f90641fa3ffd5d32f15afec63fb9de44d1e0938104252cf84d1200cb64ba05ad272f018f0eeefba14bd1cea0d89bd80c14ff556db42c89f91cc98bfa4ff6df206bcb40104b45e2f77bb349d163af5a133277a36a14b8040110ff0810bd012a3d3f569df3e92d63e922b29fad6ce4236c9eb670aafe7222f907f13873bfb5a2d4bd2101598c21a894c2855e8bad5fdfaee4713074000000000000002069c61dadffc05c86fdf098afd3bbd96ec5fed102096f8f64329371a13441bb1afd61599d62ee6925181e2d5859eb2eb79bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f00000000";

    fn prepare_even_split(
        dbc_owner: SecretKey,
        amount_secrets: AmountSecrets,
        n_ways: u8,
        output_owners: Vec<OwnerOnce>,
        spentbook_node: &mut mock::SpentBookNode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DbcBuilder> {
        let amount = amount_secrets.amount();

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_input_by_secrets(dbc_owner, amount_secrets)
            .add_outputs_by_amount(divide(amount, n_ways).zip(output_owners.into_iter()))
            .build(rng)?;

        for (public_key, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(public_key, tx.clone())?)
                .add_spent_transaction(tx);
        }

        Ok(dbc_builder)
    }

    #[test]
    fn from_hex_should_deserialize_a_hex_encoded_string_to_a_dbc() -> Result<(), Error> {
        let dbc = Dbc::from_hex(DBC_WITH_1_530_000_000)?;
        let amount = dbc.amount_secrets_bearer()?.amount();
        assert_eq!(amount, Token::from_nano(1_530_000_000));
        Ok(())
    }

    #[test]
    fn to_hex_should_serialize_a_dbc_to_a_hex_encoded_string() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 100;
        let owner_once =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);
        let tx_material = RevealedTransaction {
            inputs: vec![],
            outputs: vec![Output::new(owner_once.as_owner().public_key(), amount)],
        };
        let (transaction, revealed_commitments) = tx_material
            .sign(&mut rng)
            .expect("Failed to sign transaction");
        let input_content = DbcContent::from((
            owner_once.owner_base.clone(),
            owner_once.derivation_index,
            AmountSecrets::from(revealed_commitments[0]),
        ));
        let dbc = Dbc {
            content: input_content,
            transaction,
            spent_proofs: Default::default(),
            spent_transactions: Default::default(),
        };

        let hex = dbc.to_hex()?;

        let dbc_from_hex = Dbc::from_hex(&hex)?;
        let left = dbc.amount_secrets_bearer()?.amount();
        let right = dbc_from_hex.amount_secrets_bearer()?.amount();
        assert_eq!(left, right);
        Ok(())
    }

    #[test]
    fn to_bearer_should_convert_an_owned_dbc_to_bearer() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let (_, _, mut dbc, _) = generate_owned_dbc_of_value(
            100,
            "a7f2888a4ef621681eb8df4318ebe8c68504b50a33300e113466004de48834a3a0\
            eab591077e173ec7f2e4e1261a6a98",
            &mut rng,
        )?;
        let sk = get_secret_key_from_hex(
            "d823b03be25ad306ce2c2ef8f67d8a49322ed2a8636de5dbf01f6cc3467dc91e",
        )?;
        dbc.to_bearer(&sk)?;
        assert!(dbc.is_bearer());
        Ok(())
    }

    #[test]
    fn to_bearer_should_error_if_dbc_is_already_bearer() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let (_, _, mut dbc, _) = generate_bearer_dbc_of_value(100, &mut rng)?;
        let sk = get_secret_key_from_hex(
            "d823b03be25ad306ce2c2ef8f67d8a49322ed2a8636de5dbf01f6cc3467dc91e",
        )?;
        let result = dbc.to_bearer(&sk);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not convert owned DBC to bearer: this DBC is already bearer"
        );
        Ok(())
    }

    #[test]
    fn to_bearer_should_error_if_secret_key_does_not_match_public_key() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let (_, _, mut dbc, _) = generate_owned_dbc_of_value(
            100,
            "a14a1887c61f95d5bdf6d674da3032dad77f2168fe6bf5e282aa02394bd45f41f0\
            fe722b61fa94764da42a9b628701db",
            &mut rng,
        )?;
        let sk = get_secret_key_from_hex(
            "d823b03be25ad306ce2c2ef8f67d8a49322ed2a8636de5dbf01f6cc3467dc91e",
        )?;
        let result = dbc.to_bearer(&sk);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not convert owned DBC to bearer: supplied secret key does not match the public key"
        );
        Ok(())
    }

    #[test]
    fn test_dbc_without_inputs_fails_verification() -> Result<(), Error> {
        let mut rng = crate::rng::from_seed([0u8; 32]);
        let amount = 100;

        let owner_once =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let tx_material = RevealedTransaction {
            inputs: vec![],
            outputs: vec![Output::new(owner_once.as_owner().public_key(), amount)],
        };

        let (transaction, revealed_commitments) = tx_material
            .sign(&mut rng)
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
            spent_proofs: Default::default(),
            spent_transactions: Default::default(),
        };

        let id = crate::bls_dkg_id(&mut rng);
        let key_manager = mock::KeyManager::from(mock::Signer::from(id));

        assert!(matches!(
            dbc.verify(&owner_once.owner_base().secret_key()?, &key_manager),
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
        let (mut spentbook_node, _genesis_dbc, starting_dbc, _change_dbc) =
            generate_bearer_dbc_of_value(amount, &mut rng)?;

        let input_owners: Vec<OwnerOnce> = (0..n_inputs.coerce())
            .map(|_| OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng))
            .collect();

        let dbc_builder = prepare_even_split(
            starting_dbc.owner_once_bearer()?.secret_key()?,
            starting_dbc.amount_secrets_bearer()?,
            n_inputs.coerce(),
            input_owners,
            &mut spentbook_node,
            &mut rng,
        )?;

        let output_dbcs = dbc_builder.build(&spentbook_node.key_manager)?;

        let spent_proofs = output_dbcs
            .iter()
            .map(|x| x.0.spent_proofs.clone())
            .next()
            .unwrap();
        let sp_first = spent_proofs.iter().next().unwrap();
        assert!(sp_first
            .spentbook_pub_key
            .verify(&sp_first.spentbook_sig, sp_first.content.hash()));

        // The outputs become inputs for next tx.
        let inputs: Vec<(Dbc, SecretKey)> = output_dbcs
            .into_iter()
            .map(|(dbc, owner_once, _amount_secrets)| {
                (dbc, owner_once.owner_base().secret_key().unwrap())
            })
            .collect();

        let owner_once =
            OwnerOnce::from_owner_base(Owner::from_random_secret_key(&mut rng), &mut rng);

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_inputs_dbc(inputs)?
            .add_output_by_amount(Token::from_nano(amount), owner_once.clone())
            .build(&mut rng)?;

        for (public_key, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(public_key, tx.clone())?)
                .add_spent_transaction(tx);
        }

        // We must obtain the RevealedCommitment for our output in order to
        // know the correct blinding factor when creating fuzzed_amt_secrets.
        let output = dbc_builder.transaction.outputs.get(0).unwrap();
        let pc_gens = PedersenGens::default();
        let output_commitments: Vec<(crate::Commitment, RevealedCommitment)> = dbc_builder
            .revealed_commitments
            .iter()
            .map(|r| (r.commit(&pc_gens), *r))
            .collect();
        let amount_secrets_list: Vec<AmountSecrets> = output_commitments
            .iter()
            .filter(|(c, _)| *c == output.commitment())
            .map(|(_, r)| AmountSecrets::from(*r))
            .collect();

        let fuzzed_amt_secrets = AmountSecrets::from((
            amount + extra_output_amount.coerce::<u64>(),
            amount_secrets_list[0].blinding_factor(),
        ));
        let dbc_amount = fuzzed_amt_secrets.amount();

        let fuzzed_content = DbcContent::from((
            owner_once.owner_base.clone(),
            owner_once.derivation_index,
            fuzzed_amt_secrets,
        ));

        let mut fuzzed_spent_proofs: BTreeSet<SpentProof> = BTreeSet::new();

        let spent_proofs = dbc_builder.spent_proofs()?;
        fuzzed_spent_proofs.extend(spent_proofs.iter().take(n_valid_sigs.coerce()).cloned());

        let mut repeating_inputs = spent_proofs
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

                let fuzzed_sp = SpentProof {
                    content: spent_proof.content.clone(),
                    spentbook_pub_key: key_manager.public_key_set().public_key(),
                    spentbook_sig: sig,
                };
                // note: existing items may be replaced.
                println!("added wrong signer");
                fuzzed_spent_proofs.insert(fuzzed_sp);
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

                let fuzzed_sp = SpentProof {
                    content: spent_proof.content.clone(),
                    spentbook_pub_key: spent_proof.spentbook_pub_key,
                    spentbook_sig: wrong_msg_sig,
                };
                // note: existing items may be replaced.
                fuzzed_spent_proofs.insert(fuzzed_sp);
            }
        }

        use crate::rand::distributions::{Distribution, Standard};

        // Valid spentbook signatures for inputs not present in the transaction
        for _ in 0..n_extra_input_sigs.coerce() {
            if let Some(spent_proof) = repeating_inputs.next() {
                let secret_key: SecretKey = Standard.sample(&mut rng);

                let content = SpentProofContent {
                    public_key: secret_key.public_key(),
                    transaction_hash: spent_proof.transaction_hash(),
                    public_commitment: *spent_proof.public_commitment(),
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
                fuzzed_spent_proofs.insert(fuzzed_sp);
            }
        }

        let spent_transactions = dbc_builder.spent_transactions.values().cloned().collect();
        let dbcs = dbc_builder.build(&spentbook_node.key_manager)?;
        let (dbc_valid, ..) = &dbcs[0];

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: dbc_valid.transaction.clone(),
            spent_proofs: fuzzed_spent_proofs,
            spent_transactions,
        };

        let key_manager = &spentbook_node.key_manager;
        let verification_res = dbc.verify(&owner_once.owner_base().secret_key()?, key_manager);

        let dbc_owner = dbc
            .owner_once(&owner_once.owner_base().secret_key()?)?
            .public_key();

        match verification_res {
            Ok(()) => {
                assert!(dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| dbc_owner.eq(o.public_key())));
                assert!(n_inputs.coerce::<u8>() > 0);
                assert!(n_valid_sigs.coerce::<u8>() >= n_inputs.coerce::<u8>());
                assert_eq!(n_extra_input_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_signer_sigs.coerce::<u8>(), 0);
                assert_eq!(n_wrong_msg_sigs.coerce::<u8>(), 0);

                assert_eq!(dbc_amount, Token::from_nano(amount));
                assert_eq!(extra_output_amount.coerce::<u8>(), 0);
            }
            Err(Error::SpentProofInputLenMismatch { current, expected }) => {
                assert_ne!(dbc.spent_proofs.len(), dbc.transaction.inputs.len());
                assert_eq!(dbc.spent_proofs.len(), current);
                assert_eq!(dbc.transaction.inputs.len(), expected);
            }
            Err(Error::SpentProofInputPublicKeyMismatch) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| dbc_owner.eq(o.public_key())));
            }
            Err(Error::Transaction(crate::transaction::Error::TransactionMustHaveAnInput)) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::AmountCommitmentsDoNotMatch) => {
                assert_ne!(Token::from_nano(amount), dbc_amount);
                assert_ne!(extra_output_amount, TinyInt(0));
            }
            Err(Error::InvalidSpentProofSignature(_) | Error::FailedKnownKeyCheck(_)) => {
                // could be a wrong signer (unrecognized authority) or wrong msg.
                assert!(n_wrong_signer_sigs.coerce::<u8>() + n_wrong_msg_sigs.coerce::<u8>() > 0);

                // if we are certain it was wrong signer, then we can verify spentbook's key manager
                // does not trust the signer.
                if n_wrong_signer_sigs.coerce::<u8>() > 0 && n_wrong_msg_sigs.coerce::<u8>() == 0 {
                    for sp in dbc.spent_proofs.iter() {
                        println!("pk: {:?}", sp.spentbook_pub_key);
                    }
                    assert!(dbc
                        .spent_proofs
                        .iter()
                        .any(|sp| key_manager.verify_known_key(&sp.spentbook_pub_key).is_err()));
                }
            }
            res => panic!("Unexpected verification result {:?}", res),
        }

        Ok(())
    }

    pub(crate) fn generate_bearer_dbc_of_value(
        amount: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, Dbc, Dbc)> {
        generate_dbc_of_value(amount, Owner::from_random_secret_key(rng), rng)
    }

    pub(crate) fn generate_owned_dbc_of_value(
        amount: u64,
        pk_hex: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, Dbc, Dbc)> {
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
        let owner = Owner::from(pk);
        generate_dbc_of_value(amount, owner, rng)
    }

    fn generate_dbc_of_value(
        amount: u64,
        owner: Owner,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, Dbc, Dbc)> {
        let (mut spentbook_node, genesis_dbc, _genesis_material, _amount_secrets) =
            mock::GenesisBuilder::init_genesis_single(rng)?;

        let output_amounts = vec![
            Token::from_nano(amount),
            Token::from_nano(mock::GenesisMaterial::GENESIS_AMOUNT - amount),
        ];

        let mut dbc_builder = crate::TransactionBuilder::default()
            .add_input_by_secrets(
                genesis_dbc.owner_once_bearer()?.secret_key()?,
                genesis_dbc.amount_secrets_bearer()?,
            )
            .add_outputs_by_amount(
                output_amounts
                    .into_iter()
                    .map(|amount| (amount, OwnerOnce::from_owner_base(owner.clone(), rng))),
            )
            .build(rng)?;

        for (public_key, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(public_key, tx.clone())?)
                .add_spent_transaction(tx);
        }

        let mut iter = dbc_builder.build(&spentbook_node.key_manager)?.into_iter();
        let (starting_dbc, ..) = iter.next().unwrap();
        let (change_dbc, ..) = iter.next().unwrap();

        Ok((spentbook_node, genesis_dbc, starting_dbc, change_dbc))
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
