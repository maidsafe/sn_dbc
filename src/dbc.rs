// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::transaction::{
    group::Curve,
    output::{OutputProof, RingCtTransaction},
    {RevealedCommitment, TrueInput},
};
use crate::{
    AmountSecrets, DbcContent, DerivationIndex, Error, Hash, KeyImage, Owner, Result, SpentProof,
    SpentProofKeyVerifier, TransactionVerifier,
};
use blsttc::SecretKey;
use std::{collections::BTreeSet, convert::TryFrom};
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
    pub transaction: RingCtTransaction,
    pub spent_proofs: BTreeSet<SpentProof>,
    pub spent_transactions: BTreeSet<RingCtTransaction>,
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
        let secret_key = self.owner_once(base_sk)?.secret_key()?;
        Ok(crate::transaction::key_image(secret_key).to_affine().into())
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
        Ok(TrueInput::new(
            self.owner_once(base_sk)?.secret_key()?,
            self.amount_secrets(base_sk)?.into(),
        ))
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
        let secrets_commitment = rc.commit(&Default::default()).to_affine();
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

    use quickcheck_macros::quickcheck;

    use crate::tests::{NonZeroTinyInt, TinyInt, STD_DECOYS_PER_INPUT, STD_DECOYS_TO_FETCH};
    use crate::transaction::{bls_bulletproofs::PedersenGens, output::RingCtMaterial, Output};
    use crate::{
        mock,
        rand::{CryptoRng, RngCore},
        AmountSecrets, DbcBuilder, Hash, Owner, OwnerOnce, SpentProofContent, Token,
    };
    use blsttc::PublicKey;
    use std::convert::TryInto;

    fn divide(amount: Token, n_ways: u8) -> impl Iterator<Item = Token> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount.as_nano() / n_ways as u64;
            let leftover = amount.as_nano() % n_ways as u64;

            let odd_compensation = u64::from((i as u64) < leftover);
            Token::from_nano(equal_parts + odd_compensation)
        })
    }

    const DBC_WITH_1_530_000_000: &str = "5b27e8998542c6ae461c20bbb764da84b16721c795fa5ec73db3d109a68dcdded655d1c1ed7d2106ac1d12558049bab64581076215747dbbff95397a32a3d3848ceb318cf6dd5b371a2e2e910e0697972fb69d93e07de0d4387c3e4dfa2d59bdf91debc36b3bc8c45c3fa390e9bbb492ba54cdaca5bd94544a56f8d209b8876fa3e5eeef1e9d624a4b65c2627983dfbc3ef0f2cb1b815c3748052525fb7bdab933a5fdfc39d7dac1f657bd63f3c64d9e7601e031455e5b49479aa82c87c6cd944bba03423f7099c695593a94247b64a5bb32eccc0ad9fdbb89fb278d415a382761a130301e29d5673635b459b7932f2454d2e64e0489adc4a037e0b5bd6f9793fe52c8fba9405d0ef7eed48a296f9e070ec6961484490788bf629f2151bddd6097f63dd53274cd0df1693e96b8d3179619a05259fb25c7912520468a0abd1731535bdecf6b4f5497429dda47268d24f9f203eebac6978739a5d0d91358f84bb1f64712c83e8ed825fd1beaa06d63189fdfada90df84705f959681b4b34d58f8843dbe98bff97f87a3df4d235859c75b4642dec1566cd196f01d9665aa24597131c3c36bf5893a27136fd6fbb1c5b14c435c6914e9340b7ea5c522c834137c9b9eae762481905a04514e4ced0f048daedf7298f9ae16588f799e527963c9c7be9c89505652b62d0cf035a24ff6ab4fcaa41e9e19b217750ca2a2e6a23e14c4b54511dac6823a4e90ff077c447c941ffe75d6ddbc91939a7dbd6e0d98b01c1b0a8cb9bef1675e22939d113f23e4f245003e82051c5e4d6a37cfb87e4baf3e185f9fc4d11a7df03a191e9689eb9c07aa9ad831789577bc12446c65c29ebc7b16c022bad0e2fb1b96ba77785c6fcf60babd7c559445a42396e0f515efdf44f6058b7dfdad0345b748c4ed5ed3bd6b44e1056d54a35d05c1227db3dd194c64b30c6555622351ace8198bfcc47b57e7f7b3699032746711350a17e74207613b4395e58b892e0f1eb258ccffbc9d44f520216496fd8999d432a9a9825854e71dfe242da51f6ed909431ac766ca6e421318337425d5cb0a8794c2fa062a6575615049ad9359b493b72b51e7d5c54e23e521fd82698deffe4d9968120be1921e8288930d15d298abe9527757aecc35d87e7ec98f9ce68193e966e32274e0dd4be7dc4eda480fb9ed581053f51451e4fcd44ec292c42f9c23d40016409a097100674745fcda19603a9d4bcb3990e641ade096d7db2edc340fb0e63eca1d4a7a5e4fd2f6d9bba29f5fb69cb2053d403982672689126045e946fedd54ad97b71f9c908e40e91aa430fc12b42dcd3cd46ccac89e45828ec770bdb7963332e4afca6b2e79fd5ce4ab681cbf214e2d1b5f97f30ef1b379400000000000003a022f7884d31afa7d6290ac827610f8d1b3ac85b23d772aad211432020dc6ef7fb3b16caff655e8033f23a5a02e70a14853a153d1f310223795eedd09b7174755e42cf9ab2450e1dd5e913e5939017a2e288d521d9abfbdced62f2139aaa9bd1a030f012e75822f069d9efb8b06594c2ab3cf51631b8451bfe1289e39ae3263ca965d7dd887ca70a8d4a24fa740ea6737ef0989e55298c08c861ddea293c2112f154cc68813af354ca1e376b87b6b95504b7373fe142fddbc9bd649236bef035d1f75c14fe2b50b580ad993df6a4e5e6b855ecfa165e660beefe0b1160f2b8aebea8458cb3b4bffa99b49ec364ce39dacc8adbc388fe5c519c3428ff33e8a3238c7c17bbd748c7412432b6ca1937d02991b094e8f1b96f30df799bae9a9959d922543100fb32eb35f206ab6f875e1058b6aaaeb57e4e878fcf01d8d700c5ce619cc0c856635d1ebba1c0f031eee8a7fc4a5587a3c1acea24f6c5bbf67e8a366098091452e3412cf42360840395016ebfc882d49a9b5986e59995521b14c0645d586f4ca9afd58b90680f9f7dcf304156aeee1bf0a07517d7f12d5e1124d7fd14429214598a15b6096bac99fa59d8b8243a228953eba44f4e4df22a369f52a72da4b91fae2fb0803074f453f5f8c7ab586caeac5805f2891de74a3c5cfadc4b5bf425ae802f067f6a5a54f7564309e74fb938ca81610f88cde01aaa999306474fb49ca31994619c1c76351487efef558f8c8dd8140c9de805f40c9c8b8b152b55a5b0c61b5ff26d194f39aec49659790a8b761c837b6acb377e790798b2ff1fede7d460c146b62159c25ed50a5f58a683941668e8b849065668ecf4e380165f3029e64686d8b1f0f8ec53d4914da9612805272153be3e3e10855e7b81a4914c90ab770d72859a442055b0a3c143a435f45758ba5650da7e85cbe1f99fc04a17f993b2d092163a22ec397b01a7e37dddee80fc81b1a5244c5b4e4d06d28dd7e0e09ab2892f0b902fbc085d715a9380ac1181817975c7fa1a0df62997d2c69270f9aa2e6215c55fd92143d064119d1b283e58c46b5ebaf36ca9f1a99e10b4952423b705fea91fb697d40e5caeb1f6ca2f164dea7bd9571bf810e8aba02ce522319bfb1eacf38dc1dfb953b47833191bb695eef377f44be0753dd8abde493e413008a37ec5ebdce084d0e2cff8348f3e4208af9ed6605398f0ab2975a5d0547c67b59b9969991bcea289370e4989c749b31e8469c76f643e2cdc5bf07e7f0e4b34374cd29a305933a482667782ce7d94041fabc74c5acd5868ea15824eeb89ade841b541ad49c28a4fc10183ed1118b5db3ba997c5635fa0e4f7ed0580280e8184e3ae743f286c9d7a048a64c0dd262c80769915b66169bf7a1f1c52bbcbb508d8bcfcd9b0c392e01a638f30cb7def3c74ed3bd5de7e794a71630d8055fa10ba858f8200000000000003a07f7a21e7168519441c7c08df4df085df9016351e4f001d6bc5df9bff21e570470a34546aa7b733fdcd338c547bae02810000000000000002f5435dd67154de0c0d36d338d1282a35bfb31ccefca42a4786aac034115fc76fe6a39deb556ee1cb58682b8216ce989235f556ccfbfb57b54f658262c8b2748b32e076d5e81cd8837f2b86900ca7b27f586955006b54b10ed304ee7c4fd8318996535faeae2d5b27e4c0b37f2d8667128dbe048a2814ce4d24fc60f7a0dda7c87e1d3b30254c25aba701ff6eeb9ebe8800000000000000011ca2ae5ab0ed3dc52cc9cd341c4a482e9d9f5f2d81d981a11032821603b863baa19a900087052a2f799092f29d7e2c8b548303a73305fc9c94eada44863144d84b6f9088a6280ff1b54cf540dc6c4ded457121351f13df5ffd94cb9764079dede3220daca7d85f61d5092eaca480b7b500000000000000013f80a95efa16af78eceb4d770980e57c9f2ef4939db4fd6233e71179b281c30c0000000000000001000000000000000140bf4b37d26b0d348e8b6971ae02f1b8f4c45464d730cff075dba8dc16b3ebe83bdd0967eca3217ec4a66448829271052ede75124f072c1428102aa508a9cd83b4ee63f52d19764068efe798e3d96ae8004e2496ed626daa8fc3277c1b2aeb981f6d0adfbd03542f93053fa4056d0ce36018ebb704258d130a797471ce3a0d1802c05a7f578a1bf4851975549b2bf0b038aab683457882ebc8dc80cd829f9e292837a00789952636524a544ae1fada10439ed9478b6d0127c5fd13ed74e9e1870000000000000001fa3523c0c909f6104727a3148f3469aedf9626c9421c030dd52e65dc057914211ca2ae5ab0ed3dc52cc9cd341c4a482e9d9f5f2d81d981a11032821603b863baa19a900087052a2f799092f29d7e2c8b00000000000000015b27e8998542c6ae461c20bbb764da84b16721c795fa5ec73db3d109a68dcdded655d1c1ed7d2106ac1d12558049bab64581076215747dbbff95397a32a3d3848ceb318cf6dd5b371a2e2e910e0697972fb69d93e07de0d4387c3e4dfa2d59bdf91debc36b3bc8c45c3fa390e9bbb492ba54cdaca5bd94544a56f8d209b8876fa3e5eeef1e9d624a4b65c2627983dfbc3ef0f2cb1b815c3748052525fb7bdab933a5fdfc39d7dac1f657bd63f3c64d9e7601e031455e5b49479aa82c87c6cd944bba03423f7099c695593a94247b64a5bb32eccc0ad9fdbb89fb278d415a382761a130301e29d5673635b459b7932f2454d2e64e0489adc4a037e0b5bd6f9793fe52c8fba9405d0ef7eed48a296f9e070ec6961484490788bf629f2151bddd6097f63dd53274cd0df1693e96b8d3179619a05259fb25c7912520468a0abd1731535bdecf6b4f5497429dda47268d24f9f203eebac6978739a5d0d91358f84bb1f64712c83e8ed825fd1beaa06d63189fdfada90df84705f959681b4b34d58f8843dbe98bff97f87a3df4d235859c75b4642dec1566cd196f01d9665aa24597131c3c36bf5893a27136fd6fbb1c5b14c435c6914e9340b7ea5c522c834137c9b9eae762481905a04514e4ced0f048daedf7298f9ae16588f799e527963c9c7be9c89505652b62d0cf035a24ff6ab4fcaa41e9e19b217750ca2a2e6a23e14c4b54511dac6823a4e90ff077c447c941ffe75d6ddbc91939a7dbd6e0d98b01c1b0a8cb9bef1675e22939d113f23e4f245003e82051c5e4d6a37cfb87e4baf3e185f9fc4d11a7df03a191e9689eb9c07aa9ad831789577bc12446c65c29ebc7b16c022bad0e2fb1b96ba77785c6fcf60babd7c559445a42396e0f515efdf44f6058b7dfdad0345b748c4ed5ed3bd6b44e1056d54a35d05c1227db3dd194c64b30c6555622351ace8198bfcc47b57e7f7b3699032746711350a17e74207613b4395e58b892e0f1eb258ccffbc9d44f520216496fd8999d432a9a9825854e71dfe242da51f6ed909431ac766ca6e421318337425d5cb0a8794c2fa062a6575615049ad9359b493b72b51e7d5c54e23e521fd82698deffe4d9968120be1921e8288930d15d298abe9527757aecc35d87e7ec98f9ce68193e966e32274e0dd4be7dc4eda480fb9ed581053f51451e4fcd44ec292c42f9c23d40016409a097100674745fcda19603a9d4bcb3990e641ade096d7db2edc340fb0e63eca1d4a7a5e4fd2f6d9bba29f5fb69cb2053d403982672689126045e946fedd54ad97b71f9c908e40e91aa430fc12b42dcd3cd46ccac89e45828ec770bdb7963332e4afca6b2e79fd5ce4ab681cbf214e2d1b5f97f30ef1b379400000000000003a022f7884d31afa7d6290ac827610f8d1b3ac85b23d772aad211432020dc6ef7fb3b16caff655e8033f23a5a02e70a14853a153d1f310223795eedd09b7174755e42cf9ab2450e1dd5e913e5939017a2e288d521d9abfbdced62f2139aaa9bd1a030f012e75822f069d9efb8b06594c2ab3cf51631b8451bfe1289e39ae3263ca965d7dd887ca70a8d4a24fa740ea6737ef0989e55298c08c861ddea293c2112f154cc68813af354ca1e376b87b6b95504b7373fe142fddbc9bd649236bef035d1f75c14fe2b50b580ad993df6a4e5e6b855ecfa165e660beefe0b1160f2b8aebea8458cb3b4bffa99b49ec364ce39dacc8adbc388fe5c519c3428ff33e8a3238c7c17bbd748c7412432b6ca1937d02991b094e8f1b96f30df799bae9a9959d922543100fb32eb35f206ab6f875e1058b6aaaeb57e4e878fcf01d8d700c5ce619cc0c856635d1ebba1c0f031eee8a7fc4a5587a3c1acea24f6c5bbf67e8a366098091452e3412cf42360840395016ebfc882d49a9b5986e59995521b14c0645d586f4ca9afd58b90680f9f7dcf304156aeee1bf0a07517d7f12d5e1124d7fd14429214598a15b6096bac99fa59d8b8243a228953eba44f4e4df22a369f52a72da4b91fae2fb0803074f453f5f8c7ab586caeac5805f2891de74a3c5cfadc4b5bf425ae802f067f6a5a54f7564309e74fb938ca81610f88cde01aaa999306474fb49ca31994619c1c76351487efef558f8c8dd8140c9de805f40c9c8b8b152b55a5b0c61b5ff26d194f39aec49659790a8b761c837b6acb377e790798b2ff1fede7d460c146b62159c25ed50a5f58a683941668e8b849065668ecf4e380165f3029e64686d8b1f0f8ec53d4914da9612805272153be3e3e10855e7b81a4914c90ab770d72859a442055b0a3c143a435f45758ba5650da7e85cbe1f99fc04a17f993b2d092163a22ec397b01a7e37dddee80fc81b1a5244c5b4e4d06d28dd7e0e09ab2892f0b902fbc085d715a9380ac1181817975c7fa1a0df62997d2c69270f9aa2e6215c55fd92143d064119d1b283e58c46b5ebaf36ca9f1a99e10b4952423b705fea91fb697d40e5caeb1f6ca2f164dea7bd9571bf810e8aba02ce522319bfb1eacf38dc1dfb953b47833191bb695eef377f44be0753dd8abde493e413008a37ec5ebdce084d0e2cff8348f3e4208af9ed6605398f0ab2975a5d0547c67b59b9969991bcea289370e4989c749b31e8469c76f643e2cdc5bf07e7f0e4b34374cd29a305933a482667782ce7d94041fabc74c5acd5868ea15824eeb89ade841b541ad49c28a4fc10183ed1118b5db3ba997c5635fa0e4f7ed0580280e8184e3ae743f286c9d7a048a64c0dd262c80769915b66169bf7a1f1c52bbcbb508d8bcfcd9b0c392e01a638f30cb7def3c74ed3bd5de7e794a71630d8055fa10ba858f8200000000000003a07f7a21e7168519441c7c08df4df085df9016351e4f001d6bc5df9bff21e570470a34546aa7b733fdcd338c547bae02810000000000000002f5435dd67154de0c0d36d338d1282a35bfb31ccefca42a4786aac034115fc76fe6a39deb556ee1cb58682b8216ce989235f556ccfbfb57b54f658262c8b2748b32e076d5e81cd8837f2b86900ca7b27f586955006b54b10ed304ee7c4fd8318996535faeae2d5b27e4c0b37f2d8667128dbe048a2814ce4d24fc60f7a0dda7c87e1d3b30254c25aba701ff6eeb9ebe8800000000000000011ca2ae5ab0ed3dc52cc9cd341c4a482e9d9f5f2d81d981a11032821603b863baa19a900087052a2f799092f29d7e2c8b548303a73305fc9c94eada44863144d84b6f9088a6280ff1b54cf540dc6c4ded457121351f13df5ffd94cb9764079dede3220daca7d85f61d5092eaca480b7b500000000000000013f80a95efa16af78eceb4d770980e57c9f2ef4939db4fd6233e71179b281c30c000000000000000117b4bfcd5437771b00ce5d6fc6f604576e621cd12754539817b1ec4a6923780443e64fff60cd8adbeaca4f1d80e0f50ecdd1a86fb6a266f6eac665ba26afa828bb5badd9844262740d78bd453057a075e5beb72a437f6a6937c941cc7bb9318c52963d0c8fd7eac17088fbafa7a0de5c5703582dadd2df0ad059e859b5c38865edbe24f57ad896eb0000000000000028c931b6d85bc74c955eba7b2da84c3972aaf8131d412dcdef7b127ec7a867d45336d27907b4408369c38f1552a6ec3e840c7bd599224f0278cb63f5f02421dd9fb9ce203f9d818bd164bd3ef114ea1c80072bae0c8d2809c9ead4b4fe6744940a1b15241bd165f974c729fc16599dd5013bbfef692d01a8ff8a1f0b7ac8f03efea80de71961d60e9c2325adeaddcbe28686de4a78b5a713a39e2f786a9e6f638ec8c8d1dbc6ca8f599a114fbc1201e1810000000000000020f763c2828f215f20407616362011799e83c511791fb78a18db13c7f785b83e15659c158be1e6837ce88162954f1c9c892bb869ec22db0154809cc9e2c9ddeada3c47928783051f20f6b56f12127fdb6900000000";

    fn prepare_even_split(
        dbc_owner: SecretKey,
        amount_secrets: AmountSecrets,
        n_ways: u8,
        output_owners: Vec<OwnerOnce>,
        spentbook_node: &mut mock::SpentBookNode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DbcBuilder> {
        let amount = amount_secrets.amount();

        let decoy_inputs = spentbook_node.random_decoys(STD_DECOYS_TO_FETCH, rng);

        let mut dbc_builder = crate::TransactionBuilder::default()
            .set_decoys_per_input(STD_DECOYS_PER_INPUT)
            .set_require_all_decoys(false)
            .add_decoy_inputs(decoy_inputs)
            .add_input_by_secrets(dbc_owner, amount_secrets)
            .add_outputs_by_amount(divide(amount, n_ways).zip(output_owners.into_iter()))
            .build(rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?)
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
        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output::new(owner_once.as_owner().public_key(), amount)],
        };
        let (transaction, revealed_commitments) = ringct_material
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

        let ringct_material = RingCtMaterial {
            inputs: vec![],
            outputs: vec![Output::new(owner_once.as_owner().public_key(), amount)],
        };

        let (transaction, revealed_commitments) = ringct_material
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
            Err(Error::RingCt(
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

        let decoy_inputs = spentbook_node.random_decoys(STD_DECOYS_TO_FETCH, &mut rng);

        let mut dbc_builder = crate::TransactionBuilder::default()
            .set_decoys_per_input(STD_DECOYS_PER_INPUT)
            .set_require_all_decoys(false)
            .add_decoy_inputs(decoy_inputs)
            .add_inputs_dbc(inputs)?
            .add_output_by_amount(Token::from_nano(amount), owner_once.clone())
            .build(&mut rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?)
                .add_spent_transaction(tx);
        }

        // We must obtain the RevealedCommitment for our output in order to
        // know the correct blinding factor when creating fuzzed_amt_secrets.
        let output = dbc_builder.transaction.outputs.get(0).unwrap();
        let pc_gens = PedersenGens::default();
        let output_commitments: Vec<(crate::Commitment, RevealedCommitment)> = dbc_builder
            .revealed_commitments
            .iter()
            .map(|r| (r.commit(&pc_gens).to_affine(), *r))
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
                    key_image: secret_key.public_key(),
                    transaction_hash: spent_proof.transaction_hash(),
                    public_commitments: spent_proof.public_commitments().clone(),
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
                assert_ne!(dbc.spent_proofs.len(), dbc.transaction.mlsags.len());
                assert_eq!(dbc.spent_proofs.len(), current);
                assert_eq!(dbc.transaction.mlsags.len(), expected);
            }
            Err(Error::SpentProofInputKeyImageMismatch) => {
                assert!(n_extra_input_sigs.coerce::<u8>() > 0);
            }
            Err(Error::DbcContentNotPresentInTransactionOutput) => {
                assert!(!dbc
                    .transaction
                    .outputs
                    .iter()
                    .any(|o| dbc_owner.eq(o.public_key())));
            }
            Err(Error::RingCt(crate::transaction::Error::TransactionMustHaveAnInput)) => {
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
            .set_require_all_decoys(false)
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

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder = dbc_builder
                .add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?)
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
