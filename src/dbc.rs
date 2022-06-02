// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{AmountSecrets, KeyImage, Owner, SpentProof, TransactionVerifier};
use crate::{DbcContent, DerivationIndex, Error, KeyManager, Result};
use bls_ringct::{
    group::Curve,
    ringct::{OutputProof, RingCtTransaction},
    {RevealedCommitment, TrueInput},
};
use blsttc::SecretKey;
use std::collections::BTreeSet;
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
        Ok(bls_ringct::key_image(secret_key).to_affine().into())
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

        let mut hash = [0u8; 32];
        sha3.finalize(&mut hash);
        hash
    }

    /// Verifies that this Dbc is valid.
    ///
    /// A Dbc recipient should call this immediately upon receipt.
    ///
    /// important: this does not check if the Dbc has been spent.
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
    pub fn verify<K: KeyManager>(&self, base_sk: &SecretKey, verifier: &K) -> Result<(), Error> {
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

        self.verify_amount_matches_commitment(base_sk)
    }

    /// bearer version of verify()
    /// will return an error if the SecretKey is not available.  (not bearer)
    pub fn verify_bearer<K: KeyManager>(&self, verifier: &K) -> Result<(), Error> {
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
    use crate::{
        mock,
        rand::{CryptoRng, RngCore},
        Amount, AmountSecrets, DbcBuilder, GenesisMaterial, Hash, Owner, OwnerOnce,
        SpentProofContent,
    };
    use bls_ringct::{bls_bulletproofs::PedersenGens, ringct::RingCtMaterial, Output};

    fn divide(amount: Amount, n_ways: u8) -> impl Iterator<Item = Amount> {
        (0..n_ways).into_iter().map(move |i| {
            let equal_parts = amount / (n_ways as Amount);
            let leftover = amount % (n_ways as Amount);

            let odd_compensation = if (i as Amount) < leftover { 1 } else { 0 };
            equal_parts + odd_compensation
        })
    }

    const DBC_WITH_1_530_000_000: &str = "2fce3f70d7ad38d48d81f3f67c11ea10388a95efff66ce444f3274fb261c119a839e3de7a4c97b3b2b12fde3af09990ed20f48b3a23d79ca9b39cf0b6f492b142c03d3c0ee34d087fa3b9989cab7f7fb4e2328587330ce226277b8062881b3a231b11365712ad3a82ece13af3699fb171f16001af12522a92d1cf6d788a919bf7aa7bc1cd70f0eac4f96967bdd9cb38338aab683457882ebc8dc80cd829f9e292837a00789952636524a544ae1fada10439ed9478b6d0127c5fd13ed74e9e1870000000000000001c428455eb4b5485f9465049a3a1b519a89b50ec3bef0c4ebbf45b7198cc348321ca2ae5ab0ed3dc52cc9cd341c4a482e9d9f5f2d81d981a11032821603b863baa19a900087052a2f799092f29d7e2c8b00000000000000016caf52b6919fa145146588809f6c0d2a0b70053c9501a52730bbfba00de94dfe72f14801d29d5b2d93c8b626d443498d34bf24d89d5012a6067ccb301919272553dcdf50cbf95240e47a3c7e967ba98e70b2a97e866c810a0ba806bb96a1b8308eb9b22b29b44ea5d33ae9e9c057261b09e21456123981952224dbf9cadfd50cfb02e0dc57ce55156f844c3a2c704a5be432d2444765dd15beb7fca57a20508f73df1043f8e2e5d8a56a2fb17fe475f2cca88c8d23eae27f3d172e3d6fad45c1b3232dc10ee46a7016df417935865a99b3761bffdefea6373584f50258ab9d60cddfc80ed76c9454bcaa8083f58e6c53d3095e06b02638eccd668031cf232b87ea9474b4166849a34ffbc805310520c8b19bafa7424df714becb9ce02d6d705b51b168a0b806798da550a0807fc1a8a9122908dbbd7e4838e65a9c9bdbc1fbf3e11a79187444274a828618e4debbcc3cee1ea0d1a157f21b8624bccc8eb58c91a60d84deb16ac42241ace0f3174c3abbca0d3331990e7c6db07ff24c8537060ea76348f96af31927c49c84a4e2c4cb8cdd95f86c0fcc18cb1d6c2a519ced3ad2e9903061dd3f3c8e02fafd969f53f52274faddb0b4f5aef19dc0e62277cbcda3e3ac39cfa4b709efbbdab65440a42e628fff051c83acd583a5e3bbfb2eb4807c5aa2303c7b52f1d539899572b674bd8fb4a529354e8087067a4e374e92b855a7ec523295867f310f7cea5d48bb0295a1c3ea47b6c4229f000d0c83ae22eb449656c25083a5fc99f99a23cf25fc2020941ffb392b3c8788c25b687b21610d35e3a5f12974b20778144d6930772381a694be5605f21142ca2121a7358e377fd20d50ff00ae3550aa2622ac8d8a642c41aec117b74c22732b297dbb4e4637595bb5b7d5a69414c7822e55efb9c40ddbc2a293532ee49c705e9bb2f3fff3f2dcce8c72b90c486b3a750ee594fd2b04c2dd9553e02a226001956bed24790349d243ca5d51167c4a348d19e42bf2cabc72c0510b8217e0ce5997b763fd11a881c8757f565e3ca3766fc5c3e011ad40d634666859a3a5fdbab6fb627c5abd1d80894424c5a1b0de74cfdf5eb17b9c8bb873f4515adc3e9d62d76f4f5bbb0ef453e369ad5ffa853ab6661f2bf242d91d098f5c59ceb4c1151b47f4cd5ee9dc98daca45898168f4ff69fb230d01d7660d0718cc1b6facbb7f8e9a73cb6a8b93aba7dddc450628588fbb916641abaab4a228bc2584950e34f86a8154b4f5773d07a4ad70b9c2fdff3d16933011664e8de0298c61cd2da7511b8a0cd63acf47156bd7f667929fce5b7257582f336683abf609ad7a4b9dca4395849d81da230d13822d01224d49f4d249d9881d2e876335824514448300000000000003a00af4916a22e0177947732d2d58db7e0325d004f1de5718b3275ae009845fa53ce6948ddd9623e445c8433d30c162c9a22b05a80d417ac2efc2bf684e091bc26a81bda1ec9253ed4657c2440710623741007bdb90e9d94121babea7484d25a49432e71b55250be2a5c8ac7716ec2c61218cca98458ae648e11d31c185d20e1eb21300e7b360f1553a128ff97d54c1510a26178421859bef1dae17e4cf496acc39b20059e48b5c94c7ab244dbfc368d12868af7cac467d8c18e8cb5b60c22b7e9151e013dd28b813254e65a73c24c0efae47b29cdc3a34286dabb6fd09d9ad8b121655394d272934013773667eae726cdbab0b42cfc2c0bd988ecacafead6f179046fa3a4f5fb8ca7a790e5685f262c0e770c20a700fdab00aeac3a8634d84102f750996b5323356ad1b3199702c2d23a64279726f35e0eb630f91794dda905093995d6b457782792564be257a191f2bdeedd01e76051f7aa740735b8c408c618b3b6edac93f7504d441855d89adb6e13ed2a60c81ac0a0b445a2d1447bc30f0f30376ab55995ad0b639c1dfddb3e29e8f8ddccb59e55d863117ca6bc1c8dbf42983ea889cd03b19ab7c76addddb6dbdd53856b92df8cc929f3d37eb27ba6ab68194fc55f9ca2943acd265538751335cdbf527675494d176282e59a9c8deb95645b5b2b8660456434701b182e08915dbb6de5bfacc5480e867a9f08c8fe2d209eaa44175912ce5fb782425e264587d8ad13a70eb83d0ac0b02095a8f6d029d588b80b4f7a96c73720344247eae9613a9ff6ca368dbd823c225304725a36aee0c1822fe554733bc074c50ea296ff6b60c8711f7ef216e1ff1b532b398ba13e6da8ebd4546dcf296a4c1f7b27da5ec6e771d23afc139af51d5e9b5f2be9f32a7ab949e86cb5158c0f61b5a31f81e9c9ddc8412fcdf971a7cc296e742bcae1d444928152841a927dd7985bb7ef06c1fcfa9a1b908e6b0f52a38321f325f4bff3af4064ce8266c93821bb81f9a0404ffff81520ff370ba1b831cae5db58cb943e59dac65a9092db9fb12b00424c49dc0b92356a5b2801c40b43f8d5262278b44eb980e5857397b6ec9570dde9ca80b5ab041bf81872f3f999182589771a75c8ef0e3b8603888dade9b1d449adaac0f08c7cddbe85df0871722ded236de4b7e5f999ad3f2c8e01cab184eaec5f2fa35b22586e7838e4dde010a37ff24927c8a4845794ee699ab54b57ba50e038008af5ea0bbaf3f4e627fe03809f973980b81ced08a602b7458158ab7684376535265761dc039bb13d01ff90e732b8df17d783338db830193034d48dca8ed42b077293db0aa1da1b14c0c4c0e76c7859b832a226464e2cad01aa41bf8fd1686933b55fd961ab336cdb697e851bf3b6c1142019475e0b2925d6727e15de30cbf7b342daf509778d2af676c53a3e962ddff846c310d768e00000000000003a058998e2c08c59208820948b33b051910a3156d3beff7984798c030f971904a9085c61447ded4a76575b5fcc40b5acd93b1d0b17ba74231d94f3df0f666e751067fdc9364a3a5d07ce0881d44fabf4cf0f478a2ec3d14a668e3e5f249d57138890a5db2846b458f82e77256f2f4b3f1412b0434831aad2b96fed8c9ed2e520a5c54ddfb9f72ee0932eea6ab7a58b2f14c5ef062717e9d1da9c7f213dd11bed65bd7693398c732e08b6fe96095c68e4d7e2d3378c3632e736358e88db56bad7329bfd83bac50c0649fcf4f8baf1f95a3b16a004a02b8d0a469b687ee7f91743232a46ae0eb27d0f45d18dcbc04aeb9595995802a4ddf42f2712248d38d5b7656916211ecc6bbfb4c62b6f9d3393061ead919662e53f356bf2327536dccedd7eee28b06514de978fcc965a3d6d507aba3b3af78e3ac52e3141e9fc1b51302616138f2e14ba340d1baea0b2d3d65e21fc94545f17e956292b4cfa8eaecdfa46344a88eb15f9e230a384caefaced24f6553f5ba7c7e41f9c9bbec71a9a5d8a33b994b6d1ce62a1334351057838c2fbe0aa3a204c17fb11e1970f36a8ef3a16d634890a98dee795c197ad586a5c0cf5a23e72d5931481ddf33a342c5bcc320965b98b46bfc2c51a106ce2dedc8f7196b1af0f30825854d5a34d7fc398aea4548e13d0289fe76ec71f4d9531e56d44d39562ca349fd9b62321e28e7d1c1c406199b5dd4841e12d1c649e9e3dd7db84c8499f61621c188fcf56da4915001bc82a8b8aaafa7001486df8dc215d02261640dfce04c79ba5d66ea5daec4fe8a7f2e39527c8c5ca8d8e05fe00e9f909d49a852a9c2ab96f185aa63ccd5e542b0355d8ee66b252a5a57ab0b30c704ea8055eea246d5700c0aadf23520a445e70b331b24fb8f8c43739403cba21d87a6a63e05cddfcf6934230c4f9420b796b70df0eb70f0c1a94c09c70b7e1bb6e2494fe4ae028c358a9048404e31e6191749b83f8cc942fc796459ce1669ea7c268d3c55cb2be9e8ed54400cd831c974fe59d63b043963e98330c7179038c3be277bcb8d9713234a48a7f2e84bdc41c6f822e7292a02407c9966834fc014727d1aa86ca08f39d5fb53b745bb16d2eb11f23af7955b1a5507ff670dc39d8bd929a2ac8ad2e72ed27d36c386223672d434474f9149d39079bd72977f573bee8686584eddcb1467c24c16a38b0e6f6a9c727f7cca2b7a7a86589fa507438ee0bdaa383ddb95ac2d3abe8d07fe06dc4980bbf6423d7496d4283f85cfc9dc79091eb8695d583ebf31a6aad857a6510e3bf268b634ec62ee7112be92a89633f394792332d8e0f5fcff45353bf8e55db172dae5d60dacd372c1e47f9ce8d497f7a18438fe6a3930c240b29ab1d91176ebd5934d23230b629f46f294f9926d4f33c5ba2c1cee78df2b3bb2d43c67423751cfd78ec652596dec00a06db900000000000003a0d28d2cf0c4c23a0ae40ab3a4a29ed7eaa11a3957bf5ee7b8e61c4f3858982f5fe8f40bb19cf728f76121c2cd51ab9a970000000000000003e8c9885501863a2462cf63cd2d4109746aeda1643d286fd6fb13014bef689dc66b34b6e5a6f83e88aead415c06737aaee5eb3c7fda86f635b3345c72329088cbae5eb375e33f880727993c4c01b736f93fc1520f3fa1b41a8c8eb7002dd6a1a996535faeae2d5b27e4c0b37f2d8667128dbe048a2814ce4d24fc60f7a0dda7c87e1d3b30254c25aba701ff6eeb9ebe8800000000000000011ca2ae5ab0ed3dc52cc9cd341c4a482e9d9f5f2d81d981a11032821603b863baa19a900087052a2f799092f29d7e2c8b158a686df05f9cb8c9f01f6499b27d21c499d31ad7d8274c4dff49192e73c184018a600ba8fc0e3734dd643706ae2af8922fffa4574a630845a4a91f0ce23518000000000000000125cf08c3ee49b669e5cfb0ad13de8e19691287addf6b5228a78fc769ce76c74e0000000000000001975d70bd51172f6374af4a6caef9cf309579710d8de8544924a4b3e1dea66268cbb03d16b627871f3953107611f586177d5513c8577e1f1d6fe32db8e15652c342c3962968a07e584544049e05cfcc50692e5dc7dbb8eaf492c6b8191083f1a363b6ab807e54f04f4a7d0dd03097354d733baa72c8c74fd4705afdca689209f566a27c010f60cc64000000000000002886ec356465a6f1f026d858b4379d94d26c85b519261f1aec7ef751dbb7047e0a0d4c5c554d6c0859d3f81ffc8c67d5923165c636f32ee6cf3aee685d84a38cd411a0007ab583cc18985830be0c634b132890055ab792751ac4154645f5fc0a00697d0b202f3bc1ed194875eb59dcacc7482ce06feb934e8409ba391e56537c02b599c54b173e9ac920d9f14af16cfa9649bd35c0d4b1425f35f9c2f49f7c441b9c02bc2eb97e318b76aa4dabc55a76f40000000000000020c0f8550862860085c4f90ac96b053dfa355be3de55a341c24ea20c3ae0050e4649bbf5aa9b06c678717d7582308bd68aafdf11a379bc34056f56c762e11d1340239b777df26c543ff1e61fd0066e842400000000";

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
            dbc_builder =
                dbc_builder.add_spent_proof_share(spentbook_node.log_spent(key_image, tx)?);
        }

        Ok(dbc_builder)
    }

    #[test]
    fn from_hex_should_deserialize_a_hex_encoded_string_to_a_dbc() -> Result<(), Error> {
        let dbc = Dbc::from_hex(DBC_WITH_1_530_000_000)?;
        let amount = dbc.amount_secrets_bearer()?.amount();
        assert_eq!(amount, 1_530_000_000);
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
        };

        let hex = dbc.to_hex()?;

        let dbc_from_hex = Dbc::from_hex(&hex)?;
        let left = dbc.amount_secrets_bearer()?.amount();
        let right = dbc_from_hex.amount_secrets_bearer()?.amount();
        assert_eq!(left, right);
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
        };

        let id = crate::bls_dkg_id(&mut rng);
        let key_manager = mock::KeyManager::from(mock::Signer::from(id));

        assert!(matches!(
            dbc.verify(&owner_once.owner_base().secret_key()?, &key_manager),
            Err(Error::RingCt(bls_ringct::Error::TransactionMustHaveAnInput))
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
            generate_dbc_of_value(amount, &mut rng)?;

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
            .add_output_by_amount(amount, owner_once.clone())
            .build(&mut rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder =
                dbc_builder.add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?);
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
            amount + extra_output_amount.coerce::<Amount>(),
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
                let sig_share = key_manager.sign(&spent_proof.content.hash()).unwrap();
                let sig = key_manager
                    .public_key_set()?
                    .combine_signatures(vec![sig_share.threshold_crypto()])
                    .unwrap();

                let fuzzed_sp = SpentProof {
                    content: spent_proof.content.clone(),
                    spentbook_pub_key: key_manager.public_key_set()?.public_key(),
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
                let wrong_msg_sig_share =
                    spentbook_node.key_manager.sign(&Hash([0u8; 32])).unwrap();
                let wrong_msg_sig = spentbook_node
                    .key_manager
                    .public_key_set()?
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

                let sig_share = spentbook_node.key_manager.sign(&content.hash()).unwrap();
                let sig = spentbook_node
                    .key_manager
                    .public_key_set()?
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

        let dbcs = dbc_builder.build(&spentbook_node.key_manager)?;
        let (dbc_valid, ..) = &dbcs[0];

        let dbc = Dbc {
            content: fuzzed_content,
            transaction: dbc_valid.transaction.clone(),
            spent_proofs: fuzzed_spent_proofs,
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

                assert_eq!(dbc_amount, amount);
                assert_eq!(extra_output_amount.coerce::<u8>(), 0);
            }
            Err(Error::SpentProofInputLenMismatch) => {
                assert_ne!(dbc.spent_proofs.len(), dbc.transaction.mlsags.len());
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
            Err(Error::RingCt(bls_ringct::Error::TransactionMustHaveAnInput)) => {
                assert_eq!(n_inputs.coerce::<u8>(), 0);
            }
            Err(Error::AmountCommitmentsDoNotMatch) => {
                assert_ne!(amount, dbc_amount);
                assert_ne!(extra_output_amount, TinyInt(0));
            }
            Err(Error::InvalidSpentProofSignature(_pk, _msg)) => {
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

    pub(crate) fn generate_dbc_of_value(
        amount: Amount,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(mock::SpentBookNode, Dbc, Dbc, Dbc)> {
        let (mut spentbook_node, genesis_dbc, _genesis_material, _amount_secrets) =
            mock::GenesisBuilder::init_genesis_single(rng)?;

        let output_amounts = vec![amount, GenesisMaterial::GENESIS_AMOUNT - amount];

        let mut dbc_builder = crate::TransactionBuilder::default()
            .set_require_all_decoys(false)
            .add_input_by_secrets(
                genesis_dbc.owner_once_bearer()?.secret_key()?,
                genesis_dbc.amount_secrets_bearer()?,
            )
            .add_outputs_by_amount(output_amounts.into_iter().map(|amount| {
                (
                    amount,
                    OwnerOnce::from_owner_base(Owner::from_random_secret_key(rng), rng),
                )
            }))
            .build(rng)?;

        for (key_image, tx) in dbc_builder.inputs() {
            dbc_builder =
                dbc_builder.add_spent_proof_share(spentbook_node.log_spent(key_image, tx.clone())?);
        }

        let mut iter = dbc_builder.build(&spentbook_node.key_manager)?.into_iter();
        let (starting_dbc, ..) = iter.next().unwrap();
        let (change_dbc, ..) = iter.next().unwrap();

        Ok((spentbook_node, genesis_dbc, starting_dbc, change_dbc))
    }
}
