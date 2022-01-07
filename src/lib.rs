// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
#![allow(clippy::from_iter_instead_of_collect)]

use serde::{Deserialize, Serialize};
use std::fmt;

mod amount_secrets;
mod builder;
mod dbc;
mod dbc_content;
// mod dbc_packet;
mod error;
mod key_manager;
mod mint;
mod spent_proof;

pub use crate::{
    amount_secrets::AmountSecrets,
    builder::{DbcBuilder, Output, ReissueRequestBuilder, TransactionBuilder},
    dbc::{Dbc, KeyImage},
    dbc_content::{Amount, DbcContent},
    // dbc_packet::{DbcPacket, DerivedKeySet},
    error::{Error, Result},
    key_manager::{
        KeyManager, NodeSignature, PublicKey, PublicKeySet, Signature, SimpleKeyManager,
        SimpleSigner,
    },
    mint::{
        genesis_dbc_input, GenesisDbcShare, MintNode, MintNodeSignatures, ReissueRequest,
        ReissueShare,
    },
    spent_proof::{SpentProof, SpentProofShare},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    #[allow(clippy::self_named_constructors)]
    /// sha3 256 hash
    pub fn hash(input: &[u8]) -> Self {
        Self::from(sha3_256(input))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(val: [u8; 32]) -> Hash {
        Hash(val)
    }
}

// Display Hash value as hex in Debug output.  consolidates 36 lines to 3 for pretty output
// and the hex value is the same as sn_dbc_mint display of DBC IDs.
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash").field(&hex::encode(self.0)).finish()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "dkg")]
use rand::RngCore;

#[cfg(feature = "dkg")]
pub fn bls_dkg_id(mut rng: impl RngCore) -> bls_dkg::outcome::Outcome {
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    let mut owner_name = [0u8; 32];
    rng.fill_bytes(&mut owner_name);
    let owner_xorname = xor_name::XorName::from_content(&owner_name);

    let threshold = 0;
    let (mut key_gen, proposal) = bls_dkg::KeyGen::initialize(
        owner_xorname,
        threshold,
        BTreeSet::from_iter([owner_xorname]),
    )
    .expect("Failed to init key gen");

    let mut msgs = vec![proposal];
    while let Some(msg) = msgs.pop() {
        let response_msgs = key_gen
            .handle_message(&mut rng, msg)
            .expect("Error while generating BLS key");

        msgs.extend(response_msgs);
    }

    let (_, outcome) = key_gen.generate_keys().unwrap();
    outcome
}

#[cfg(feature = "dkg")]
use blsttc::{Ciphertext, SecretKey};

#[cfg(feature = "dkg")]
use blstrs::{G1Affine, Scalar};

#[cfg(feature = "dkg")]
use std::convert::TryFrom;

#[cfg(feature = "dkg")]
pub struct DbcHelper {}

#[cfg(feature = "dkg")]
impl DbcHelper {
    #[allow(dead_code)]
    pub(crate) fn blsttc_to_blstrs_sk(sk: SecretKey) -> Scalar {
        let bytes = sk.to_bytes();
        println!("sk bytes: {:?}", bytes);
        Scalar::from_bytes_be(&bytes).unwrap()
    }

    pub(crate) fn blsttc_to_blstrs_pubkey(pk: &PublicKey) -> G1Affine {
        let bytes = pk.to_bytes();
        G1Affine::from_compressed(&bytes).unwrap()
    }

    pub(crate) fn blstrs_to_blsttc_pubkey(pk: &G1Affine) -> PublicKey {
        let bytes = pk.to_compressed();
        PublicKey::from_bytes(bytes).unwrap()
    }

    pub fn decrypt_amount_secrets(
        owner: &bls_dkg::outcome::Outcome,
        ciphertext: &Ciphertext,
    ) -> Result<AmountSecrets, Error> {
        let mut shares: std::collections::BTreeMap<usize, bls_dkg::SecretKeyShare> =
            Default::default();
        shares.insert(owner.index, owner.secret_key_share.clone());
        AmountSecrets::try_from((&owner.public_key_set, &shares, ciphertext))
    }

    pub fn decrypt_amount(
        owner: &bls_dkg::outcome::Outcome,
        ciphertext: &Ciphertext,
    ) -> Result<Amount, Error> {
        Ok(Self::decrypt_amount_secrets(owner, ciphertext)?.amount())
    }
}

pub(crate) fn sha3_256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Sha3};

    let mut sha3 = Sha3::v256();
    let mut output = [0; 32];
    sha3.update(input);
    sha3.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU8;
    use quickcheck::{Arbitrary, Gen};

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TinyInt(u8);

    impl TinyInt {
        pub fn coerce<T: From<u8>>(self) -> T {
            self.0.into()
        }
    }

    impl std::fmt::Debug for TinyInt {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Arbitrary for TinyInt {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(u8::arbitrary(g) % 5)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new((0..(self.0)).into_iter().rev().map(Self))
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct NonZeroTinyInt(NonZeroU8);

    impl NonZeroTinyInt {
        // pub fn coerce<T: From<u8>>(self) -> T {
        //     self.0.get().into()
        // }
    }

    impl std::fmt::Debug for NonZeroTinyInt {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Arbitrary for NonZeroTinyInt {
        fn arbitrary(g: &mut Gen) -> Self {
            let r = NonZeroU8::new(u8::arbitrary(g) % 4 + 1)
                .unwrap_or_else(|| panic!("Failed to generate an arbitrary non-zero u8"));
            Self(r)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(
                (1..(self.0.get()))
                    .into_iter()
                    .rev()
                    .filter_map(NonZeroU8::new)
                    .map(Self),
            )
        }
    }

    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TinyVec<T>(Vec<T>);

    impl<T> TinyVec<T> {
        pub fn into_iter(self) -> impl Iterator<Item = T> {
            self.0.into_iter()
        }
    }

    impl<T: std::fmt::Debug> std::fmt::Debug for TinyVec<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }

    impl<T: Arbitrary> Arbitrary for TinyVec<T> {
        fn arbitrary(g: &mut Gen) -> Self {
            let n = u8::arbitrary(g) % 7;
            let mut vec = Vec::new();
            for _ in 0..n {
                vec.push(T::arbitrary(g));
            }
            Self(vec)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(self.0.shrink().map(Self))
        }
    }

    #[test]
    fn hash() {
        let data = b"hello world";
        let expected = b"\
    \x64\x4b\xcc\x7e\x56\x43\x73\x04\x09\x99\xaa\xc8\x9e\x76\x22\xf3\
    \xca\x71\xfb\xa1\xd9\x72\xfd\x94\xa3\x1c\x3b\xfb\xf2\x4e\x39\x38\
";
        assert_eq!(sha3_256(data), *expected);
    }
}
