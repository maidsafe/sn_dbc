// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::fmt;

mod amount_secrets;
mod blst;
mod builder;
mod dbc;
mod dbc_content;
mod error;
mod mint;
mod owner;
mod spent_proof;
mod token;
mod transaction;
mod verification;

#[cfg(feature = "mock")]
pub mod mock;

// re-export crates used in our public API
pub use blsttc;
pub use blsttc::rand;
pub use blsttc::{PublicKey, PublicKeySet, Signature, SignatureShare};
pub use bulletproofs::PedersenGens;

pub use crate::{
    amount_secrets::AmountSecrets,
    blst::{BlindingFactor, Commitment},
    builder::{DbcBuilder, OutputOwnerMap, TransactionBuilder},
    dbc::Dbc,
    dbc_content::DbcContent,
    error::{Error, Result},
    owner::{DerivationIndex, Owner, OwnerOnce},
    spent_proof::{
        IndexedSignatureShare, SpentProof, SpentProofContent, SpentProofKeyVerifier,
        SpentProofShare,
    },
    token::Token,
    transaction::{
        Amount, DbcTransaction, Input, Output, OutputProof, RevealedCommitment, RevealedInput,
        RevealedTransaction,
    },
    verification::{get_public_commitments_from_transaction, TransactionVerifier},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// This is a helper module to make it a bit easier
/// and regular for API callers to instantiate
/// an Rng when calling sn_dbc methods that require
/// them.
pub mod rng {
    use crate::rand::{
        rngs::{StdRng, ThreadRng},
        SeedableRng,
    };

    pub fn thread_rng() -> ThreadRng {
        crate::rand::thread_rng()
    }

    pub fn from_seed(seed: <StdRng as SeedableRng>::Seed) -> StdRng {
        StdRng::from_seed(seed)
    }
}

#[cfg(test)]
use {
    crate::rand::RngCore,
    blsttc::{SecretKeySet, SecretKeyShare},
};

#[cfg(test)]
pub fn bls_dkg_id(rng: &mut impl RngCore) -> (PublicKeySet, SecretKeyShare, usize) {
    let sks = SecretKeySet::random(0, rng);
    (sks.public_keys(), sks.secret_key_share(0), 0)
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
    pub struct TinyInt(pub u8);

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
    pub struct NonZeroTinyInt(pub NonZeroU8);

    impl NonZeroTinyInt {
        pub fn coerce<T: From<u8>>(self) -> T {
            self.0.get().into()
        }
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
    pub struct TinyVec<T>(pub Vec<T>);

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
