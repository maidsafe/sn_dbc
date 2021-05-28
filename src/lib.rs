// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
#![feature(test)] // required for #[bench] macro
#![allow(clippy::from_iter_instead_of_collect)]

use serde::{Deserialize, Serialize};
use std::ops::Deref;
#[cfg(test)]
use tiny_keccak::{Hasher, Sha3};
/// These typdefs are to simplify algorithm for now and will be removed for production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash([u8; 32]);
pub(crate) type DbcContentHash = Hash;
mod dbc;
mod dbc_content;
mod dbc_transaction;
mod error;
mod key_manager;
mod mint;

pub use crate::{
    dbc::Dbc,
    dbc_content::{BlindedOwner, DbcContent},
    dbc_transaction::DbcTransaction,
    error::{Error, Result},
    key_manager::{ChainNode, KeyCache, KeyManager, PublicKey, Signature},
    mint::{Mint, MintRequest, MintTransaction},
};

impl From<[u8; 32]> for Hash {
    fn from(val: [u8; 32]) -> Hash {
        Hash(val)
    }
}

impl Deref for Hash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
use rand::distributions::{Distribution, Standard};

#[cfg(test)]
use rand::Rng;

#[cfg(test)]
/// used when fuzzing DBC's in testing.
impl Distribution<Hash> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Hash {
        Hash(rng.gen())
    }
}

#[cfg(test)]
pub(crate) fn bls_dkg_id() -> bls_dkg::outcome::Outcome {
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    let owner_name = rand::random();
    let threshold = 0;
    let (mut key_gen, proposal) = match bls_dkg::KeyGen::initialize(
        owner_name,
        threshold,
        BTreeSet::from_iter(vec![owner_name]),
    ) {
        Ok(key_gen_init) => key_gen_init,
        Err(e) => panic!("Failed to init key gen {:?}", e),
    };

    let mut msgs = vec![proposal];
    while let Some(msg) = msgs.pop() {
        match key_gen.handle_message(&mut rand::thread_rng(), msg) {
            Ok(response_msgs) => msgs.extend(response_msgs),
            Err(e) => panic!("Error while generating BLS key: {:?}", e),
        }
    }

    let (_, outcome) = key_gen.generate_keys().unwrap();
    outcome
}

#[cfg(test)]
fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut output = [0; 32];
    sha3.update(input);
    sha3.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    extern crate test;

    use super::*;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::iter::FromIterator;

    use core::num::NonZeroU8;
    use quickcheck::{Arbitrary, Gen};
    use test::Bencher;

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

    fn genesis(amount: u64) -> (Mint, bls_dkg::outcome::Outcome, Dbc) {
        let genesis_owner = bls_dkg_id();
        let (genesis, genesis_dbc) = Mint::genesis(genesis_owner.public_key_set.clone(), amount);

        (genesis, genesis_owner, genesis_dbc)
    }

    #[bench]
    fn bench_reissue_1_to_100(b: &mut Bencher) {
        let n_outputs: u32 = 100;
        let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);

        let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let output_owner = bls_dkg_id();
        let owner_pub_key = output_owner.public_key_set.public_key();
        let outputs = (0..n_outputs)
            .into_iter()
            .map(|i| DbcContent::new(input_hashes.clone(), 1, i, owner_pub_key))
            .collect();

        let transaction = MintTransaction { inputs, outputs };

        let sig_share = genesis_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(
                genesis_dbc.name(),
                (genesis_owner.public_key_set.public_key(), sig),
            )]),
        };

        let spendbook = genesis.snapshot_spendbook();
        b.iter(|| {
            genesis.reset_spendbook(spendbook.clone());
            genesis
                .reissue(mint_request.clone(), input_hashes.clone())
                .unwrap();
        });
    }

    #[bench]
    fn bench_reissue_100_to_1(b: &mut Bencher) {
        let n_outputs: u32 = 100;
        let (mut genesis, genesis_owner, genesis_dbc) = genesis(n_outputs as u64);

        let inputs = HashSet::from_iter(vec![genesis_dbc.clone()]);
        let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

        let owners: Vec<_> = (0..n_outputs).into_iter().map(|_| bls_dkg_id()).collect();
        let outputs = Vec::from_iter((0..n_outputs).into_iter().map(|i| {
            DbcContent::new(
                input_hashes.clone(),
                1,
                i,
                owners[i as usize].public_key_set.public_key(),
            )
        }));

        let transaction = MintTransaction {
            inputs,
            outputs: HashSet::from_iter(outputs.clone()),
        };

        let sig_share = genesis_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();

        let mint_request = MintRequest {
            transaction,
            input_ownership_proofs: HashMap::from_iter(vec![(
                genesis_dbc.name(),
                (genesis_owner.public_key_set.public_key(), sig),
            )]),
        };

        let (transaction, transaction_sigs) = genesis
            .reissue(mint_request.clone(), input_hashes.clone())
            .unwrap();

        let dbcs = Vec::from_iter(outputs.into_iter().map(|content| Dbc {
            content,
            transaction: transaction.clone(),
            transaction_sigs: transaction_sigs.clone(),
        }));

        let merged_output = DbcContent::new(
            BTreeSet::from_iter(dbcs.iter().map(Dbc::name)),
            n_outputs as u64,
            0,
            bls_dkg_id().public_key_set.public_key(),
        );

        let merge_transaction = MintTransaction {
            inputs: HashSet::from_iter(dbcs.clone()),
            outputs: HashSet::from_iter([merged_output]),
        };

        let input_ownership_proofs = HashMap::from_iter(dbcs.iter().enumerate().map(|(i, dbc)| {
            let sig_share = owners[i]
                .secret_key_share
                .sign(merge_transaction.blinded().hash());
            let sig = owners[i]
                .public_key_set
                .combine_signatures(vec![(0, &sig_share)])
                .unwrap();
            (dbc.name(), (owners[i].public_key_set.public_key(), sig))
        }));

        let merge_mint_request = MintRequest {
            transaction: merge_transaction,
            input_ownership_proofs,
        };
        let inputs = merge_mint_request.transaction.blinded().inputs;

        let spendbook = genesis.snapshot_spendbook();
        b.iter(|| {
            genesis.reset_spendbook(spendbook.clone());
            genesis
                .reissue(merge_mint_request.clone(), inputs.clone())
                .unwrap();
        });
    }
}
