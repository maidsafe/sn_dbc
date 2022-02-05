// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
#![allow(clippy::from_iter_instead_of_collect)]

use std::fmt;

mod amount_secrets;
mod blst;
mod builder;
mod dbc;
mod dbc_content;
mod derived_owner;
mod error;
mod key_manager;
mod mint;
mod spent_proof;
mod spentbook;
mod validation;

pub use crate::{
    amount_secrets::AmountSecrets,
    blst::{BlindingFactor, BlsHelper, Commitment, KeyImage, PublicKeyBlst, SecretKeyBlst},
    builder::{DbcBuilder, Output, OutputOwnerMap, ReissueRequestBuilder, TransactionBuilder},
    dbc::Dbc,
    dbc_content::{Amount, DbcContent},
    derived_owner::{DerivationIndex, DerivedOwner, Owner},
    error::{Error, Result},
    key_manager::{
        KeyManager, NodeSignature, PublicKey, PublicKeySet, Signature, SimpleKeyManager,
        SimpleSigner,
    },
    mint::{GenesisDbcShare, MintNode, MintNodeSignatures, ReissueRequest, ReissueShare},
    spent_proof::{SpentProof, SpentProofShare},
    spentbook::SpentBookNodeMock,
    validation::TransactionValidator,
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
    use std::collections::BTreeMap;

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

    pub(crate) fn init_genesis(
        mut rng: impl rand::RngCore,
        mut rng8: impl rand8::RngCore + rand_core::CryptoRng,
        genesis_amount: Amount,
    ) -> Result<(
        MintNode<SimpleKeyManager>,
        SpentBookNodeMock,
        GenesisDbcShare,
        Dbc,
    )> {
        use std::collections::BTreeSet;
        use std::iter::FromIterator;

        let mut spentbook = SpentBookNodeMock::from(SimpleKeyManager::from(SimpleSigner::from(
            crate::bls_dkg_id(&mut rng),
        )));

        let (mint_node, genesis) = MintNode::new(SimpleKeyManager::from(SimpleSigner::from(
            crate::bls_dkg_id(&mut rng),
        )))
        .trust_spentbook_public_key(spentbook.key_manager.public_key_set()?.public_key())?
        .issue_genesis_dbc(genesis_amount, &mut rng8)?;

        spentbook.set_genesis(&genesis.ringct_material);

        let mint_sig = mint_node
            .key_manager()
            .public_key_set()?
            .combine_signatures(vec![genesis.transaction_sig.threshold_crypto()])?;

        let spent_proof_share =
            spentbook.log_spent(genesis.input_key_image.clone(), genesis.transaction.clone())?;

        let spentbook_sig =
            spent_proof_share
                .spentbook_pks
                .combine_signatures(vec![spent_proof_share
                    .spentbook_sig_share
                    .threshold_crypto()])?;

        let tx_hash = Hash::from(genesis.transaction.hash());
        assert!(spent_proof_share
            .spentbook_pks
            .public_key()
            .verify(&spentbook_sig, &tx_hash));

        let spent_proofs = BTreeSet::from_iter([SpentProof {
            key_image: spent_proof_share.key_image,
            spentbook_pub_key: spent_proof_share.spentbook_pks.public_key(),
            spentbook_sig,
            public_commitments: spent_proof_share.public_commitments,
        }]);

        let genesis_dbc = Dbc {
            content: genesis.dbc_content.clone(),
            transaction: genesis.transaction.clone(),
            transaction_sigs: BTreeMap::from_iter([(
                genesis.input_key_image.clone(),
                (
                    mint_node.key_manager().public_key_set()?.public_key(),
                    mint_sig,
                ),
            )]),
            spent_proofs,
        };

        Ok((mint_node, spentbook, genesis, genesis_dbc))
    }
}
