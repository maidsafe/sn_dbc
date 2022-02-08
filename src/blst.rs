// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This module defines blstrs aliases, wrappers, and helpers.
//!
//! blstrs types Scalar and G1Affine are used to represent distinct concepts
//! in ringct such as:
//!   Scalar:    SecretKey, BlindingFactor
//!   G1Affine:  Commitment, PublicKey, KeyImage
//!
//! We provide type aliases to make the usage in each context clearer and to make the
//! the sn_dbc public API simpler so that the caller should not need to depend on blstrs
//! and use its types directly.
//!
//! Even sn_dbc uses the type aliases rather than directly using the blstrs types.
//!
//! We could consider moving some or all of this lower into blst_ringct to make these
//! crates consistent.

use blstrs::{G1Affine, Scalar};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use blsttc::{PublicKey, SecretKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// a SecretKey in Blst format
pub type SecretKeyBlst = Scalar;

/// a PublicKey in Blst format
pub type PublicKeyBlst = G1Affine;

/// a Commitment
pub type Commitment = G1Affine;

/// a BlindingFactor
pub type BlindingFactor = Scalar;

/// A KeyImage, which is derived from pk and sk
pub type KeyImage = PublicKeyBlstMappable;

// This is a NewType wrapper for blstrs::G1Affine because in places we
// need to use it as a key in a BTreeMap.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct PublicKeyBlstMappable(G1Affine);

impl PublicKeyBlstMappable {
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }
}

impl PartialEq for KeyImage {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_compressed() == other.0.to_compressed()
    }
}

impl AsRef<G1Affine> for KeyImage {
    fn as_ref(&self) -> &G1Affine {
        &self.0
    }
}

impl Eq for PublicKeyBlstMappable {}

impl PartialOrd for KeyImage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKeyBlstMappable {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_compressed().cmp(&other.0.to_compressed())
    }
}

impl Hash for PublicKeyBlstMappable {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = self.0.to_compressed();
        bytes.hash(state);
    }
}

impl From<G1Affine> for PublicKeyBlstMappable {
    fn from(k: G1Affine) -> Self {
        Self(k)
    }
}

// temporary: should go away once blsttc is integrated with with blstrs
pub struct BlsHelper {}

impl BlsHelper {
    #[allow(dead_code)]
    pub fn blsttc_to_blstrs_secret_key(sk: SecretKey) -> SecretKeyBlst {
        let bytes = sk.to_bytes();
        SecretKeyBlst::from_bytes_be(&bytes).unwrap()
    }

    pub fn blsttc_to_blstrs_public_key(pk: &PublicKey) -> PublicKeyBlst {
        let bytes = pk.to_bytes();
        // fixme: unwrap
        PublicKeyBlst::from_compressed(&bytes).unwrap()
    }

    pub fn blstrs_to_blsttc_public_key(pk: &PublicKeyBlst) -> PublicKey {
        let bytes = pk.to_compressed();
        // fixme: unwrap
        PublicKey::from_bytes(bytes).unwrap()
    }

    pub fn blstrs_to_blsttc_secret_key(sk: SecretKeyBlst) -> SecretKey {
        let bytes = sk.to_bytes_be();
        // fixme: unwrap
        SecretKey::from_bytes(bytes).unwrap()
    }
}
