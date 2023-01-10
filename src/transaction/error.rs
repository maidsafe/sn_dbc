// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("We need a corresponding public key for each MLSAG ring entry")]
    ExpectedAPublicCommitmentsForEachRingEntry,
    #[error("The hidden commitment in the MLSAG ring must be of the form: $C - C'$")]
    InvalidHiddenCommitmentInRing,
    #[error("InputPseudoCommitmentsDoNotSumToOutputCommitments")]
    InputPseudoCommitmentsDoNotSumToOutputCommitments,
    #[error("The MLSAG ring signature is not valid")]
    InvalidRingSignature,
    #[error("KeyImage is not on the BLS12-381 G1 Curve")]
    KeyImageNotOnCurve,
    #[error("BulletProofs Error: {0}")]
    BulletProofs(#[from] bls_bulletproofs::ProofError),
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("key image is not unique across all transaction inputs")]
    KeyImageNotUniqueAcrossInputs,
    #[error("public key is not unique across all transaction inputs")]
    PublicKeyNotUniqueAcrossInputs,
}
