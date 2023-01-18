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
    #[error("The commitment in the input doesn't match the public commitment")]
    InvalidCommitment,
    #[error("InputPseudoCommitmentsDoNotSumToOutputCommitments")]
    InputPseudoCommitmentsDoNotSumToOutputCommitments,
    #[error("The signature is not valid")]
    InvalidSignature,
    #[error("BulletProofs Error: {0}")]
    BulletProofs(#[from] bls_bulletproofs::ProofError),
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("public key is not unique across all transaction inputs")]
    PublicKeyNotUniqueAcrossInputs,
}
