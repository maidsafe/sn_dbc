// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("Failed to decompress commitment")]
    FailedToDecompressCommitment,
    #[error("The commitment in the input doesn't match the public commitment")]
    InvalidCommitment,
    #[error("InputPseudoCommitmentsDoNotSumToOutputCommitments")]
    InputPseudoCommitmentsDoNotSumToOutputCommitments,
    #[error("The signature is not valid")]
    InvalidSignature,
    #[error("BulletProofs Error: {0}")]
    BulletProofs(#[from] bulletproofs::ProofError),
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("public key is not unique across all transaction inputs")]
    PublicKeyNotUniqueAcrossInputs,
}
