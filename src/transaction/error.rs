// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("Failed to decompress blinded amount.")]
    FailedToDecompressBlindedAmount,
    #[error("The blinded amount in the input doesn't match the known amount.")]
    InvalidInputBlindedAmount,
    #[error("The input and output amounts of the transaction do not match.")]
    InconsistentDbcTransaction,
    #[error("The signature is not valid.")]
    InvalidSignature,
    #[error("BulletProofs Error: {0}.")]
    BulletProofs(#[from] bulletproofs::ProofError),
    #[error("The DBC transaction must have at least one input.")]
    TransactionMustHaveAnInput,
    #[error("Dbc id is not unique across all transaction inputs.")]
    DbcIdNotUniqueAcrossInputs,
}
