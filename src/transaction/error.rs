// Copyright (c) 2023, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("The input and output amounts of the tx do not match.")]
    InconsistentDbcTransaction,
    #[error("The signature is not valid.")]
    InvalidSignature,
    #[error("The Dbc tx must have at least one input.")]
    MissingTxInputs,
    #[error("Dbc id is not unique across all tx inputs.")]
    DbcIdNotUniqueAcrossInputs,
    #[error("Overflow occurred while adding values")]
    NumericOverflow,
}
