// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::DbcId;
use thiserror::Error;

/// Specialisation of `std::Result`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    /// While parsing a `Token`, precision would be lost.
    #[error("Lost precision on the number of coins during parsing.")]
    LossOfTokenPrecision,
    /// The amount would exceed the maximum value for `Token` (u64::MAX).
    #[error("The token amount would exceed the maximum value (u64::MAX).")]
    ExcessiveTokenValue,
    /// Failed to parse a `Token` from a string.
    #[error("Failed to parse: {0}")]
    FailedToParseToken(String),

    #[error("Invalid Spend Signature for {0:?}")]
    InvalidSpendSignature(DbcId),

    #[error("Transaction hash does not match the transaction signed by spentbook.")]
    InvalidTransactionHash,

    #[error("Dbc ciphers are not present in transaction outputs.")]
    DbcCiphersNotPresentInTransactionOutput,

    #[error("Output not found in transaction outputs.")]
    OutputNotFound,

    #[error("DbcId is not unique across all transaction outputs.")]
    DbcIdNotUniqueAcrossOutputs,

    #[error(
        "The number of SignedSpend ({current}) does not match the number of inputs ({expected})."
    )]
    SignedSpendInputLenMismatch { current: usize, expected: usize },

    #[error("A SignedSpend DbcId does not match an MlsagSignature DbcId.")]
    SignedSpendInputIdMismatch,

    #[error("SignedSpends for {0:?} have mismatching reasons.")]
    SignedSpendReasonMismatch(DbcId),

    #[error("Decryption failed.")]
    DecryptionBySecretKeyFailed,

    #[error("DbcId not found.")]
    DbcIdNotFound,

    #[error("Main key does not match public address.")]
    MainKeyDoesNotMatchPublicAddress,

    #[error("Could not deserialize specified hex string to a DBC: {0}")]
    HexDeserializationFailed(String),

    #[error("Could not serialize DBC to hex: {0}")]
    HexSerializationFailed(String),

    #[error("Bls error: {0}")]
    Blsttc(#[from] blsttc::error::Error),

    #[error("The input and output amounts of the tx do not match.")]
    InconsistentDbcTransaction,

    #[error("The Dbc tx must have at least one input.")]
    MissingTxInputs,

    #[error("Dbc id is not unique across all tx inputs.")]
    DbcIdNotUniqueAcrossInputs,

    #[error("Overflow occurred while adding values")]
    NumericOverflow,

    #[cfg(feature = "mock")]
    #[error("mock object error.")]
    Mock(#[from] crate::mock::Error),
}
