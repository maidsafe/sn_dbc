// Copyright 2023 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use thiserror::Error;

use crate::transaction;
use crate::PublicKey;

/// Specialisation of `std::Result`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    /// While parsing a `Token`, precision would be lost.
    #[error("Lost precision on the number of coins during parsing")]
    LossOfTokenPrecision,
    /// The amount would exceed the maximum value for `Token` (u64::MAX).
    #[error("The token amount would exceed the maximum value (u64::MAX)")]
    ExcessiveTokenValue,
    /// Failed to parse a `Token` from a string.
    #[error("Failed to parse: {0}")]
    FailedToParseToken(String),

    #[error("Failed signature check.")]
    FailedSignature,

    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,

    #[error("Invalid SpentProof Signature for {0:?}")]
    InvalidSpentProofSignature(PublicKey),

    #[error("Transaction hash does not match the transaction signed by spentbook")]
    InvalidTransactionHash,

    #[error("Dbc Content is not a member of transaction outputs")]
    DbcContentNotPresentInTransactionOutput,

    #[error("OutputProof not found in transaction outputs")]
    OutputProofNotFound,

    #[error("Missing spent transaction for at least one of the spent proofs")]
    MissingSpentTransaction,

    #[error("public key is not unique across all transaction outputs")]
    PublicKeyNotUniqueAcrossOutputs,

    #[error(
        "The number of SpentProof ({current}) does not match the number of inputs ({expected})"
    )]
    SpentProofInputLenMismatch { current: usize, expected: usize },

    #[error(
        "Missing amount for public key: {0:?}. There must be exactly one amount per public key."
    )]
    MissingAmountForPubkey(PublicKey),

    #[error("Multiple amounts found for public key: {0:?}. There must be exactly one amount per public key.")]
    MultipleAmountsForPubkey(PublicKey),

    #[error("A SpentProof PublicKey does not match an MlsagSignature PublicKey")]
    SpentProofInputPublicKeyMismatch,

    #[error("We need at least one spent proof share for {0:?} to build a SpentProof")]
    MissingSpentProofShare(PublicKey),

    #[error("SpentProofShares for {0:?} have mismatching reasons")]
    SpentProofShareReasonMismatch(PublicKey),

    #[error("Decryption failed")]
    DecryptionBySecretKeyFailed,

    #[error("Invalid RevealedAmount bytes")]
    InvalidRevealedAmountBytes,

    #[error("Blinded amounts do not match")]
    BlindedAmountsDoNotMatch,

    #[error("Secret key unavailable")]
    SecretKeyUnavailable,

    #[error("Public key not found")]
    PublicKeyNotFound,

    #[error("Secret key does not match public key")]
    SecretKeyDoesNotMatchPublicKey,

    #[error("Could not deserialize specified hex string to a DBC: {0}")]
    HexDeserializationFailed(String),

    #[error("Could not serialize DBC to hex: {0}")]
    HexSerializationFailed(String),

    #[error("Could not convert owned DBC to bearer: {0}")]
    DbcBearerConversionFailed(String),

    #[error("Failed known key check")]
    FailedKnownKeyCheck(String),

    #[error("Bls error: {0}")]
    Blsttc(#[from] blsttc::error::Error),

    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::Error),

    #[cfg(feature = "mock")]
    #[error("mock object error")]
    Mock(#[from] crate::mock::Error),

    #[error("Infallible.  Can never fail")]
    Infallible(#[from] std::convert::Infallible),
}
