// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use thiserror::Error;

use crate::KeyImage;

/// Specialisation of `std::Result`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    #[error("Failed signature check.")]
    FailedSignature,

    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,

    #[error("Invalid SpentProof Signature for {0:?}.  Error: {1}")]
    InvalidSpentProofSignature(KeyImage, String),

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
        "The number of SpentProof ({current}) does not match the number of input MlsagSignature ({expected})"
    )]
    SpentProofInputLenMismatch { current: usize, expected: usize },

    #[error("A SpentProof KeyImage does not match an MlsagSignature KeyImage")]
    SpentProofInputKeyImageMismatch,

    #[error("We need at least one spent proof share for {0:?} to build a SpentProof")]
    MissingSpentProofShare(KeyImage),

    #[error("Decryption failed")]
    DecryptionBySecretKeyFailed,

    #[error("Invalid AmountSecret bytes")]
    AmountSecretsBytesInvalid,

    #[error("Amount Commitments do not match")]
    AmountCommitmentsDoNotMatch,

    #[error("Secret key unavailable")]
    SecretKeyUnavailable,

    #[error("Public key not found")]
    PublicKeyNotFound,

    #[error("Insufficient decoys available for all inputs")]
    InsufficientDecoys,

    #[error("Secret key does not match public key")]
    SecretKeyDoesNotMatchPublicKey,

    #[error("Could not deserialize specified hex string to a DBC: {0}")]
    HexDeserializationFailed(String),

    #[error("Could not serialize DBC to hex: {0}")]
    HexSerializationFailed(String),

    #[error("Could not convert owned DBC to bearer: {0}")]
    DbcBearerConversionFailed(String),

    #[error("Bls error: {0}")]
    Blsttc(#[from] blsttc::error::Error),

    #[error("ringct error: {0}")]
    RingCt(#[from] bls_ringct::Error),

    #[cfg(feature = "mock")]
    #[error("mock object error")]
    Mock(#[from] crate::mock::Error),

    #[error("Infallible.  Can never fail")]
    Infallible(#[from] std::convert::Infallible),
}
