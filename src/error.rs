// Copyright 2021 MaidSafe.net limited.
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
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    #[error("An error occured when signing {0}")]
    Signing(String),

    #[error("This input has a signature, but it doesn't appear in the transaction")]
    UnknownInput,

    #[error("Failed signature check.")]
    FailedSignature,

    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,

    #[error("At least one transaction input is missing a signature.")]
    MissingSignatureForInput,

    #[error("Invalid SpentProof Signature for {0:?}")]
    InvalidSpentProofSignature(KeyImage),

    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,

    #[error("Dbc Content is not a member of transaction outputs")]
    DbcContentNotPresentInTransactionOutput,

    #[error("OutputProof not found in transaction outputs")]
    OutputProofNotFound,

    #[error("key image is not unique across all transaction inputs")]
    KeyImageNotUniqueAcrossInputs,

    #[error("public key is not unique across all transaction outputs")]
    PublicKeyNotUniqueAcrossOutputs,

    #[error("The number of SpentProof does not match the number of input MlsagSignature")]
    SpentProofInputMismatch,

    #[error("The PublicKeySet differs between ReissueRequest entries")]
    ReissueRequestPublicKeySetMismatch,

    #[error("The Public Commitments differ between ReissueRequest entries")]
    ReissueRequestPublicCommitmentMismatch,

    #[error("We need at least one spent proof share for {0:?} to build a SpentProof")]
    ReissueRequestMissingSpentProofShare(usize),

    #[error("The PublicKeySet differs between ReissueShare entries")]
    ReissueSharePublicKeySetMismatch,

    #[error("The MintNodeSignature count in ReissueShare differs from input count in ReissueTransaction")]
    ReissueShareMintNodeSignaturesLenMismatch,

    #[error("MintNodeSignature not found for an input in ReissueTransaction")]
    ReissueShareMintNodeSignatureNotFoundForInput,

    #[error("No reissue shares")]
    NoReissueShares,

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

    #[error("Secret key does not match public key")]
    SecretKeyDoesNotMatchPublicKey,

    #[error("Bls error: {0}")]
    Blsttc(#[from] blsttc::error::Error),

    /// blst_ringct error.
    #[error("ringct error: {0}")]
    RingCt(#[from] blst_ringct::Error),

    #[error("Infallible.  Can never fail")]
    Infallible(#[from] std::convert::Infallible),
}
