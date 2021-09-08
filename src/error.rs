// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use std::collections::BTreeMap;
use std::io;
use thiserror::Error;

/// Specialisation of `std::Result`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    #[error("An error occured when signing {0}")]
    Signing(String),
    #[error("Attempted an invalid operation {0}")]
    InvalidOperation(String),
    #[error("This input has a signature, but it doesn't appear in the transaction")]
    UnknownInput,
    #[error("Filtered input doesn't appear in the transaction")]
    FilteredInputNotPresent,
    #[error("Failed signature check.")]
    FailedSignature,
    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,
    #[error("At least one transaction input is missing a signature.")]
    MissingSignatureForInput,
    #[error("At least one input is missing an ownership proof")]
    MissingInputOwnerProof,
    #[error("Mint request doesn't balance out sum(input) == sum(output)")]
    DbcReissueRequestDoesNotBalance,
    #[error("Failed to unblind an input DBC")]
    FailedUnblinding,
    #[error("DBC already spent in transaction: {transaction:?}")]
    DbcAlreadySpent {
        transaction: crate::DbcTransaction,
        transaction_sigs:
            BTreeMap<crate::DbcContentHash, (crate::PublicKeySet, crate::NodeSignature)>,
    },
    #[error("Genesis Input has already been spent in a different transaction")]
    GenesisInputAlreadySpent,
    #[error("This node is not a genesis node")]
    NotGenesisNode,
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("Dbc Content is not a member of transaction outputs")]
    DbcContentNotPresentInTransactionOutput,
    #[error("Dbc Content parents is not the same transaction inputs")]
    DbcContentParentsDifferentFromTransactionInputs,

    #[error("The PublicKeySet differs between ReissueRequest entries")]
    ReissueRequestPublicKeySetMismatch,

    #[error("The PublicKeySet differs between ReissueShare entries")]
    ReissueSharePublicKeySetMismatch,

    #[error("The MintNodeSignature count in ReissueShare differs from input count in ReissueTransaction")]
    ReissueShareMintNodeSignaturesLenMismatch,

    #[error("MintNodeSignature not found for an input in ReissueTransaction")]
    ReissueShareMintNodeSignatureNotFoundForInput,

    #[error("The DbcTransaction in ReissueShare differs from that of ReissueTransaction")]
    ReissueShareDbcTransactionMismatch,

    #[error("No reissue shares")]
    NoReissueShares,

    #[error("No reissue transaction")]
    NoReissueTransaction,

    #[error("RangeProof error: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),

    #[error("Decryption error: {0}")]
    DecryptionBySharesFailed(#[from] blsttc::error::Error),

    #[error("Decryption failed")]
    DecryptionBySecretKeyFailed,

    #[error("Invalid AmountSecret bytes")]
    AmountSecretsBytesInvalid,

    #[error("Invalid Amount Commitment")]
    AmountCommitmentInvalid,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// JSON serialisation error.
    #[error("JSON serialisation error: {0}")]
    JsonSerialisation(#[from] serde_json::Error),
    #[error("SpendBook error {0}")]
    SpendBook(String),

    #[error("Infallible.  Can never fail")]
    Infallible(#[from] std::convert::Infallible),
}
