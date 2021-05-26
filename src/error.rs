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
    /// Attempted to perform an operation meant only for Adults when we are not one.
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
    DbcMintRequestDoesNotBalance { input: u64, output: u64 },
    #[error("Outputs must be numbered 0..N where N = # of outputs")]
    OutputsAreNotNumberedCorrectly,
    #[error("Failed to unblind an input DBC")]
    FailedUnblinding,
    #[error("DBC already spent in transaction: {transaction:?}")]
    DbcAlreadySpent {
        transaction: crate::DbcTransaction,
        transaction_sigs: BTreeMap<crate::DbcContentHash, (crate::PublicKey, crate::Signature)>,
    },
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("Dbc Content is not a member of transaction outputs")]
    DbcContentNotPresentInTransactionOutput,
    #[error("Dbc Content parents is not the same transaction inputs")]
    DbcContentParentsDifferentFromTransactionInputs,
    #[error("Failed to verify signature")]
    Ed25519(#[from] ed25519::ed25519::Error),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// JSON serialisation error.
    #[error("JSON serialisation error:: {0}")]
    JsonSerialisation(#[from] serde_json::Error),
}
