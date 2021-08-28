// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
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
    #[error("Failed mint signature check.")]
    FailedMintSignature,
    #[error("Failed dbc owner signature check.")]
    FailedOwnerSignature,
    #[error("Unrecognised authority.")]
    UnrecognisedAuthority,
    #[error("ReissueRequestBuilder is missing a reissue transaction")]
    MissingReissueTransaction,
    #[error("At least one transaction input is missing a signature.")]
    MissingSignatureForInput,
    #[error("At least one input is missing an ownership proof")]
    MissingInputOwnerProof,
    #[error("Mint request doesn't balance out. sum(input) != sum(output)")]
    DbcReissueRequestDoesNotBalance,
    #[error("Failed to unblind an input DBC")]
    FailedUnblinding,
    #[error("DBC already spent in transaction: {dbc_transaction:?}")]
    DbcAlreadySpent {
        dbc_transaction: crate::DbcTransaction,
        public_key_set: crate::PublicKeySet,
        // fixme: this should be full Signature(s) from Spendbook, ie SignedEnvelope
        signed_envelope_shares: Vec<blsbs::SignedEnvelopeShare>,
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

    #[error("No output envelope/content mappings")]
    NoOutputSecrets,

    #[error("No reissue shares")]
    NoReissueShares,

    #[error("Unknown denomination")]
    UnknownDenomination,

    /// Blind Signature error
    #[error("blind signature error: {0}")]
    BlindSignature(#[from] blsbs::Error),

    /// Bls error
    #[error("Bls error: {0}")]
    Bls(#[from] blsttc::error::Error),

    #[error("deserialization from bytes failed")]
    BlsttcFromBytes(#[from] blsttc::error::FromBytesError),

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
