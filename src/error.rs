use thiserror::Error;

#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed signature check.")]
    FailedSignature,
    #[error("Unrecodnised authority.")]
    UnrecodnisedAuthority,
    #[error("Output DBCs must <= input dbc")]
    DoubleSpend,
    // #[error("Network layer error: {0}")]
    // Network(#[from] qp2p::Error),
}
