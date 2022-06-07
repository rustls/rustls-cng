//! Error struct

/// Errors that may be returned in this crate
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CngError {
    #[error("Unsupported private key algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("Invalid hash length")]
    InvalidHashLength,
    #[error("Certificate chain error")]
    CertificateChain,
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}
