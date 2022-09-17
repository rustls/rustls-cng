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
    InvalidCertificateChain,
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
}

impl CngError {
    pub fn from_win32_error() -> Self {
        Self::WindowsError(windows::core::Error::from_win32())
    }
}
