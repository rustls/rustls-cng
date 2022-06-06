#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CngError {
    #[error("Unsupported private key algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("Certificate chain error")]
    CertificateChain,
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}
