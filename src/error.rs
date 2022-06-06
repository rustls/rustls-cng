#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CngError {
    #[error("Private key error")]
    PrivateKey,
    #[error("Certificate chain error")]
    CertificateChain,
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}
