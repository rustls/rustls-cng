//! Error struct

use windows_sys::{
    core::HRESULT,
    Win32::Foundation::{GetLastError, ERROR_SUCCESS, WIN32_ERROR},
};

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
    #[error("Windows error 0x{0:x}")]
    WindowsError(u32),
}

impl CngError {
    pub fn from_win32_error() -> Self {
        unsafe { Self::WindowsError(GetLastError()) }
    }

    pub fn from_hresult(result: HRESULT) -> Result<(), CngError> {
        if result as WIN32_ERROR == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(CngError::WindowsError(result as _))
        }
    }
}
