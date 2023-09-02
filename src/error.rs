//! Error struct

use std::fmt;

use windows_sys::{
    core::HRESULT,
    Win32::Foundation::{GetLastError, ERROR_SUCCESS, WIN32_ERROR},
};

/// Errors that may be returned in this crate
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CngError {
    InvalidHashLength,
    WindowsError(u32),
}

impl fmt::Display for CngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CngError::InvalidHashLength => write!(f, "Invalid hash length"),
            CngError::WindowsError(code) => write!(f, "Error code {:08x}", code),
        }
    }
}

impl std::error::Error for CngError {}

impl CngError {
    pub fn from_win32_error() -> Self {
        unsafe { Self::WindowsError(GetLastError()) }
    }

    pub fn from_hresult(result: HRESULT) -> crate::Result<()> {
        if result as WIN32_ERROR == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(CngError::WindowsError(result as _))
        }
    }
}
