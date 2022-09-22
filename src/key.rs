//! CNG key wrapper

use std::{os::raw::c_void, ptr, sync::Arc};

use widestring::{u16cstr, U16CStr, U16CString};
use windows::{
    core::PCWSTR,
    Win32::Security::{
        Cryptography::{
            NCryptFreeObject, NCryptGetProperty, NCryptSignHash, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS,
            BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, BCRYPT_SHA256_ALGORITHM,
            BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM, NCRYPT_ALGORITHM_GROUP_PROPERTY,
            NCRYPT_ALGORITHM_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
            NCRYPT_LENGTH_PROPERTY, NCRYPT_SILENT_FLAG,
        },
        OBJECT_SECURITY_INFORMATION,
    },
};

use crate::error::CngError;

/// Algorithm group of the CNG private key
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum AlgorithmGroup {
    Rsa,
    Ecdsa,
    Ecdh,
    Other(String),
}

impl AlgorithmGroup {
    fn from_str(s: &str) -> Self {
        match s {
            "RSA" => Self::Rsa,
            "ECDSA" => Self::Ecdsa,
            "ECDH" => Self::Ecdh,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Signature padding. Used with RSA keys.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum SignaturePadding {
    None,
    Pkcs1,
    Pss,
}

#[derive(Debug)]
enum InnerKey {
    Owned(NCRYPT_KEY_HANDLE),
    Borrowed(NCRYPT_KEY_HANDLE),
}

impl InnerKey {
    fn inner(&self) -> NCRYPT_KEY_HANDLE {
        match self {
            Self::Owned(handle) => *handle,
            Self::Borrowed(handle) => *handle,
        }
    }
}

impl Drop for InnerKey {
    fn drop(&mut self) {
        match self {
            Self::Owned(handle) => unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(handle.0));
            },
            Self::Borrowed(_) => {}
        }
    }
}

/// CNG private key wrapper
#[derive(Clone, Debug)]
pub struct NCryptKey(Arc<InnerKey>);

impl NCryptKey {
    /// Create an owned instance which frees the underlying handle automatically
    pub fn new_owned(handle: NCRYPT_KEY_HANDLE) -> Self {
        NCryptKey(Arc::new(InnerKey::Owned(handle)))
    }

    /// Create a borrowed instance which doesn't free the key handle
    pub fn new_borrowed(handle: NCRYPT_KEY_HANDLE) -> Self {
        NCryptKey(Arc::new(InnerKey::Borrowed(handle)))
    }

    /// Return an inner CNG key handle
    pub fn inner(&self) -> NCRYPT_KEY_HANDLE {
        self.0.inner()
    }

    /// Return NCRYPT_HANDLE
    pub fn as_ncrypt_handle(&self) -> NCRYPT_HANDLE {
        NCRYPT_HANDLE(self.0.inner().0)
    }

    fn get_string_property(&self, property: &str) -> Result<String, CngError> {
        let mut result: u32 = 0;
        unsafe {
            let property = U16CString::from_str_unchecked(property);

            NCryptGetProperty(
                self.as_ncrypt_handle(),
                PCWSTR(property.as_ptr()),
                None,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            let mut prop_value = vec![0u8; result as usize];

            NCryptGetProperty(
                self.as_ncrypt_handle(),
                PCWSTR(property.as_ptr()),
                Some(prop_value.as_mut()),
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            Ok(U16CStr::from_ptr_str(prop_value.as_ptr() as _).to_string_lossy())
        }
    }

    /// Return a number of bits in the key material
    pub fn bits(&self) -> Result<u32, CngError> {
        let mut bits = [0u8; 4];
        let mut result: u32 = 0;
        unsafe {
            NCryptGetProperty(
                self.as_ncrypt_handle(),
                PCWSTR(u16cstr!(NCRYPT_LENGTH_PROPERTY).as_ptr()),
                Some(&mut bits),
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            Ok(u32::from_ne_bytes(bits))
        }
    }

    /// Return algorithm group of the key
    pub fn algorithm_group(&self) -> Result<AlgorithmGroup, CngError> {
        Ok(AlgorithmGroup::from_str(
            &self.get_string_property(NCRYPT_ALGORITHM_GROUP_PROPERTY)?,
        ))
    }

    /// Return algorithm name of the key
    pub fn algorithm(&self) -> Result<String, CngError> {
        self.get_string_property(NCRYPT_ALGORITHM_PROPERTY)
    }

    /// Sign a given digest with this key. The `sign` slice must be 32, 48 or 64 bytes long.
    pub fn sign(&self, hash: &[u8], padding: SignaturePadding) -> Result<Vec<u8>, CngError> {
        let mut result = 0;
        unsafe {
            let hash_alg = match hash.len() {
                32 => BCRYPT_SHA256_ALGORITHM,
                48 => BCRYPT_SHA384_ALGORITHM,
                64 => BCRYPT_SHA512_ALGORITHM,
                _ => return Err(CngError::InvalidHashLength),
            };
            let alg_name = U16CString::from_str_unchecked(hash_alg);
            let mut pkcs1 = BCRYPT_PKCS1_PADDING_INFO::default();
            let mut pss = BCRYPT_PSS_PADDING_INFO::default();
            let (info, flag) = match padding {
                SignaturePadding::Pkcs1 => {
                    pkcs1.pszAlgId = PCWSTR(alg_name.as_ptr());
                    (&pkcs1 as *const _ as *const c_void, BCRYPT_PAD_PKCS1)
                }
                SignaturePadding::Pss => {
                    pss.pszAlgId = PCWSTR(alg_name.as_ptr());
                    pss.cbSalt = hash.len() as u32;
                    (&pss as *const _ as *const c_void, BCRYPT_PAD_PSS)
                }
                SignaturePadding::None => (ptr::null(), NCRYPT_FLAGS::default()),
            };

            NCryptSignHash(
                NCRYPT_KEY_HANDLE(self.inner().0),
                Some(info),
                hash,
                None,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )?;

            let mut signature = vec![0u8; result as usize];

            NCryptSignHash(
                NCRYPT_KEY_HANDLE(self.inner().0),
                Some(info),
                hash,
                Some(signature.as_mut()),
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )?;

            Ok(signature)
        }
    }
}
