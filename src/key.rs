//! CNG key wrapper

use std::{os::raw::c_void, ptr, str::FromStr, sync::Arc};

use windows_sys::{
    core::PCWSTR,
    Win32::Security::{Cryptography::*, OBJECT_SECURITY_INFORMATION},
};

use crate::{error::CngError, Result};

/// Algorithm group of the CNG private key
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum AlgorithmGroup {
    Rsa,
    Ecdsa,
    Ecdh,
}

impl FromStr for AlgorithmGroup {
    type Err = CngError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "RSA" => Ok(Self::Rsa),
            "ECDSA" => Ok(Self::Ecdsa),
            "ECDH" => Ok(Self::Ecdh),
            _ => Err(CngError::UnsupportedKeyAlgorithmGroup),
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
                let _ = NCryptFreeObject(*handle);
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

    fn get_string_property(&self, property: PCWSTR) -> Result<String> {
        let mut result: u32 = 0;
        unsafe {
            CngError::from_hresult(NCryptGetProperty(
                self.inner(),
                property,
                ptr::null_mut(),
                0,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            ))?;

            let mut prop_value = vec![0u8; result as usize];

            CngError::from_hresult(NCryptGetProperty(
                self.inner(),
                property,
                prop_value.as_mut_ptr(),
                prop_value.len() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            ))?;

            Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
                prop_value.as_ptr() as *const u16,
                prop_value.len() / 2 - 1,
            )))
        }
    }

    /// Return a number of bits in the key material
    pub fn bits(&self) -> Result<u32> {
        let mut bits = [0u8; 4];
        let mut result: u32 = 0;
        unsafe {
            CngError::from_hresult(NCryptGetProperty(
                self.inner(),
                NCRYPT_LENGTH_PROPERTY,
                bits.as_mut_ptr(),
                4,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            ))?;

            Ok(u32::from_ne_bytes(bits))
        }
    }

    /// Return algorithm group of the key
    pub fn algorithm_group(&self) -> Result<AlgorithmGroup> {
        self.get_string_property(NCRYPT_ALGORITHM_GROUP_PROPERTY)?
            .parse()
    }

    /// Return algorithm name of the key
    pub fn algorithm(&self) -> Result<String> {
        self.get_string_property(NCRYPT_ALGORITHM_PROPERTY)
    }

    /// Set a pin code for hardware tokens
    pub fn set_pin(&self, pin: &str) -> Result<()> {
        let pin_val = pin.encode_utf16().chain([0]).collect::<Vec<u16>>();

        let result = unsafe {
            NCryptSetProperty(
                self.inner(),
                NCRYPT_PIN_PROPERTY,
                pin_val.as_ptr() as *const u8,
                pin.len() as u32,
                NCRYPT_FLAGS::default(),
            )
        };

        CngError::from_hresult(result)
    }

    /// Sign a given digest with this key. The `hash` slice must be 32, 48 or 64 bytes long.
    pub fn sign(&self, hash: &[u8], padding: SignaturePadding) -> Result<Vec<u8>> {
        unsafe {
            let hash_alg = match hash.len() {
                32 => BCRYPT_SHA256_ALGORITHM,
                48 => BCRYPT_SHA384_ALGORITHM,
                64 => BCRYPT_SHA512_ALGORITHM,
                _ => return Err(CngError::InvalidHashLength),
            };

            let pkcs1;
            let pss;

            let (info, flag) = match padding {
                SignaturePadding::Pkcs1 => {
                    pkcs1 = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: hash_alg };
                    (&pkcs1 as *const _ as *const c_void, BCRYPT_PAD_PKCS1)
                }
                SignaturePadding::Pss => {
                    pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: hash_alg,
                        cbSalt: hash.len() as u32,
                    };
                    (&pss as *const _ as *const c_void, BCRYPT_PAD_PSS)
                }
                SignaturePadding::None => (ptr::null(), NCRYPT_FLAGS::default()),
            };

            let mut result = 0;

            CngError::from_hresult(NCryptSignHash(
                self.inner(),
                info,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            ))?;

            let mut signature = vec![0u8; result as usize];

            CngError::from_hresult(NCryptSignHash(
                self.inner(),
                info,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            ))?;

            Ok(signature)
        }
    }
}
