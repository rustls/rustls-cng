use std::{mem, os::raw::c_void, ptr, sync::Arc};

use widestring::{U16CStr, U16CString};
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

#[derive(Debug, Clone, PartialEq, PartialOrd)]
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

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum SignaturePadding {
    None,
    Pkcs1,
    Pss,
}

#[derive(Debug)]
enum InnerKey {
    Owned(NCRYPT_HANDLE),
    Borrowed(NCRYPT_HANDLE),
}

impl InnerKey {
    fn inner(&self) -> NCRYPT_HANDLE {
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

#[derive(Clone, Debug)]
pub struct NCryptKey(Arc<InnerKey>);

impl NCryptKey {
    pub fn owned(handle: NCRYPT_HANDLE) -> Self {
        NCryptKey(Arc::new(InnerKey::Owned(handle)))
    }

    pub fn borrowed(handle: NCRYPT_HANDLE) -> Self {
        NCryptKey(Arc::new(InnerKey::Borrowed(handle)))
    }

    pub fn inner(&self) -> NCRYPT_HANDLE {
        self.0.inner()
    }

    fn get_string_property(&self, property: &str) -> Result<String, CngError> {
        let mut result: u32 = 0;
        unsafe {
            NCryptGetProperty(
                self.inner(),
                property,
                ptr::null_mut(),
                0,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            let mut prop_value = vec![0u8; result as usize];

            NCryptGetProperty(
                self.inner(),
                property,
                prop_value.as_mut_ptr(),
                prop_value.len() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            Ok(U16CStr::from_ptr_str(prop_value.as_ptr() as _).to_string_lossy())
        }
    }

    pub fn bits(&self) -> Result<u32, CngError> {
        let mut bits: u32 = 0;
        let mut result: u32 = 0;
        unsafe {
            NCryptGetProperty(
                self.inner(),
                NCRYPT_LENGTH_PROPERTY,
                &mut bits as *mut _ as _,
                mem::size_of::<u32>() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            )?;

            Ok(bits)
        }
    }

    pub fn algorithm_group(&self) -> Result<AlgorithmGroup, CngError> {
        Ok(AlgorithmGroup::from_str(
            &self.get_string_property(NCRYPT_ALGORITHM_GROUP_PROPERTY)?,
        ))
    }

    pub fn algorithm(&self) -> Result<String, CngError> {
        self.get_string_property(NCRYPT_ALGORITHM_PROPERTY)
    }

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
                info,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )?;

            let mut signature = vec![0u8; result as usize];

            NCryptSignHash(
                NCRYPT_KEY_HANDLE(self.inner().0),
                info,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )?;

            Ok(signature)
        }
    }
}
