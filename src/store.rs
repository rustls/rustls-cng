//! Windows certificate store wrapper

use std::{os::raw::c_void, ptr};

use bitflags::bitflags;
use windows_sys::Win32::Security::Cryptography::*;

use crate::{cert::CertContext, error::CngError, Result};

const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

macro_rules! utf16z {
    ($str: expr) => {
        $str.encode_utf16().chain([0]).collect::<Vec<_>>()
    };
}

/// Certificate store type
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum CertStoreType {
    LocalMachine,
    CurrentUser,
    CurrentService,
}

bitflags! {
    /// Set of flags to pass to the ` CertStore::from_pkcs12 ` method.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Pkcs12Flags: u32 {
        const INCLUDE_EXTENDED_PROPERTIES = 0x0010;
        const PREFER_CNG_KSP = 0x0000_0100;
        const ALWAYS_CNG_KSP = 0x0000_0200;
        const ALLOW_OVERWRITE_KEY = 0x0000_4000;
        const NO_PERSIST_KEY =0x0000_8000;
    }
}

impl Default for Pkcs12Flags {
    fn default() -> Self {
        Pkcs12Flags::INCLUDE_EXTENDED_PROPERTIES | Pkcs12Flags::PREFER_CNG_KSP
    }
}

impl CertStoreType {
    fn as_flags(&self) -> u32 {
        match self {
            CertStoreType::LocalMachine => {
                CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentUser => {
                CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentService => {
                CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
        }
    }
}

/// Windows certificate store wrapper
#[derive(Debug)]
pub struct CertStore(HCERTSTORE);

unsafe impl Send for CertStore {}
unsafe impl Sync for CertStore {}

impl CertStore {
    /// Return an inner handle to the store
    pub fn inner(&self) -> HCERTSTORE {
        self.0
    }

    /// Open certificate store of the given type and name
    pub fn open(store_type: CertStoreType, store_name: &str) -> Result<CertStore> {
        unsafe {
            let store_name = utf16z!(store_name);
            let handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                store_type.as_flags() | CERT_STORE_OPEN_EXISTING_FLAG,
                store_name.as_ptr() as _,
            );
            if handle.is_null() {
                Err(CngError::from_win32_error())
            } else {
                Ok(CertStore(handle))
            }
        }
    }

    /// Import certificate store from PKCS12 file
    pub fn from_pkcs12(data: &[u8], password: &str, flags: Pkcs12Flags) -> Result<CertStore> {
        unsafe {
            let blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let password = utf16z!(password);
            let store =
                PFXImportCertStore(&blob, password.as_ptr(), CRYPT_EXPORTABLE | flags.bits());
            if store.is_null() {
                Err(CngError::from_win32_error())
            } else {
                Ok(CertStore(store))
            }
        }
    }

    /// Find list of certificates matching the subject substring
    pub fn find_by_subject_str<S>(&self, subject: S) -> Result<Vec<CertContext>>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_SUBJECT_STR)
    }

    /// Find list of certificates matching the exact subject name
    pub fn find_by_subject_name<S>(&self, subject: S) -> Result<Vec<CertContext>>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_SUBJECT_NAME)
    }

    /// Find list of certificates matching the issuer substring
    pub fn find_by_issuer_str<S>(&self, subject: S) -> Result<Vec<CertContext>>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_ISSUER_STR)
    }

    /// Find list of certificates matching the exact issuer name
    pub fn find_by_issuer_name<S>(&self, subject: S) -> Result<Vec<CertContext>>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_ISSUER_NAME)
    }

    /// Find list of certificates matching the SHA1 hash
    pub fn find_by_sha1<D>(&self, hash: D) -> Result<Vec<CertContext>>
    where
        D: AsRef<[u8]>,
    {
        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: hash.as_ref().len() as u32,
            pbData: hash.as_ref().as_ptr() as _,
        };
        unsafe { self.do_find(CERT_FIND_HASH, &hash_blob as *const _ as _) }
    }

    // On later OS releases, we added CERT_FIND_SHA256_HASH.
    // However, rustls-cng could be installed on earlier OS release where this FIND_SHA256 isn't present.
    // But the CERT_SHA256_HASH_PROP_ID is present.
    // So will need to add a new internal find function that gets and compares the SHA256 property.
    // Also, since SHA1 is being deprecated, Windows components should not use.
    // Therefore, the need to find via SHA256 instead of SHA1.

    /// Find list of certificates matching the SHA256 hash
    pub fn find_by_sha256<D>(&self, hash: D) -> Result<Vec<CertContext>>
    where
        D: AsRef<[u8]>,
    {
        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: hash.as_ref().len() as u32,
            pbData: hash.as_ref().as_ptr() as _,
        };
        unsafe { self.do_find_by_sha256_property(&hash_blob as *const _ as _) }
    }

    /// Find list of certificates matching the key identifier
    pub fn find_by_key_id<D>(&self, key_id: D) -> Result<Vec<CertContext>>
    where
        D: AsRef<[u8]>,
    {
        let cert_id = CERT_ID {
            dwIdChoice: CERT_ID_KEY_IDENTIFIER,
            Anonymous: CERT_ID_0 {
                KeyId: CRYPT_INTEGER_BLOB {
                    cbData: key_id.as_ref().len() as u32,
                    pbData: key_id.as_ref().as_ptr() as _,
                },
            },
        };
        unsafe { self.do_find(CERT_FIND_CERT_ID, &cert_id as *const _ as _) }
    }

    /// Get all certificates
    pub fn find_all(&self) -> Result<Vec<CertContext>> {
        unsafe { self.do_find(CERT_FIND_ANY, ptr::null()) }
    }

    unsafe fn do_find(
        &self,
        flags: CERT_FIND_FLAGS,
        find_param: *const c_void,
    ) -> Result<Vec<CertContext>> {
        let mut certs = Vec::new();

        let mut cert: *mut CERT_CONTEXT = ptr::null_mut();

        loop {
            cert = CertFindCertificateInStore(self.0, MY_ENCODING_TYPE, 0, flags, find_param, cert);
            if cert.is_null() {
                break;
            } else {
                // increase refcount because it will be released by next call to CertFindCertificateInStore
                let cert = CertDuplicateCertificateContext(cert);
                certs.push(CertContext::new_owned(cert))
            }
        }
        Ok(certs)
    }

    unsafe fn do_find_by_sha256_property(
        &self,
        find_param: *const c_void,
    ) -> Result<Vec<CertContext>> {
        let mut certs = Vec::new();
        let mut cert: *mut CERT_CONTEXT = ptr::null_mut();
        let hash_blob = &*(find_param as *const CRYPT_INTEGER_BLOB);
        let sha256_hash = std::slice::from_raw_parts(hash_blob.pbData, hash_blob.cbData as usize);
        loop {
            cert = CertFindCertificateInStore(
                self.0,
                MY_ENCODING_TYPE,
                0,
                CERT_FIND_ANY,
                find_param,
                cert,
            );
            if cert.is_null() {
                break;
            } else {
                let mut prop_data = [0u8; 32];
                let mut prop_data_len = prop_data.len() as u32;

                if CertGetCertificateContextProperty(
                    cert,
                    CERT_SHA256_HASH_PROP_ID,
                    prop_data.as_mut_ptr() as *mut c_void,
                    &mut prop_data_len,
                ) != 0
                    && prop_data[..prop_data_len as usize] == sha256_hash[..]
                {
                    let cert = CertDuplicateCertificateContext(cert);
                    certs.push(CertContext::new_owned(cert))
                }
            }
        }
        Ok(certs)
    }

    fn find_by_str(&self, pattern: &str, flags: CERT_FIND_FLAGS) -> Result<Vec<CertContext>> {
        let u16pattern = utf16z!(pattern);
        unsafe { self.do_find(flags, u16pattern.as_ptr() as _) }
    }

    fn find_by_name(&self, field: &str, flags: CERT_FIND_FLAGS) -> Result<Vec<CertContext>> {
        let mut name_size = 0;

        unsafe {
            let field_name = utf16z!(field);
            if CertStrToNameW(
                MY_ENCODING_TYPE,
                field_name.as_ptr(),
                CERT_X500_NAME_STR,
                ptr::null(),
                ptr::null_mut(),
                &mut name_size,
                ptr::null_mut(),
            ) == 0
            {
                return Err(CngError::from_win32_error());
            }

            let mut x509name = vec![0u8; name_size as usize];
            if CertStrToNameW(
                MY_ENCODING_TYPE,
                field_name.as_ptr(),
                CERT_X500_NAME_STR,
                ptr::null(),
                x509name.as_mut_ptr(),
                &mut name_size,
                ptr::null_mut(),
            ) == 0
            {
                return Err(CngError::from_win32_error());
            }

            let name_blob = CRYPT_INTEGER_BLOB {
                cbData: x509name.len() as _,
                pbData: x509name.as_mut_ptr(),
            };

            self.do_find(flags, &name_blob as *const _ as _)
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.0, 0) };
    }
}
