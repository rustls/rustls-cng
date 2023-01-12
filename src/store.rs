//! Windows certificate store wrapper

use std::{os::raw::c_void, ptr};

use widestring::U16CString;
use windows::{core::PCWSTR, Win32::Security::Cryptography::*};

use crate::{cert::CertContext, error::CngError};

const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0);

/// Certificate store type
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum CertStoreType {
    LocalMachine,
    CurrentUser,
    CurrentService,
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
    pub fn open(store_type: CertStoreType, store_name: &str) -> Result<CertStore, CngError> {
        unsafe {
            let store_name = U16CString::from_str_unchecked(store_name);
            let handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(store_type.as_flags() | CERT_STORE_OPEN_EXISTING_FLAG.0),
                Some(store_name.as_ptr() as _),
            )?;
            Ok(CertStore(handle))
        }
    }

    /// Import certificate store from PKCS12 file
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<CertStore, CngError> {
        unsafe {
            let blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let password = U16CString::from_str_unchecked(password);
            let store = PFXImportCertStore(
                &blob,
                PCWSTR(password.as_ptr()),
                CRYPT_EXPORTABLE | PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_PREFER_CNG_KSP,
            )?;
            Ok(CertStore(store))
        }
    }

    /// Find list of certificates matching the subject substring
    pub fn find_by_subject_str<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_SUBJECT_STR)
    }

    /// Find list of certificates matching the exact subject name
    pub fn find_by_subject_name<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_SUBJECT_NAME)
    }

    /// Find list of certificates matching the issuer substring
    pub fn find_by_issuer_str<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_ISSUER_STR)
    }

    /// Find list of certificates matching the exact issuer name
    pub fn find_by_issuer_name<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_ISSUER_NAME)
    }

    /// Find list of certificates matching the SHA1 hash
    pub fn find_by_sha1<D>(&self, hash: D) -> Result<Vec<CertContext>, CngError>
    where
        D: AsRef<[u8]>,
    {
        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: hash.as_ref().len() as u32,
            pbData: hash.as_ref().as_ptr() as _,
        };
        self.do_find(CERT_FIND_HASH, &hash_blob as *const _ as _)
    }

    /// Get all certificates
    pub fn find_all(&self) -> Result<Vec<CertContext>, CngError> {
        self.do_find(CERT_FIND_ANY, ptr::null())
    }

    fn do_find(
        &self,
        flags: CERT_FIND_FLAGS,
        find_param: *const c_void,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut certs = Vec::new();

        let mut cert: *mut CERT_CONTEXT = ptr::null_mut();

        loop {
            cert = unsafe {
                CertFindCertificateInStore(
                    self.0,
                    MY_ENCODING_TYPE,
                    0,
                    flags,
                    Some(find_param),
                    Some(cert),
                )
            };
            if cert.is_null() {
                break;
            } else {
                // increase refcount because it will be released by next call to CertFindCertificateInStore
                let cert = unsafe { CertDuplicateCertificateContext(Some(cert)) };
                certs.push(CertContext::new_owned(cert))
            }
        }
        Ok(certs)
    }

    fn find_by_str(
        &self,
        pattern: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let u16pattern = unsafe { U16CString::from_str_unchecked(pattern) };
        self.do_find(flags, u16pattern.as_ptr() as _)
    }

    fn find_by_name(
        &self,
        field: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut name_size = 0;

        unsafe {
            let field_name = U16CString::from_str_unchecked(field);
            if !CertStrToNameW(
                MY_ENCODING_TYPE,
                PCWSTR(field_name.as_ptr()),
                CERT_X500_NAME_STR,
                None,
                None,
                &mut name_size,
                None,
            )
            .as_bool()
            {
                return Err(CngError::from_win32_error());
            }

            let mut x509name = vec![0u8; name_size as usize];
            if !CertStrToNameW(
                MY_ENCODING_TYPE,
                PCWSTR(field_name.as_ptr()),
                CERT_X500_NAME_STR,
                None,
                Some(x509name.as_mut_ptr()),
                &mut name_size,
                None,
            )
            .as_bool()
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
