//! Windows certificate store wrapper

use std::ptr;

use widestring::U16CString;
use windows::Win32::Security::Cryptography::{
    CertStrToNameW, CERT_FIND_ISSUER_NAME, CERT_FIND_SUBJECT_NAME, CERT_X500_NAME_STR,
};
use windows::{
    core::PCSTR,
    Win32::Security::Cryptography::{
        CertCloseStore, CertDuplicateCertificateContext, CertFindCertificateInStore, CertOpenStore,
        PFXImportCertStore, CERT_FIND_FLAGS, CERT_FIND_ISSUER_STR, CERT_FIND_SUBJECT_STR,
        CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_SYSTEM_STORE_CURRENT_SERVICE_ID, CERT_SYSTEM_STORE_CURRENT_USER_ID,
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPTOAPI_BLOB,
        CRYPT_KEY_FLAGS, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    },
};

use crate::{cert::CertContext, error::CngError};

const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0);

/// Certificate store type
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
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
                PCSTR(10 as _),
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(store_type.as_flags() | CERT_STORE_OPEN_EXISTING_FLAG.0),
                store_name.as_ptr() as _,
            )?;
            Ok(CertStore(handle))
        }
    }

    /// Import certificate store from PKCS12 file
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<CertStore, CngError> {
        unsafe {
            let blob = CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let store = PFXImportCertStore(&blob, password, CRYPT_KEY_FLAGS::default())?;
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

    fn find_by_str(
        &self,
        pattern: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut certs = Vec::new();
        let u16pattern = unsafe { U16CString::from_str_unchecked(pattern) };

        let mut cert = ptr::null();

        loop {
            cert = unsafe {
                CertFindCertificateInStore(
                    self.0,
                    MY_ENCODING_TYPE.0,
                    0,
                    flags,
                    u16pattern.as_ptr() as _,
                    cert,
                )
            };
            if cert.is_null() {
                break;
            } else {
                // increase refcount because it will be released by next call to CertFindCertificateInStore
                let cert = unsafe { CertDuplicateCertificateContext(cert) };
                certs.push(CertContext::owned(cert))
            }
        }
        Ok(certs)
    }

    fn find_by_name(
        &self,
        field: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut certs = Vec::new();
        let mut name_size = 0;

        unsafe {
            if !CertStrToNameW(
                MY_ENCODING_TYPE.0,
                field,
                CERT_X500_NAME_STR,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut name_size,
                ptr::null_mut(),
            )
            .as_bool()
            {
                return Err(CngError::Windows(windows::core::Error::from_win32()));
            }

            let mut x509name = vec![0u8; name_size as usize];
            if !CertStrToNameW(
                MY_ENCODING_TYPE.0,
                field,
                CERT_X500_NAME_STR,
                ptr::null_mut(),
                x509name.as_mut_ptr() as _,
                &mut name_size,
                ptr::null_mut(),
            )
            .as_bool()
            {
                return Err(CngError::Windows(windows::core::Error::from_win32()));
            }

            let name_blob = CRYPTOAPI_BLOB {
                cbData: x509name.len() as _,
                pbData: x509name.as_mut_ptr() as _,
            };

            let mut cert = ptr::null();

            loop {
                cert = CertFindCertificateInStore(
                    self.0,
                    MY_ENCODING_TYPE.0,
                    0,
                    flags,
                    &name_blob as *const _ as _,
                    cert,
                );
                if cert.is_null() {
                    break;
                } else {
                    // increase refcount because it will be released by next call to CertFindCertificateInStore
                    let cert = CertDuplicateCertificateContext(cert);
                    certs.push(CertContext::owned(cert))
                }
            }
            Ok(certs)
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.0, 0) };
    }
}
