//! Wrapper struct for Windows CERT_CONTEXT

use std::{mem, ptr, slice, sync::Arc};

use windows::Win32::Security::Cryptography::{
    CertFreeCertificateChain, CertFreeCertificateContext, CertGetCertificateChain,
    CryptAcquireCertificatePrivateKey, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT,
    CERT_KEY_SPEC, CRYPT_ACQUIRE_FLAGS, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
    CRYPT_ACQUIRE_SILENT_FLAG, HCERTCHAINENGINE, HCERTSTORE, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    NCRYPT_KEY_HANDLE,
};

use crate::{error::CngError, key::NCryptKey};

#[derive(Debug)]
enum InnerContext {
    Owned(*const CERT_CONTEXT),
    Borrowed(*const CERT_CONTEXT),
}

unsafe impl Send for InnerContext {}
unsafe impl Sync for InnerContext {}

impl InnerContext {
    fn inner(&self) -> *const CERT_CONTEXT {
        match self {
            Self::Owned(handle) => *handle,
            Self::Borrowed(handle) => *handle,
        }
    }
}

impl Drop for InnerContext {
    fn drop(&mut self) {
        match self {
            Self::Owned(handle) => unsafe {
                CertFreeCertificateContext(*handle);
            },
            Self::Borrowed(_) => {}
        }
    }
}

/// CertContext wraps CERT_CONTEXT structure for high-level certificate operations
#[derive(Debug, Clone)]
pub struct CertContext(Arc<InnerContext>);

impl CertContext {
    /// Construct CertContext as an owned object which automatically frees the inner handle
    pub fn owned(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Owned(context)))
    }

    /// Construct CertContext as a borrowed object which does not free the inner handle
    pub fn borrowed(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Borrowed(context)))
    }

    /// Return a raw reference to the inner handle
    pub fn inner(&self) -> *const CERT_CONTEXT {
        self.0.inner()
    }

    /// Attempt to silently acquire a CNG private key from this context.
    pub fn acquire_key(&self) -> Result<NCryptKey, CngError> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();
        let flags =
            CRYPT_ACQUIRE_FLAGS(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG) | CRYPT_ACQUIRE_SILENT_FLAG;
        unsafe {
            let result = CryptAcquireCertificatePrivateKey(
                self.inner(),
                flags,
                ptr::null_mut(),
                &mut handle,
                &mut key_spec,
                ptr::null_mut(),
            )
            .as_bool();
            if result {
                Ok(NCryptKey::owned(NCRYPT_KEY_HANDLE(handle.0)))
            } else {
                Err(CngError::Windows(windows::core::Error::from_win32()))
            }
        }
    }

    /// Return DER-encoded X.509 certificate
    pub fn as_der(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                (*self.inner()).pbCertEncoded,
                (*self.inner()).cbCertEncoded as usize,
            )
            .into()
        }
    }

    /// Return DER-encoded X.509 certificate chain
    pub fn as_chain_der(&self) -> Result<Vec<Vec<u8>>, CngError> {
        unsafe {
            let param = CERT_CHAIN_PARA {
                cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                RequestedUsage: Default::default(),
            };

            let mut context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

            let result = CertGetCertificateChain(
                HCERTCHAINENGINE::default(),
                self.0.inner(),
                ptr::null(),
                HCERTSTORE::default(),
                &param,
                0,
                ptr::null_mut(),
                &mut context,
            );

            if result.as_bool() {
                let mut chain = vec![];

                if (*context).cChain > 0 {
                    let chain_ptr = *(*context).rgpChain;
                    let elements = slice::from_raw_parts(
                        (*chain_ptr).rgpElement,
                        (*chain_ptr).cElement as usize,
                    );
                    for element in elements {
                        let context = (**element).pCertContext;
                        chain.push(Self::borrowed(context).as_der().to_vec());
                    }
                }

                CertFreeCertificateChain(context);

                Ok(chain)
            } else {
                Err(CngError::CertificateChain)
            }
        }
    }
}
