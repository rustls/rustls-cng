//! SigningKey implementation

use std::sync::Arc;

use rustls::{
    Error, OtherError, SignatureAlgorithm, SignatureScheme,
    sign::{Signer, SigningKey},
};
use rustls_pki_types::SubjectPublicKeyInfoDer;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALG_HANDLE, BCRYPT_SHA512_ALG_HANDLE, BCryptHash,
};

use crate::key::{AlgorithmGroup, NCryptKey, SignaturePadding};

// Convert IEEE-P1363 signature format to DER encoding.
// We assume the length of the r and s parts is less than 256 bytes.
fn p1363_to_der(data: &[u8]) -> Vec<u8> {
    let (r, s) = data.split_at(data.len() / 2);

    let r_sign: &[u8] = if r[0] >= 0x80 { &[0] } else { &[] };
    let s_sign: &[u8] = if s[0] >= 0x80 { &[0] } else { &[] };

    let length = data.len() + 2 + 4 + r_sign.len() + s_sign.len();

    let mut buf = Vec::with_capacity(length);

    buf.push(0x30); // SEQUENCE
    buf.push((length - 2) as u8);

    buf.push(0x02); // INTEGER
    buf.push((r.len() + r_sign.len()) as u8);
    buf.extend(r_sign);
    buf.extend(r);

    buf.push(0x02); // INTEGER
    buf.push((s.len() + s_sign.len()) as u8);
    buf.extend(s_sign);
    buf.extend(s);

    buf
}

/// Custom implementation of `rustls` SigningKey trait
#[derive(Debug)]
pub struct CngSigningKey {
    key: NCryptKey,
    algorithm_group: AlgorithmGroup,
    bits: u32,
}

impl CngSigningKey {
    /// Create instance from the CNG key
    pub fn new(key: NCryptKey) -> crate::Result<Self> {
        let group = key.algorithm_group()?;
        let bits = key.bits()?;
        Ok(Self {
            key,
            algorithm_group: group,
            bits,
        })
    }

    /// Return a reference to the CNG key
    pub fn key(&self) -> &NCryptKey {
        &self.key
    }

    /// Return algorithm group of the key
    pub fn algorithm_group(&self) -> &AlgorithmGroup {
        &self.algorithm_group
    }

    /// Return number of bits in the key material
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Return supported signature schemes
    pub fn supported_schemes(&self) -> &[SignatureScheme] {
        match self.algorithm_group {
            AlgorithmGroup::Rsa => &[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ],
            AlgorithmGroup::Ecdsa | AlgorithmGroup::Ecdh => match self.bits {
                256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
                384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
                _ => &[],
            },
        }
    }
}

#[derive(Debug)]
struct CngSigner {
    key: NCryptKey,
    scheme: SignatureScheme,
}

impl CngSigner {
    // hash function using BCryptHash function which uses FIPS certified SymCrypt
    fn hash(&self, message: &[u8]) -> Result<(Vec<u8>, SignaturePadding), Error> {
        let (alg, padding) = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => {
                (BCRYPT_SHA256_ALG_HANDLE, SignaturePadding::Pkcs1)
            }
            SignatureScheme::RSA_PKCS1_SHA384 => {
                (BCRYPT_SHA384_ALG_HANDLE, SignaturePadding::Pkcs1)
            }
            SignatureScheme::RSA_PKCS1_SHA512 => {
                (BCRYPT_SHA512_ALG_HANDLE, SignaturePadding::Pkcs1)
            }
            SignatureScheme::RSA_PSS_SHA256 => (BCRYPT_SHA256_ALG_HANDLE, SignaturePadding::Pss),
            SignatureScheme::RSA_PSS_SHA384 => (BCRYPT_SHA384_ALG_HANDLE, SignaturePadding::Pss),
            SignatureScheme::RSA_PSS_SHA512 => (BCRYPT_SHA512_ALG_HANDLE, SignaturePadding::Pss),
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                (BCRYPT_SHA256_ALG_HANDLE, SignaturePadding::None)
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                (BCRYPT_SHA384_ALG_HANDLE, SignaturePadding::None)
            }
            _ => return Err(Error::General("Unsupported signature scheme".to_owned())),
        };

        let hash_len = match alg {
            BCRYPT_SHA256_ALG_HANDLE => 32,
            BCRYPT_SHA384_ALG_HANDLE => 48,
            BCRYPT_SHA512_ALG_HANDLE => 64,
            _ => return Err(Error::General("Unsupported hash algorithm!".to_owned())),
        };

        let mut hash = vec![0u8; hash_len];

        unsafe {
            let status = BCryptHash(
                alg,
                std::ptr::null_mut(), // pbSecret
                0,                    // cbSecret
                message.as_ptr() as *mut u8,
                message.len() as u32,
                hash.as_mut_ptr(),
                hash_len as u32,
            );

            if status != 0 {
                return Err(Error::General(format!(
                    "BCryptHash failed with status: 0x{status:X}"
                )));
            }
        }
        Ok((hash, padding))
    }
}

impl Signer for CngSigner {
    fn sign(self: Box<CngSigner>, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (hash, padding) = self.hash(message)?;
        let signature = self
            .key
            .sign(&hash, padding)
            .map_err(|e| Error::Other(OtherError(Arc::new(e))))?;

        if padding == SignaturePadding::None {
            // For ECDSA keys Windows produces IEEE-P1363 signatures which must be converted to DER format
            Ok(p1363_to_der(&signature))
        } else {
            Ok(signature)
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl SigningKey for CngSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let supported = self.supported_schemes();
        for scheme in offered {
            if supported.contains(scheme) {
                return Some(Box::new(CngSigner {
                    key: self.key.clone(),
                    scheme: *scheme,
                }));
            }
        }
        None
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.algorithm_group {
            AlgorithmGroup::Rsa => SignatureAlgorithm::RSA,
            AlgorithmGroup::Ecdsa | AlgorithmGroup::Ecdh => SignatureAlgorithm::ECDSA,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_p1363_to_der() {
        let p1363 = [1, 2, 3, 4, 5, 6, 7, 8];
        let der = super::p1363_to_der(&p1363);
        assert_eq!(
            der,
            [0x30, 0x0c, 0x02, 0x04, 1, 2, 3, 4, 0x02, 0x04, 5, 6, 7, 8]
        )
    }

    #[test]
    fn test_p1363_to_der_signed() {
        let p1363 = [0x81, 2, 3, 4, 0x85, 6, 7, 8];
        let der = super::p1363_to_der(&p1363);
        assert_eq!(
            der,
            [
                0x30, 0x0e, 0x02, 0x05, 0, 0x81, 2, 3, 4, 0x02, 0x05, 0, 0x85, 6, 7, 8
            ]
        )
    }
}
