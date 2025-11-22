//! SigningKey implementation

use std::sync::Arc;

use rustls::{
    crypto::{SignatureScheme, Signer, SigningKey},
    error::{Error, OtherError},
};
use rustls_pki_types::SubjectPublicKeyInfoDer;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALG_HANDLE, BCRYPT_SHA512_ALG_HANDLE, BCryptHash,
};

use crate::key::{AlgorithmGroup, NCryptKey, SignaturePadding};

// Convert IEEE-P1363 signature format to DER encoding.
// Some modifications are taken from https://github.com/tofay/rustls-cng-crypto/blob/main/src/signer/ec.rs
fn p1363_to_der(data: &[u8]) -> Vec<u8> {
    const SEQUENCE_TAG: u8 = 0x30;
    const INTEGER_TAG: u8 = 0x02;

    let (mut r, mut s) = data.split_at(data.len() / 2);

    while r[0] == 0x0 {
        r = &r[1..];
    }

    while s[0] == 0x0 {
        s = &s[1..];
    }

    let r_sign: &[u8] = if r[0] >= 0x80 { &[0] } else { &[] };
    let s_sign: &[u8] = if s[0] >= 0x80 { &[0] } else { &[] };

    let v_length = 4 + r_sign.len() + s_sign.len() + r.len() + s.len();

    let (short_form, length_len) = if v_length <= 0x80 {
        (true, 1)
    } else {
        let mut v_length = v_length;
        let mut length_len = 0;
        while v_length > 0 {
            v_length >>= 8;
            length_len += 1;
        }
        (false, length_len)
    };

    let length = length_len + v_length + 1;
    let mut der = Vec::with_capacity(length);

    der.push(SEQUENCE_TAG);
    if short_form {
        der.push(v_length as u8); // LENGTH - short form
    } else {
        der.push(0x80 | length_len as u8);
        for i in (0..length_len).rev() {
            der.push((v_length >> (i * 8)) as u8);
        }
    }

    der.push(INTEGER_TAG);
    der.push((r.len() + r_sign.len()) as u8);
    der.extend(r_sign);
    der.extend(r);

    der.push(INTEGER_TAG);
    der.push((s.len() + s_sign.len()) as u8);
    der.extend(s_sign);
    der.extend(s);
    der
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
                521 => &[SignatureScheme::ECDSA_NISTP521_SHA512],
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
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                (BCRYPT_SHA512_ALG_HANDLE, SignaturePadding::None)
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
            .map_err(|e| Error::Other(OtherError::new(Arc::new(e))))?;

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
