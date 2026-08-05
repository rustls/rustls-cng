//! SigningKey implementation

use std::sync::Arc;

use rustls::{
    sign::{Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme, {Error, OtherError},
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptHash, CryptEncodeObjectEx, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALG_HANDLE,
    BCRYPT_SHA512_ALG_HANDLE, CERT_ECC_SIGNATURE, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
    X509_ECC_SIGNATURE,
};

use crate::key::{AlgorithmGroup, NCryptKey, SignaturePadding};

// Convert an IEEE-P1363 (raw r || s) signature into DER encoding using the Win32 API.
// CryptEncodeObjectEx with X509_ECC_SIGNATURE produces the DER `SEQUENCE { INTEGER r, INTEGER s }`,
// taking care of minimal-length and sign-byte padding of the integers.
fn p1363_to_der(data: &mut [u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() || !data.len().is_multiple_of(2) {
        return Err(Error::General("Invalid signature size".to_owned()));
    }

    let (r, s) = data.split_at_mut(data.len() / 2);

    // CNG integer blobs are little-endian, so reverse the big-endian halves in place.
    r.reverse();
    s.reverse();

    let sig = CERT_ECC_SIGNATURE {
        r: CRYPT_INTEGER_BLOB {
            cbData: r.len() as u32,
            pbData: r.as_mut_ptr(),
        },
        s: CRYPT_INTEGER_BLOB {
            cbData: s.len() as u32,
            pbData: s.as_mut_ptr(),
        },
    };
    let sig_ptr = std::ptr::from_ref(&sig).cast();

    unsafe {
        // First call retrieves the required output buffer size.
        let mut len = 0u32;
        let status = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            sig_ptr,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut len,
        );
        if status == 0 {
            return Err(Error::General(
                "CryptEncodeObjectEx failed to size the signature".to_owned(),
            ));
        }

        let mut der = vec![0u8; len as usize];
        let status = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            sig_ptr,
            0,
            std::ptr::null(),
            der.as_mut_ptr().cast(),
            &mut len,
        );
        if status == 0 {
            return Err(Error::General(
                "CryptEncodeObjectEx failed to encode the signature".to_owned(),
            ));
        }

        der.truncate(len as usize);
        Ok(der)
    }
}

/// Custom implementation of `rustls` SigningKey trait
#[derive(Debug, Clone)]
pub struct CngSigningKey {
    key: NCryptKey,
    algorithm_group: AlgorithmGroup,
    bits: u32,
}

impl CngSigningKey {
    /// Create an instance from the CNG key
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
    pub fn algorithm_group(&self) -> AlgorithmGroup {
        self.algorithm_group
    }

    /// Return a number of bits in the key material
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
                message.as_ptr().cast(),
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
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (hash, padding) = self.hash(message)?;
        let mut signature = self
            .key
            .sign(&hash, padding)
            .map_err(|e| Error::Other(OtherError(Arc::new(e))))?;

        if padding == SignaturePadding::None {
            // For ECDSA keys Windows produces IEEE-P1363 signatures which must be converted to DER format
            Ok(p1363_to_der(&mut signature)?)
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

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.algorithm_group {
            AlgorithmGroup::Rsa => SignatureAlgorithm::RSA,
            AlgorithmGroup::Ecdsa | AlgorithmGroup::Ecdh => SignatureAlgorithm::ECDSA,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use windows_sys::Win32::Security::Cryptography::{
        CryptDecodeObjectEx, CERT_ECC_SIGNATURE, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
        X509_ECC_SIGNATURE,
    };

    // Extract the big-endian magnitude of a CNG integer blob, which is stored in little-endian order.
    unsafe fn blob_to_be(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let le = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
        let mut be = le.iter().rev().copied().collect::<Vec<u8>>();
        while be.len() > 1 && be[0] == 0 {
            be.remove(0);
        }
        be
    }

    // Decode a DER-encoded ECDSA signature via the Win32 API and return the (r, s) integers
    // as big-endian magnitude byte vectors.
    fn decode_der(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            // First call retrieves the required output buffer size.
            let mut len = 0u32;
            let status = CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_ECC_SIGNATURE,
                data.as_ptr(),
                data.len() as u32,
                0,
                ptr::null(),
                ptr::null_mut(),
                &mut len,
            );
            assert_ne!(status, 0, "CryptDecodeObjectEx failed to size the output");

            let mut buf = vec![0u8; len as usize];
            let status = CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_ECC_SIGNATURE,
                data.as_ptr(),
                data.len() as u32,
                0,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut len,
            );
            assert_ne!(status, 0, "CryptDecodeObjectEx failed to decode");

            let sig: &CERT_ECC_SIGNATURE = &*buf.as_ptr().cast();
            (blob_to_be(&sig.r), blob_to_be(&sig.s))
        }
    }

    fn validate_der(data: &[u8], r: &[u8], s: &[u8]) {
        let (parsed_r, parsed_s) = decode_der(data);
        assert_eq!(parsed_r, r);
        assert_eq!(parsed_s, s);
    }

    #[test]
    fn test_p1363_to_der() {
        let mut p1363 = [1, 2, 3, 4, 5, 6, 7, 8];
        let der = super::p1363_to_der(&mut p1363).unwrap();
        validate_der(&der, &[1, 2, 3, 4], &[5, 6, 7, 8]);
    }

    #[test]
    fn test_p1363_to_der_signed() {
        let mut p1363 = [0x81, 2, 3, 4, 0x85, 6, 7, 8];
        let der = super::p1363_to_der(&mut p1363).unwrap();
        validate_der(&der, &[0x81, 2, 3, 4], &[0x85, 6, 7, 8]);
    }

    #[test]
    fn test_p1363_to_der_zeroes_stripped() {
        let mut p1363 = [0, 1, 2, 3, 4, 0, 5, 6, 7, 8];
        let der = super::p1363_to_der(&mut p1363).unwrap();
        validate_der(&der, &[1, 2, 3, 4], &[5, 6, 7, 8]);
    }

    #[test]
    fn test_p1363_to_der_signed_zeroes_stripped() {
        let mut p1363 = [0, 0x81, 2, 3, 4, 0, 0x85, 6, 7, 8];
        let der = super::p1363_to_der(&mut p1363).unwrap();
        validate_der(&der, &[0x81, 2, 3, 4], &[0x85, 6, 7, 8]);
    }

    #[test]
    fn test_p1363_to_der_long() {
        let r = (1..128).collect::<Vec<u8>>();
        let s = (128..254).chain([0]).rev().collect::<Vec<u8>>();

        let mut p1363 = r.clone().into_iter().chain(s.clone()).collect::<Vec<u8>>();
        let der = super::p1363_to_der(&mut p1363).unwrap();

        // The decoded magnitude has the padding zero stripped.
        let expected_s = (128..254).rev().collect::<Vec<u8>>();
        validate_der(&der, &r, &expected_s);
    }
}
