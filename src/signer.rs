use rustls::{
    internal::msgs::enums::SignatureAlgorithm,
    sign::{Signer, SigningKey},
    Error, SignatureScheme,
};
use sha2::digest::Digest;

use crate::{
    cert::CertContext,
    error::CngError,
    key::{AlgorithmGroup, NCryptKey, SignaturePadding},
};

fn do_sha(message: &[u8], mut hasher: impl Digest) -> Vec<u8> {
    hasher.update(message);
    hasher.finalize().to_vec()
}

// Convert IEEE-P1363 signature format to ASN.1
fn p1363_to_der(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    let r = &data[0..data.len() / 2];
    let s = &data[data.len() / 2..];

    result.push(0x30); // SEQUENCE
    result.push(0); // length, filled later

    // encode each number as unsigned integer
    for num in [r, s] {
        let signed = num[0] >= 0x80;
        result.push(0x02); // INTEGER
        result.push(num.len() as u8 + signed as u8); // length
        if signed {
            result.push(0);
        }
        result.extend(num);
    }
    result[1] = (result.len() - 2) as u8;
    result
}

pub struct CngSigningKey {
    key: NCryptKey,
    algorithm_group: AlgorithmGroup,
    bits: u32,
}

impl CngSigningKey {
    pub fn from_cert_context(context: &CertContext) -> Result<Self, CngError> {
        let key = context.acquire_key()?;
        let group = key.algorithm_group()?;
        let bits = key.bits()?;
        match group {
            AlgorithmGroup::Other(_) => Err(CngError::UnsupportedKeyAlgorithm),
            group => Ok(Self {
                key,
                algorithm_group: group,
                bits,
            }),
        }
    }

    pub fn key(&self) -> &NCryptKey {
        &self.key
    }

    pub fn algorithm_group(&self) -> &AlgorithmGroup {
        &self.algorithm_group
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

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
            _ => &[],
        }
    }
}

struct CngSigner {
    key: NCryptKey,
    scheme: SignatureScheme,
}

impl Signer for CngSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (hash, padding) = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PKCS1_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PKCS1_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PSS_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                SignaturePadding::Pss,
            ),
            SignatureScheme::RSA_PSS_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                SignaturePadding::Pss,
            ),
            SignatureScheme::RSA_PSS_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                SignaturePadding::Pss,
            ),
            SignatureScheme::ECDSA_NISTP256_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                SignaturePadding::None,
            ),
            SignatureScheme::ECDSA_NISTP384_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                SignaturePadding::None,
            ),
            SignatureScheme::ECDSA_NISTP521_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                SignaturePadding::None,
            ),
            _ => return Err(Error::General("Unsupported signature scheme!".to_owned())),
        };

        let signature = self
            .key
            .sign(&hash, padding)
            .map_err(|e| Error::General(e.to_string()))?;

        if padding == SignaturePadding::None {
            // For ECDSA keys Windows produces IEEE-P1363 signatures.
            // Convert them to ASN.1
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

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.algorithm_group {
            AlgorithmGroup::Rsa => SignatureAlgorithm::RSA,
            AlgorithmGroup::Ecdsa | AlgorithmGroup::Ecdh => SignatureAlgorithm::ECDSA,
            _ => panic!("Unexpected algorithm group!"),
        }
    }
}
