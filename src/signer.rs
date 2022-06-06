use rustls::{
    internal::msgs::enums::SignatureAlgorithm,
    sign::{Signer, SigningKey},
    Error, SignatureScheme,
};
use sha2::digest::Digest;

use crate::{
    cert::CertContext,
    error::CngError,
    key::{NCryptKey, SignaturePadding},
};

fn do_sha(message: &[u8], mut hasher: impl Digest) -> Vec<u8> {
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub struct CngSigningKey {
    key: NCryptKey,
    algorithm_group: String,
}

impl CngSigningKey {
    pub fn from_cert_context(context: &CertContext) -> Result<Self, CngError> {
        let key = context.acquire_key()?;
        let group = key.algorithm_group()?;
        match group.as_str() {
            "RSA" | "ECDSA" | "ECDH" => Ok(Self {
                key,
                algorithm_group: group,
            }),
            _ => Err(CngError::UnsupportedKeyAlgorithm),
        }
    }

    pub fn key(&self) -> &NCryptKey {
        &self.key
    }

    pub fn algorithm_group(&self) -> &str {
        &self.algorithm_group
    }

    pub fn supported_schemes(&self) -> Vec<SignatureScheme> {
        match self.algorithm_group.as_str() {
            "RSA" => {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                ]
            }
            "ECDSA" | "ECDH" => match self.key.bits() {
                Ok(256) => vec![SignatureScheme::ECDSA_NISTP256_SHA256],
                Ok(384) => vec![SignatureScheme::ECDSA_NISTP384_SHA384],
                Ok(521) => vec![SignatureScheme::ECDSA_NISTP521_SHA512],
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

struct CngSigner {
    key: NCryptKey,
    scheme: SignatureScheme,
}

impl Signer for CngSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (hash, alg, padding) = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                "SHA256",
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PKCS1_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                "SHA384",
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PKCS1_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                "SHA512",
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::RSA_PSS_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                "SHA256",
                SignaturePadding::Pss,
            ),
            SignatureScheme::RSA_PSS_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                "SHA384",
                SignaturePadding::Pss,
            ),
            SignatureScheme::RSA_PSS_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                "SHA512",
                SignaturePadding::Pss,
            ),
            SignatureScheme::ECDSA_NISTP256_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                "SHA256",
                SignaturePadding::None,
            ),
            SignatureScheme::ECDSA_NISTP384_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                "SHA384",
                SignaturePadding::None,
            ),
            SignatureScheme::ECDSA_NISTP521_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                "SHA512",
                SignaturePadding::None,
            ),
            _ => return Err(Error::General("Unsupported signature scheme!".to_owned())),
        };
        self.key
            .sign(&hash, alg, padding)
            .map_err(|e| Error::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl SigningKey for CngSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let supported = self.supported_schemes();
        println!("Offered: {:#?}, Supported: {:#?}", offered, supported);
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
        match self.algorithm_group.as_str() {
            "RSA" => SignatureAlgorithm::RSA,
            "ECDSA" | "ECDH" => SignatureAlgorithm::ECDSA,
            _ => panic!("Unexpected algorithm group!"),
        }
    }
}
