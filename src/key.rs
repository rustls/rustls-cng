use rustls::{
    internal::msgs::enums::SignatureAlgorithm,
    sign::{Signer, SigningKey},
    Error, SignatureScheme,
};
use sha2::digest::{FixedOutput, Update};
use wincms::cert::{CertStore, CertStoreType, NCryptKey, SignaturePadding};

fn do_sha(message: &[u8], mut hasher: impl Update + FixedOutput) -> Vec<u8> {
    hasher.update(message);
    hasher.finalize_fixed().to_vec()
}

pub struct CngChain {
    key: NCryptKey,
    certificates: Vec<Vec<u8>>,
    algorithm_group: String,
}

impl CngChain {
    pub fn from_subject_str(subject: &str) -> anyhow::Result<Self> {
        let store = CertStore::open(CertStoreType::LocalMachine, "my")?;
        let certs = store.find_cert_by_subject_str(subject)?;
        for mut cert in certs {
            if let Ok(key) = cert.acquire_key(true) {
                if let Ok(group) = key.get_algorithm_group() {
                    match group.as_str() {
                        "RSA" | "ECDSA" => {
                            return Ok(Self {
                                key,
                                certificates: cert.as_chain_der()?,
                                algorithm_group: group,
                            })
                        }
                        _ => {}
                    }
                }
            }
        }
        Err(anyhow::Error::msg("No suitable certificate chain found!"))
    }

    pub fn key(&self) -> &NCryptKey {
        &self.key
    }

    pub fn certificates(&self) -> &[Vec<u8>] {
        self.certificates.as_ref()
    }

    fn supported_schemes(&self) -> Vec<SignatureScheme> {
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
            "ECDSA" => match self.key.get_bits() {
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
            SignatureScheme::ECDSA_NISTP256_SHA256 => (
                do_sha(message, sha2::Sha256::default()),
                "SHA256",
                SignaturePadding::None,
            ),
            SignatureScheme::RSA_PKCS1_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                "SHA384",
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::ECDSA_NISTP384_SHA384 => (
                do_sha(message, sha2::Sha384::default()),
                "SHA384",
                SignaturePadding::None,
            ),
            SignatureScheme::RSA_PKCS1_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                "SHA512",
                SignaturePadding::Pkcs1,
            ),
            SignatureScheme::ECDSA_NISTP521_SHA512 => (
                do_sha(message, sha2::Sha512::default()),
                "SHA512",
                SignaturePadding::None,
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
            _ => return Err(Error::General("Unsupported signature scheme!".to_owned())),
        };
        self.key
            .sign_hash(&hash, alg, padding)
            .map_err(|e| Error::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl SigningKey for CngChain {
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
        match self.algorithm_group.as_str() {
            "RSA" => SignatureAlgorithm::RSA,
            "ECDSA" => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }
}
