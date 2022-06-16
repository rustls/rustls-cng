use rustls::{internal::msgs::enums::SignatureAlgorithm, sign::SigningKey, SignatureScheme};

use rustls_cng::{signer::CngSigningKey, store::CertStore};

const PFX: &[u8] = include_bytes!("assets/rustls-ec.p12");
const PASSWORD: &str = "changeit";
const MESSAGE: &str = "Security is our business";

#[test]
fn test_sign() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_subject_str("rustls")
        .expect("No signer certificate")
        .into_iter()
        .next()
        .unwrap();

    let offered = vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
    ];

    let key = context.acquire_key().unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();
    assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ECDSA);
    let signer = signing_key.choose_scheme(&offered).unwrap();
    assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);

    let signature = signer.sign(MESSAGE.as_bytes()).unwrap();
    assert!(signature.len() >= 102);
}
