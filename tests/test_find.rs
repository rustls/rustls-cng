use rustls_cng::store::{CertStore, Pkcs12Flags};

const PFX: &[u8] = include_bytes!("assets/rustls-ec.p12");
const PASSWORD: &str = "changeit";

#[test]
fn test_find_by_subject_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let context = store
        .find_by_subject_str("rustls")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_subject_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let context = store
        .find_by_subject_name("CN=rustls-ec")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let context = store
        .find_by_issuer_str("Inforce")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let context = store
        .find_by_issuer_name("O=Inforce Technologies, CN=Inforce Technologies CA")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_hash() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let sha1 = [
        0x66, 0xBF, 0xFD, 0xE5, 0xD2, 0x9D, 0x57, 0x97, 0x1B, 0x17, 0xBB, 0x81, 0x5D, 0x7A, 0xF8,
        0x6D, 0x61, 0x91, 0xA8, 0xA7,
    ];
    let context = store.find_by_sha1(sha1).unwrap().into_iter().next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_hash256() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let sha256 = [
        0xC9, 0x7C, 0xD6, 0xA1, 0x3F, 0xF6, 0xBD, 0xF6, 0xD4, 0xE2, 0xFB, 0x0E, 0xCD, 0x74, 0x2F,
        0x14, 0x30, 0x53, 0xB0, 0x89, 0xFA, 0x4D, 0xA5, 0xE5, 0x8B, 0xA3, 0x9F, 0x72, 0xED, 0x2F,
        0x9F, 0xB6,
    ];

    let context = store.find_by_sha256(sha256).unwrap().into_iter().next();
    assert!(context.is_some());
}

#[test]
fn test_find_all() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD, Pkcs12Flags::default())
        .expect("Cannot open cert store");

    let context = store.find_all().unwrap().into_iter().next();
    assert!(context.is_some());
}
