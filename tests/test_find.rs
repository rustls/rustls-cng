use rustls_cng::store::CertStore;

const PFX: &[u8] = include_bytes!("assets/rustls-ec.p12");
const PASSWORD: &str = "changeit";

#[test]
fn test_find_by_subject_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_subject_str("rustls")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_subject_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_subject_name("CN=rustls-ec")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_str() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_issuer_str("Inforce")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_issuer_name() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store
        .find_by_issuer_name("O=Inforce Technologies, CN=Inforce Technologies CA")
        .unwrap()
        .into_iter()
        .next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_hash() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let sha1 = [
        0xfe, 0x0e, 0x21, 0x9b, 0x62, 0xf8, 0xf7, 0x8a, 0x93, 0xa3, 0x05, 0xa3, 0xaf, 0xed, 0x80,
        0x23, 0x0d, 0xce, 0xab, 0x61,
    ];
    let context = store.find_by_sha1(sha1).unwrap().into_iter().next();
    assert!(context.is_some());
}

#[test]
fn test_find_by_hash256() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");
     
    let sha256 = [
        0x83, 0xb4, 0x4e, 0xc2, 0xa7, 0xa6, 0x8a, 0x3e,
        0x5d, 0x13, 0xf8, 0xc7, 0x6a, 0xf4, 0x64, 0x87,
        0x98, 0x41, 0x8b, 0x36, 0xf9, 0x1d, 0x77, 0x91,
        0xcd, 0x74, 0x09, 0x7e, 0x25, 0xd7, 0xd3, 0x44
    ];
    
    let context = store.find_by_sha256(sha256).unwrap().into_iter().next();
    assert!(context.is_some());
}

#[test]
fn test_find_all() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let context = store.find_all().unwrap().into_iter().next();
    assert!(context.is_some());
}
