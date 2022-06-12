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
