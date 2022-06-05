use std::sync::Arc;

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    Certificate,
};

use crate::key::CngChain;

pub struct ServerCertResolver;

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        let cng = CngChain::from_subject_str(name).ok()?;
        let certs = cng
            .certificates()
            .iter()
            .map(|cert| Certificate(cert.clone()))
            .collect::<Vec<_>>();
        Some(Arc::new(CertifiedKey {
            cert: certs,
            key: Arc::new(cng),
            ocsp: None,
            sct_list: None,
        }))
    }
}
