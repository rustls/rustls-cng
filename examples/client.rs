use std::{
    hash::Hasher,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
};

use rustls::{
    ClientConfig, RootCertStore,
    client::{ClientCredentialResolver, CredentialRequest},
    crypto::{Credentials, Identity, SelectedCredential},
    enums::CertificateType,
    pki_types::{CertificateDer, ServerName},
};
use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
};
use rustls_util::Stream;

const PORT: u16 = 8000;

#[derive(Debug)]
pub struct ClientCertResolver {
    store: CertStore,
    cert_name: String,
}

fn get_chain(
    store: &CertStore,
    name: &str,
) -> Result<(Vec<CertificateDer<'static>>, CngSigningKey), Box<dyn std::error::Error>> {
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts
        .first()
        .ok_or_else(|| std::io::Error::other("No client cert"))?;
    let key = context.acquire_key(false)?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context.as_chain_der()?.into_iter().map(Into::into).collect();
    Ok((chain, signing_key))
}

impl ClientCredentialResolver for ClientCertResolver {
    fn resolve(&self, server_hello: &CredentialRequest) -> Option<SelectedCredential> {
        println!("Server sig schemes: {:?}", server_hello.signature_schemes());
        let (chain, signing_key) = get_chain(&self.store, &self.cert_name).ok()?;
        Credentials::new_unchecked(Arc::new(Identity::from_cert_chain(chain).ok()?), Box::new(signing_key))
            .signer(server_hello.signature_schemes())
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        println!("Usage: {} <sni-name> [client-cert-name]", args[0]);
        return Ok(());
    }

    let store = CertStore::open(CertStoreType::CurrentUser, "my")?;

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

    let builder =
        ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER)).with_root_certificates(root_store);

    let client_config = Arc::new(if let Some(client_cert) = args.get(2) {
        builder.with_client_credential_resolver(Arc::new(ClientCertResolver {
            store,
            cert_name: client_cert.clone(),
        }))?
    } else {
        builder.with_no_client_auth()?
    });

    let server_name = ServerName::try_from(args[1].as_str())?.to_owned();

    let mut connection = client_config.connect(server_name).build()?;
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", PORT))?;

    let mut tls_stream = Stream::new(&mut connection, &mut client);
    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut buf = [0u8; 4];
    tls_stream.read_exact(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    tls_stream.sock.shutdown(Shutdown::Read)?;

    Ok(())
}
