use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    client::ResolvesClientCert, sign::CertifiedKey, Certificate, ClientConfig, ClientConnection,
    RootCertStore, SignatureScheme, Stream,
};

use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
};

const PORT: u16 = 8000;

pub struct ClientCertResolver(CertStore, String);

fn get_chain(store: &CertStore, name: &str) -> anyhow::Result<(Vec<Certificate>, CngSigningKey)> {
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts
        .first()
        .ok_or_else(|| anyhow::Error::msg("No client cert"))?;
    let key = context.acquire_key()?;
    let signing_key = CngSigningKey::from_key(key)?;
    let chain = context
        .as_chain_der()?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok((chain, signing_key))
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        println!("Server sig schemes: {:#?}", sigschemes);
        let (chain, signing_key) = get_chain(&self.0, &self.1).ok()?;
        for scheme in signing_key.supported_schemes() {
            if sigschemes.contains(scheme) {
                return Some(Arc::new(CertifiedKey {
                    cert: chain,
                    key: Arc::new(signing_key),
                    ocsp: None,
                    sct_list: None,
                }));
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Parser)]
#[clap(name = "rustls-client-sample")]
struct AppParams {
    #[clap(
        short = 'c',
        long = "ca-cert",
        help = "CA cert name to verify the peer certificate"
    )]
    ca_cert: String,

    #[clap(short = 'k', long = "keystore", help = "Use external PFX keystore")]
    keystore: Option<PathBuf>,

    #[clap(
        short = 'p',
        long = "password",
        help = "Keystore password",
        default_value = "changeit"
    )]
    password: String,

    #[clap(
        short = 's',
        long = "server-name",
        help = "Server name for TLS SNI extension"
    )]
    server_name: String,

    #[clap(
        short = 'l',
        long = "client-cert",
        help = "Client cert name for client auth"
    )]
    client_cert: String,

    #[clap(help = "Server address")]
    server_address: String,
}

fn main() -> anyhow::Result<()> {
    let params: AppParams = AppParams::parse();

    let store = if let Some(ref keystore) = params.keystore {
        let data = std::fs::read(keystore)?;
        CertStore::from_pkcs12(&data, &params.password)?
    } else {
        CertStore::open(CertStoreType::LocalMachine, "my")?
    };

    let ca_cert_context = store.find_by_subject_str(&params.ca_cert)?;
    let ca_cert = ca_cert_context.first().unwrap();

    let mut root_store = RootCertStore::empty();
    root_store.add(&Certificate(ca_cert.as_der()))?;

    let client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_client_cert_resolver(Arc::new(ClientCertResolver(
            store,
            params.client_cert.clone(),
        )));

    let mut connection = ClientConnection::new(
        Arc::new(client_config),
        params.server_name.as_str().try_into()?,
    )?;
    let mut client = TcpStream::connect(format!("{}:{}", params.server_address, PORT))?;

    let mut tls_stream = Stream::new(&mut connection, &mut client);
    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut buf = Vec::new();
    tls_stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    tls_stream.sock.shutdown(Shutdown::Read)?;

    Ok(())
}
