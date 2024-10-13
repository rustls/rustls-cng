use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    client::ResolvesClientCert, sign::CertifiedKey, ClientConfig, ClientConnection, RootCertStore,
    SignatureScheme, Stream,
};
use rustls_pki_types::{CertificateDer, ServerName};

use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
};

const PORT: u16 = 8000;

#[derive(Debug)]
pub struct ClientCertResolver {
    store: CertStore,
    cert_name: String,
    pin: Option<String>,
}

fn get_chain(
    store: &CertStore,
    name: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, CngSigningKey)> {
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts
        .first()
        .ok_or_else(|| anyhow::Error::msg("No client cert"))?;
    let key = context.acquire_key()?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context
        .as_chain_der()?
        .into_iter()
        .map(Into::into)
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
        let (chain, signing_key) = get_chain(&self.store, &self.cert_name).ok()?;
        if let Some(ref pin) = self.pin {
            signing_key.key().set_pin(pin).ok()?;
        }
        for scheme in signing_key.supported_schemes() {
            if sigschemes.contains(scheme) {
                return Some(Arc::new(CertifiedKey {
                    cert: chain,
                    key: Arc::new(signing_key),
                    ocsp: None,
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
        help = "Keystore password or token pin"
    )]
    password: Option<String>,

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
        CertStore::from_pkcs12(&data, params.password.as_deref().unwrap_or_default())?
    } else {
        CertStore::open(CertStoreType::CurrentUser, "my")?
    };

    let ca_cert_context = store.find_by_subject_str(&params.ca_cert)?;
    let ca_cert = ca_cert_context.first().unwrap();

    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert.as_der().into())?;

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_cert_resolver(Arc::new(ClientCertResolver {
            store,
            cert_name: params.client_cert.clone(),
            pin: params.password.clone(),
        }));

    let server_name = ServerName::try_from(params.server_name.as_str())?.to_owned();
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)?;
    let mut client = TcpStream::connect(format!("{}:{}", params.server_address, PORT))?;

    let mut tls_stream = Stream::new(&mut connection, &mut client);
    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut buf = [0u8; 4];
    tls_stream.read_exact(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    tls_stream.sock.shutdown(Shutdown::Read)?;

    Ok(())
}
