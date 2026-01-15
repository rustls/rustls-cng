use std::{
    hash::Hasher,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, Stream,
    client::{ClientCredentialResolver, CredentialRequest},
    crypto::{Credentials, Identity, SelectedCredential},
    enums::CertificateType,
};
use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType, Pkcs12Flags},
};
use rustls_pki_types::{CertificateDer, ServerName};

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
) -> Result<(Vec<CertificateDer<'static>>, CngSigningKey), Box<dyn std::error::Error>> {
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts
        .first()
        .ok_or_else(|| std::io::Error::other("No client cert"))?;
    let key = context.acquire_key(true)?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context.as_chain_der()?.into_iter().map(Into::into).collect();
    Ok((chain, signing_key))
}

impl ClientCredentialResolver for ClientCertResolver {
    fn resolve(&self, server_hello: &CredentialRequest) -> Option<SelectedCredential> {
        println!("Server sig schemes: {:?}", server_hello.signature_schemes());
        let (chain, signing_key) = get_chain(&self.store, &self.cert_name).ok()?;
        if let Some(ref pin) = self.pin {
            signing_key.key().set_pin(pin).ok()?;
        }
        Credentials::new_unchecked(Arc::new(Identity::from_cert_chain(chain).ok()?), Box::new(signing_key))
            .signer(server_hello.signature_schemes())
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[derive(Parser)]
#[clap(name = "rustls-client-sample")]
struct AppParams {
    #[clap(short = 'c', long = "ca-cert", help = "CA cert name to verify the peer certificate")]
    ca_cert: Option<String>,

    #[clap(short = 'k', long = "keystore", help = "Use external PFX keystore")]
    keystore: Option<PathBuf>,

    #[clap(short = 'p', long = "password", help = "Keystore password or token pin")]
    password: Option<String>,

    #[clap(short = 's', long = "server-name", help = "Server name for TLS SNI extension")]
    server_name: Option<String>,

    #[clap(short = 'l', long = "client-cert", help = "Client cert name for client auth")]
    client_cert: Option<String>,

    #[clap(help = "Server address")]
    server_address: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params: AppParams = AppParams::parse();

    let store = if let Some(ref keystore) = params.keystore {
        let data = std::fs::read(keystore)?;
        CertStore::from_pkcs12(
            &data,
            params.password.as_deref().unwrap_or_default(),
            Pkcs12Flags::default(),
        )?
    } else {
        CertStore::open(CertStoreType::CurrentUser, "my")?
    };

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

    if let Some(ca_cert) = params.ca_cert {
        let ca_cert_context = store.find_by_subject_str(&ca_cert)?;
        let ca_cert = ca_cert_context.first().unwrap();

        root_store.add(ca_cert.as_der().into())?;
    }

    let builder =
        ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER)).with_root_certificates(root_store);

    let client_config = if let Some(client_cert) = params.client_cert {
        builder.with_client_credential_resolver(Arc::new(ClientCertResolver {
            store,
            cert_name: client_cert.clone(),
            pin: params.password.clone(),
        }))?
    } else {
        builder.with_no_client_auth()?
    };

    let server_name = ServerName::try_from(params.server_name.as_deref().unwrap_or(&params.server_address))?.to_owned();

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
