use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    RootCertStore, ServerConfig, ServerConnection,
    crypto::{Credentials, Identity, SelectedCredential},
    server::{ClientHello, ServerCredentialResolver, WebPkiClientVerifier},
};
use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType, Pkcs12Flags},
};
use rustls_util::Stream;

const PORT: u16 = 8000;

#[derive(Parser)]
#[clap(name = "rustls-server-sample")]
struct AppParams {
    #[clap(
        action,
        short = 'c',
        long = "ca-cert",
        help = "CA cert name to verify the peer certificate"
    )]
    ca_cert: Option<String>,

    #[clap(action, short = 'k', long = "keystore", help = "Use external PFX keystore")]
    keystore: Option<PathBuf>,

    #[clap(action, short = 'p', long = "password", help = "Keystore password or card pin")]
    password: Option<String>,
}

#[derive(Debug)]
pub struct ServerCertResolver {
    store: CertStore,
    pin: Option<String>,
}

impl ServerCredentialResolver for ServerCertResolver {
    fn resolve(&self, client_hello: &ClientHello) -> Result<SelectedCredential, rustls::Error> {
        println!("Client hello server name: {:?}", client_hello.server_name());
        let name = client_hello
            .server_name()
            .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

        let contexts = self
            .store
            .find_by_subject_str(name)
            .map_err(|_| rustls::Error::NoSuitableCertificate)?;

        let (context, key) = contexts
            .into_iter()
            .find_map(|ctx| {
                let key = ctx.acquire_key(true).ok()?;
                if let Some(ref pin) = self.pin {
                    key.set_pin(pin).ok()?;
                }
                CngSigningKey::new(key).ok().map(|key| (ctx, key))
            })
            .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

        println!("Key alg group: {:?}", key.key().algorithm_group());
        println!("Key alg: {:?}", key.key().algorithm());

        let chain = context
            .as_chain_der()
            .map_err(|_| rustls::Error::NoSuitableCertificate)?;
        let certs = chain.into_iter().map(Into::into).collect();

        Credentials::new_unchecked(Arc::new(Identity::from_cert_chain(certs)?), Box::new(key))
            .signer(client_hello.signature_schemes())
            .ok_or_else(|| rustls::Error::General("No common schemes".to_owned()))
    }
}

fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Accepted incoming connection from {}", stream.peer_addr()?);
    let mut connection = ServerConnection::new(config)?;
    let mut tls_stream = Stream::new(&mut connection, &mut stream);

    rustls_util::complete_io(tls_stream.sock, tls_stream.conn)?;

    println!("Protocol version: {:?}", tls_stream.conn.protocol_version());
    println!("Cipher suite: {:?}", tls_stream.conn.negotiated_cipher_suite());
    println!("SNI host name: {:?}", tls_stream.conn.server_name());
    println!("Peer identity: {:?}", tls_stream.conn.peer_identity());

    let mut buf = [0u8; 4];
    tls_stream.read_exact(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    tls_stream.sock.shutdown(Shutdown::Read)?;
    tls_stream.write_all(b"pong")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    Ok(())
}

fn accept(server: TcpListener, config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming().flatten() {
        let config = config.clone();
        std::thread::spawn(|| {
            let _ = handle_connection(stream, config);
        });
    }
    Ok(())
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

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store), &rustls_aws_lc_rs::DEFAULT_PROVIDER).build()?;

    let server_config = ServerConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
        .with_client_cert_verifier(Arc::new(verifier))
        .with_server_credential_resolver(Arc::new(ServerCertResolver {
            store,
            pin: params.password.clone(),
        }))?;

    let server = TcpListener::bind(format!("0.0.0.0:{PORT}"))?;

    // to test: openssl s_client -servername HOSTNAME -connect localhost:8000
    accept(server, Arc::new(server_config))?;

    Ok(())
}
