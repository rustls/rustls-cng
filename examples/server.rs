use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    server::{AllowAnyAuthenticatedClient, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    Certificate, RootCertStore, ServerConfig, ServerConnection, Stream,
};

use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
};

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
    ca_cert: String,

    #[clap(
        action,
        short = 'k',
        long = "keystore",
        help = "Use external PFX keystore"
    )]
    keystore: Option<PathBuf>,

    #[clap(
        action,
        short = 'p',
        long = "password",
        help = "Keystore password",
        default_value = "changeit"
    )]
    password: String,
}

pub struct ServerCertResolver(CertStore);

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        println!("Client hello server name: {:?}", client_hello.server_name());
        let name = client_hello.server_name()?;

        // look up certificate by subject
        let contexts = self.0.find_by_subject_str(name).ok()?;

        // attempt to acquire a private key and construct CngSigningKey
        let (context, key) = contexts.into_iter().find_map(|ctx| {
            let key = ctx.acquire_key().ok()?;
            CngSigningKey::new(key).ok().map(|key| (ctx, key))
        })?;

        println!("Key alg group: {:?}", key.key().algorithm_group());
        println!("Key alg: {:?}", key.key().algorithm());

        // attempt to acquire a full certificate chain
        let chain = context.as_chain_der().ok()?;
        let certs = chain.into_iter().map(Certificate).collect();

        // return CertifiedKey instance
        Some(Arc::new(CertifiedKey {
            cert: certs,
            key: Arc::new(key),
            ocsp: None,
            sct_list: None,
        }))
    }
}

fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    println!("Accepted incoming connection from {}", stream.peer_addr()?);
    let mut connection = ServerConnection::new(config)?;
    let mut tls_stream = Stream::new(&mut connection, &mut stream);

    // perform handshake early to get and dump some protocol information
    if tls_stream.conn.is_handshaking() {
        tls_stream.conn.complete_io(tls_stream.sock)?;
    }

    println!("Protocol version: {:?}", tls_stream.conn.protocol_version());
    println!(
        "Cipher suite: {:?}",
        tls_stream.conn.negotiated_cipher_suite()
    );
    println!("SNI host name: {:?}", tls_stream.conn.server_name());
    println!(
        "Peer certificates: {:?}",
        tls_stream.conn.peer_certificates().map(|c| c.len())
    );

    let mut buf = [0u8; 4];
    tls_stream.read(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    tls_stream.sock.shutdown(Shutdown::Read)?;
    tls_stream.write_all(b"pong")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    Ok(())
}

fn accept(server: TcpListener, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    for stream in server.incoming().flatten() {
        let config = config.clone();
        std::thread::spawn(|| {
            let _ = handle_connection(stream, config);
        });
    }
    Ok(())
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
    root_store.add(&Certificate(ca_cert.as_der().to_vec()))?;

    let server_config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
        .with_cert_resolver(Arc::new(ServerCertResolver(store)));

    let server = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;

    // to test: openssl s_client -servername HOSTNAME -connect localhost:8000
    accept(server, Arc::new(server_config))?;

    Ok(())
}
