use std::{
    io::Read,
    net::{Shutdown, TcpListener},
    sync::Arc,
};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    Certificate, ServerConfig, ServerConnection, Stream,
};

use rustls_cng::{
    signer::CngSigningKey,
    store::{CertStore, CertStoreType},
};

const PORT: u16 = 8000;

pub struct ServerCertResolver(CertStore);

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        println!("Client hello server name: {:?}", client_hello.server_name());
        let name = client_hello.server_name()?;
        let contexts = self.0.find_by_subject_str(name).ok()?;

        let (context, key) = contexts.into_iter().find_map(|ctx| {
            let key = ctx.acquire_key().ok()?;
            CngSigningKey::from_key(key).ok().map(|key| (ctx, key))
        })?;

        println!("Key alg group: {:?}", key.key().algorithm_group());
        println!("Key alg: {:?}", key.key().algorithm());

        let chain = context.as_chain_der().ok()?;
        let certs = chain.into_iter().map(Certificate).collect();
        Some(Arc::new(CertifiedKey {
            cert: certs,
            key: Arc::new(key),
            ocsp: None,
            sct_list: None,
        }))
    }
}

fn accept(
    server: TcpListener,
    config: Arc<ServerConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut stream = stream?;
        println!("Accepted incoming connection from {}", stream.peer_addr()?);
        let mut connection = ServerConnection::new(config.clone())?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);

        if tls_stream.conn.is_handshaking() {
            tls_stream.conn.complete_io(tls_stream.sock)?;
        }

        println!("Protocol version: {:?}", tls_stream.conn.protocol_version());
        println!(
            "Cipher suite: {:?}",
            tls_stream.conn.negotiated_cipher_suite()
        );
        println!("SNI host name: {:?}", tls_stream.conn.sni_hostname());
        println!(
            "Peer certificates: {:?}",
            tls_stream.conn.peer_certificates()
        );

        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));

        tls_stream.sock.shutdown(Shutdown::Read)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    let store = if args.len() < 3 {
        CertStore::open(CertStoreType::LocalMachine, "my")?
    } else {
        let data = std::fs::read(&args[1])?;
        CertStore::from_pkcs12(&data, &args[2])?
    };

    let server_config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ServerCertResolver(store)));

    let server = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;

    accept(server, Arc::new(server_config))?;

    Ok(())
}
