use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
};

use rustls::{
    RootCertStore, ServerConfig, ServerConnection,
    server::{ClientHello, WebPkiClientVerifier},
};
use rustls_cng::{
    config::{CngCredentials, WithCngServerCredentials},
    store::{CertStore, CertStoreType},
};
use rustls_util::Stream;

const PORT: u16 = 8000;

fn resolve(store: &CertStore, client_hello: &ClientHello) -> Result<CngCredentials, rustls::Error> {
    let name = client_hello
        .server_name()
        .ok_or_else(|| rustls::Error::NoSuitableCertificate)
        .inspect_err(|e| println!("{}", e))?;

    let contexts = store
        .find_by_subject_str(name)
        .map_err(|_| rustls::Error::NoSuitableCertificate)
        .inspect_err(|e| println!("{}", e))?;

    let (context, key) = contexts
        .into_iter()
        .find_map(|ctx| {
            let key = ctx.acquire_key(false).ok()?;
            Some((ctx, key))
        })
        .ok_or_else(|| rustls::Error::NoSuitableCertificate)
        .inspect_err(|e| println!("{}", e))?;

    let chain = context
        .as_chain_der()
        .map_err(|_| rustls::Error::NoSuitableCertificate)
        .inspect_err(|e| println!("{}", e))?;

    let certs = chain.into_iter().map(Into::into).collect();
    Ok(CngCredentials::new(key, certs))
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
    let store = CertStore::open(CertStoreType::CurrentUser, "my")?;

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store), &rustls_aws_lc_rs::DEFAULT_PROVIDER).build()?;

    let server_config = ServerConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cng_server_credentials(move |client_hello| resolve(&store, client_hello))?;

    let server = TcpListener::bind(format!("127.0.0.1:{PORT}"))?;

    println!("Listening on port {}", PORT);

    // to test: openssl s_client -servername HOSTNAME -connect localhost:8000
    accept(server, Arc::new(server_config))?;

    Ok(())
}
