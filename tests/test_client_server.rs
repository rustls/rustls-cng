const PORT: u16 = 18118;
const PASSWORD: &str = "changeit";

mod client {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
        sync::Arc,
    };

    use rustls::{
        client::ResolvesClientCert, sign::CertifiedKey, Certificate, ClientConfig,
        ClientConnection, RootCertStore, SignatureScheme, Stream,
    };

    use rustls_cng::{signer::CngSigningKey, store::CertStore};

    use crate::{PASSWORD, PORT};

    const CLIENT_PFX: &[u8] = include_bytes!("assets/rustls-client.pfx");

    pub struct ClientCertResolver(CertStore, String);

    fn get_chain(
        store: &CertStore,
        name: &str,
    ) -> anyhow::Result<(Vec<Certificate>, CngSigningKey)> {
        let contexts = store.find_by_subject_str(name)?;
        let context = contexts
            .first()
            .ok_or_else(|| anyhow::Error::msg("No client cert"))?;
        let key = context.acquire_key()?;
        let signing_key = CngSigningKey::new(key)?;
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

    pub fn run_client() -> anyhow::Result<()> {
        let store = CertStore::from_pkcs12(CLIENT_PFX, PASSWORD)?;

        let ca_cert_context = store.find_by_subject_str("Inforce Technologies CA")?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(&Certificate(ca_cert.as_der().to_vec()))?;

        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_client_cert_resolver(Arc::new(ClientCertResolver(
                store,
                "rustls-client".to_string(),
            )));

        let mut connection =
            ClientConnection::new(Arc::new(client_config), "rustls-server".try_into()?)?;

        let mut client = TcpStream::connect(format!("localhost:{}", PORT))?;

        let mut tls_stream = Stream::new(&mut connection, &mut client);
        tls_stream.write_all(b"ping")?;
        tls_stream.sock.shutdown(Shutdown::Write)?;

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        assert_eq!(&buf, b"pong");

        tls_stream.sock.shutdown(Shutdown::Read)?;

        Ok(())
    }
}

mod server {
    use std::sync::mpsc::Sender;
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::Arc,
    };

    use rustls::{
        server::{AllowAnyAuthenticatedClient, ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        Certificate, RootCertStore, ServerConfig, ServerConnection, Stream,
    };

    use rustls_cng::{signer::CngSigningKey, store::CertStore};

    use crate::{PASSWORD, PORT};

    const SERVER_PFX: &[u8] = include_bytes!("assets/rustls-server.pfx");

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
        tls_stream.read_exact(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        assert_eq!(&buf, b"ping");
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
        tls_stream.sock.shutdown(Shutdown::Write)?;

        Ok(())
    }

    pub fn run_server(sender: Sender<()>) -> anyhow::Result<()> {
        let store = CertStore::from_pkcs12(SERVER_PFX, PASSWORD)?;

        let ca_cert_context = store.find_by_subject_str("Inforce Technologies CA")?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(&Certificate(ca_cert.as_der().to_vec()))?;

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
            .with_cert_resolver(Arc::new(ServerCertResolver(store)));

        let server = TcpListener::bind(format!("127.0.0.1:{}", PORT))?;

        let _ = sender.send(());

        let stream = server.incoming().next().unwrap()?;
        let config = Arc::new(server_config);
        handle_connection(stream, config)?;

        Ok(())
    }
}

#[test]
fn test_client_server() {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        assert!(server::run_server(tx).is_ok());
    });

    if rx.recv().is_ok() {
        client::run_client().unwrap();
    }
}
