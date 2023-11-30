const CA_SUBJECT: &str = "Inforce Technologies CA";
const CLIENT_PFX: &[u8] = include_bytes!("assets/rustls-client.pfx");
const SERVER_PFX: &[u8] = include_bytes!("assets/rustls-server.pfx");
const PASSWORD: &str = "changeit";

mod client {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
        sync::Arc,
    };

    use rustls::{
        client::ResolvesClientCert, sign::CertifiedKey, ClientConfig, ClientConnection,
        RootCertStore, SignatureScheme, Stream,
    };
    use rustls_pki_types::CertificateDer;

    use rustls_cng::{signer::CngSigningKey, store::CertStore};

    #[derive(Debug)]
    pub struct ClientCertResolver(CertStore, String);

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
            let (chain, signing_key) = get_chain(&self.0, &self.1).ok()?;
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

    pub fn run_client(port: u16) -> anyhow::Result<()> {
        let store = CertStore::from_pkcs12(super::CLIENT_PFX, super::PASSWORD)?;

        let ca_cert_context = store.find_by_subject_str(super::CA_SUBJECT)?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert.as_der().into())?;

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_cert_resolver(Arc::new(ClientCertResolver(
                store,
                "rustls-client".to_string(),
            )));

        let mut connection =
            ClientConnection::new(Arc::new(client_config), "rustls-server".try_into()?)?;

        let mut client = TcpStream::connect(format!("localhost:{}", port))?;

        let mut tls_stream = Stream::new(&mut connection, &mut client);
        tls_stream.write_all(b"ping")?;
        tls_stream.sock.shutdown(Shutdown::Write)?;

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"pong");

        tls_stream.sock.shutdown(Shutdown::Read)?;

        Ok(())
    }
}

mod server {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::{mpsc::Sender, Arc},
    };

    use rustls::{
        server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
        sign::CertifiedKey,
        RootCertStore, ServerConfig, ServerConnection, Stream,
    };

    use rustls_cng::{signer::CngSigningKey, store::CertStore};

    #[derive(Debug)]
    pub struct ServerCertResolver(CertStore);

    impl ResolvesServerCert for ServerCertResolver {
        fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
            let name = client_hello.server_name()?;

            let contexts = self.0.find_by_subject_str(name).ok()?;

            let (context, key) = contexts.into_iter().find_map(|ctx| {
                let key = ctx.acquire_key().ok()?;
                CngSigningKey::new(key).ok().map(|key| (ctx, key))
            })?;

            let chain = context.as_chain_der().ok()?;
            let certs = chain.into_iter().map(Into::into).collect();

            Some(Arc::new(CertifiedKey {
                cert: certs,
                key: Arc::new(key),
                ocsp: None,
            }))
        }
    }

    fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> anyhow::Result<()> {
        let mut connection = ServerConnection::new(config)?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"ping");
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
        tls_stream.sock.shutdown(Shutdown::Write)?;

        Ok(())
    }

    pub fn run_server(sender: Sender<u16>) -> anyhow::Result<()> {
        let store = CertStore::from_pkcs12(super::SERVER_PFX, super::PASSWORD)?;

        let ca_cert_context = store.find_by_subject_str(super::CA_SUBJECT)?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert.as_der().into())?;

        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .unwrap();

        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(ServerCertResolver(store)));

        let server = TcpListener::bind("127.0.0.1:0")?;

        let _ = sender.send(server.local_addr()?.port());

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

    if let Ok(port) = rx.recv() {
        client::run_client(port).unwrap();
    }
}
