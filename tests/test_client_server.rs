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
        ClientConfig, ClientConnection, RootCertStore, Stream,
        client::{ClientCredentialResolver, CredentialRequest},
        crypto::{Credentials, Identity, SelectedCredential, aws_lc_rs},
        enums::CertificateType,
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
        let key = context.acquire_key(true)?;
        let signing_key = CngSigningKey::new(key)?;
        let chain = context
            .as_chain_der()?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok((chain, signing_key))
    }

    impl ClientCredentialResolver for ClientCertResolver {
        fn resolve(&self, server_hello: &CredentialRequest) -> Option<SelectedCredential> {
            let (chain, signing_key) = get_chain(&self.0, &self.1).ok()?;
            Credentials::new_unchecked(
                Arc::new(Identity::from_cert_chain(chain).ok()?),
                Box::new(signing_key),
            )
            .signer(server_hello.signature_schemes())
        }

        fn supported_certificate_types(&self) -> &'static [CertificateType] {
            &[CertificateType::X509]
        }
    }

    pub fn run_client(port: u16) -> anyhow::Result<()> {
        let store = CertStore::from_pkcs12(super::CLIENT_PFX, super::PASSWORD)?;

        let ca_cert_context = store.find_by_subject_str(super::CA_SUBJECT)?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert.as_der().into())?;

        let client_config = ClientConfig::builder(Arc::new(aws_lc_rs::DEFAULT_PROVIDER))
            .with_root_certificates(root_store)
            .with_client_credential_resolver(Arc::new(ClientCertResolver(
                store,
                "rustls-client".to_string(),
            )))?;

        let mut connection =
            ClientConnection::new(Arc::new(client_config), "rustls-server".try_into()?)?;

        let mut client = TcpStream::connect(format!("localhost:{port}"))?;

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
        sync::{Arc, mpsc::Sender},
    };

    use rustls::{
        RootCertStore, ServerConfig, ServerConnection, Stream,
        crypto::{Credentials, Identity, SelectedCredential, aws_lc_rs},
        server::{ClientHello, ServerCredentialResolver, WebPkiClientVerifier},
    };
    use rustls_cng::{signer::CngSigningKey, store::CertStore};

    #[derive(Debug)]
    pub struct ServerCertResolver(CertStore);

    impl ServerCredentialResolver for ServerCertResolver {
        fn resolve(&self, client_hello: &ClientHello) -> Result<SelectedCredential, rustls::Error> {
            let name = client_hello
                .server_name()
                .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

            let contexts = self
                .0
                .find_by_subject_str(name)
                .map_err(|_| rustls::Error::NoSuitableCertificate)?;

            let (context, key) = contexts
                .into_iter()
                .find_map(|ctx| {
                    let key = ctx.acquire_key(true).ok()?;
                    CngSigningKey::new(key).ok().map(|key| (ctx, key))
                })
                .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

            let chain = context
                .as_chain_der()
                .map_err(|_| rustls::Error::NoSuitableCertificate)?;
            let certs = chain.into_iter().map(Into::into).collect();

            Credentials::new_unchecked(Arc::new(Identity::from_cert_chain(certs)?), Box::new(key))
                .signer(client_hello.signature_schemes())
                .ok_or_else(|| rustls::Error::General("No common schemes".to_owned()))
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

        let verifier =
            WebPkiClientVerifier::builder(Arc::new(root_store), &aws_lc_rs::DEFAULT_PROVIDER)
                .build()?;

        let server_config = ServerConfig::builder(Arc::new(aws_lc_rs::DEFAULT_PROVIDER))
            .with_client_cert_verifier(verifier)
            .with_server_credential_resolver(Arc::new(ServerCertResolver(store)))?;

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
