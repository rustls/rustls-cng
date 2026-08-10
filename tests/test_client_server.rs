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

    use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
    use rustls_cng::{
        config::{CngCredentials, WithClientCngCredentials},
        key::NCryptKey,
        store::{CertStore, Pkcs12Flags},
    };
    use rustls_util::StreamOwned;

    fn get_chain(
        store: &CertStore,
        name: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, NCryptKey), Box<dyn std::error::Error>> {
        let contexts = store.find_by_subject_str(name)?;
        let context = contexts
            .first()
            .ok_or_else(|| std::io::Error::other("No client cert"))?;
        let key = context.acquire_key(true)?;
        let chain = context.as_chain_der()?.into_iter().map(Into::into).collect();
        Ok((chain, key))
    }

    pub fn run_client(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let store = CertStore::from_pkcs12(super::CLIENT_PFX, super::PASSWORD, Pkcs12Flags::default())?;

        let ca_cert_context = store.find_by_subject_str(super::CA_SUBJECT)?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert.as_der().into())?;

        let (certs, key) = get_chain(&store, "rustls-client")?;
        let credentials = CngCredentials { key, chain: certs };

        let client_config = Arc::new(
            ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
                .with_root_certificates(root_store)
                .with_client_cng_credentials(credentials)?,
        );

        let mut client_output = Vec::new();

        let connection = client_config
            .connect("rustls-server".try_into()?)
            .build(&mut client_output)?;

        let client = TcpStream::connect(format!("localhost:{port}"))?;

        let mut tls_stream = StreamOwned::new(connection, client, client_output);

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
        RootCertStore, ServerConfig, ServerConnection,
        server::{ClientHello, WebPkiClientVerifier},
    };
    use rustls_cng::{
        config::{CngCredentials, WithServerCngCredentials},
        store::{CertStore, Pkcs12Flags},
    };
    use rustls_util::StreamOwned;

    fn resolve(store: &CertStore, client_hello: &ClientHello) -> Result<CngCredentials, rustls::Error> {
        let name = client_hello
            .server_name()
            .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

        let contexts = store
            .find_by_subject_str(name)
            .map_err(|_| rustls::Error::NoSuitableCertificate)?;

        let (context, key) = contexts
            .into_iter()
            .find_map(|ctx| ctx.acquire_key(true).ok().map(|key| (ctx, key)))
            .ok_or_else(|| rustls::Error::NoSuitableCertificate)?;

        let chain = context
            .as_chain_der()
            .map_err(|_| rustls::Error::NoSuitableCertificate)?;
        let certs = chain.into_iter().map(Into::into).collect();

        Ok(CngCredentials { key, chain: certs })
    }

    fn handle_connection(stream: TcpStream, config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
        let connection = ServerConnection::new(config)?;
        let mut tls_stream = StreamOwned::new(connection, stream, Vec::new());

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf)?;

        assert_eq!(&buf, b"ping");

        tls_stream.sock.shutdown(Shutdown::Read)?;

        tls_stream.write_all(b"pong")?;

        tls_stream.sock.shutdown(Shutdown::Write)?;

        Ok(())
    }

    pub fn run_server(sender: Sender<u16>) -> Result<(), Box<dyn std::error::Error>> {
        let store = CertStore::from_pkcs12(super::SERVER_PFX, super::PASSWORD, Pkcs12Flags::default())?;

        let ca_cert_context = store.find_by_subject_str(super::CA_SUBJECT)?;
        let ca_cert = ca_cert_context.first().unwrap();

        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert.as_der().into())?;

        let verifier =
            WebPkiClientVerifier::builder(Arc::new(root_store), &rustls_aws_lc_rs::DEFAULT_PROVIDER).build()?;

        let server_config = ServerConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
            .with_client_cert_verifier(Arc::new(verifier))
            .with_server_cng_credentials(move |hello| resolve(&store, hello))?;

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
        server::run_server(tx).expect("server test failed");
    });

    if let Ok(port) = rx.recv() {
        client::run_client(port).expect("client test failed");
    }
}
