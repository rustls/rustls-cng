use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use rustls_cng::{
    config::{CngCredentials, WithClientCngCredentials},
    store::{CertStore, CertStoreType},
};
use rustls_util::StreamOwned;

const PORT: u16 = 8000;

fn get_credentials(name: &str) -> Result<CngCredentials, Box<dyn std::error::Error>> {
    let store = CertStore::open(CertStoreType::CurrentUser, "my")?;
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts
        .first()
        .ok_or_else(|| std::io::Error::other("No client cert"))?;
    let key = context.acquire_key(false)?;
    let chain = context.as_chain_der()?.into_iter().map(Into::into).collect();
    Ok(CngCredentials { key, chain })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        println!("Usage: {} <sni-name> [client-cert-name]", args[0]);
        return Ok(());
    }

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

    let builder =
        ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER)).with_root_certificates(root_store);

    let client_config = Arc::new(if let Some(client_cert) = args.get(2) {
        let credentials = get_credentials(client_cert)?;
        builder.with_client_cng_credentials(credentials)?
    } else {
        builder.with_no_client_auth()?
    });

    let server_name = ServerName::try_from(args[1].as_str())?.to_owned();

    let mut client_output = Vec::new();
    let connection = client_config.connect(server_name).build(&mut client_output)?;
    let client = TcpStream::connect(format!("127.0.0.1:{}", PORT))?;

    let mut tls_stream = StreamOwned::new(connection, client, client_output);

    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut buf = [0u8; 4];
    tls_stream.read_exact(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    tls_stream.sock.shutdown(Shutdown::Read)?;

    Ok(())
}
