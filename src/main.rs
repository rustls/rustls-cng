use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection, Stream};

use crate::resolver::ServerCertResolver;

pub mod key;
pub mod resolver;

const PORT: u16 = 8000;

fn accept(
    server: TcpListener,
    mut connection: ServerConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut stream = stream?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);
        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ServerCertResolver));

    let connection = ServerConnection::new(Arc::new(server_config))?;
    let server = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;

    accept(server, connection)?;

    Ok(())
}
