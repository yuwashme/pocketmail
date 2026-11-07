//! tls.rs: rustls config builders.
//! Certificates come from a test CA generated at test time; nothing leaves 127.0.0.1.

mod net;
use net::*;

use std::sync::Arc;

use rustls::pki_types::ServerName;
use synology_mail_server::tls::{self, TlsError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Handshake `client` against `server` on 127.0.0.1 as `name`, exchange one line both ways.
/// Returns the negotiated protocol version, or the client-side error.
async fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> Result<rustls::ProtocolVersion, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if let Ok(mut s) = tokio_rustls::TlsAcceptor::from(server).accept(tcp).await {
            let mut b = [0u8; 5];
            if s.read_exact(&mut b).await.is_ok() {
                let _ = s.write_all(b"pong\n").await;
                let _ = s.shutdown().await;
            }
        }
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(name.to_string()).unwrap();
    let mut s = tokio_rustls::TlsConnector::from(client).connect(name, tcp).await?;
    s.write_all(b"ping\n").await?;
    let mut b = Vec::new();
    s.read_to_end(&mut b).await?;
    assert_eq!(b, b"pong\n");
    Ok(s.get_ref().1.protocol_version().unwrap())
}

#[tokio::test]
async fn server_config_from_pem_serves_tls13_to_a_client_trusting_the_ca() {
    let pki = Pki::local();
    let server = tls::server_config(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    let v = handshake(server, client_tls(&pki), "127.0.0.1").await.unwrap();
    assert_eq!(v, rustls::ProtocolVersion::TLSv1_3);
}

#[tokio::test]
async fn server_config_still_accepts_tls12_clients() {
    // Keep tls12 for Outlook / Windows 10 IMAP clients.
    let pki = Pki::local();
    let server = tls::server_config(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    let v = handshake(server, client_tls_versions(&pki, &[&rustls::version::TLS12]), "localhost").await.unwrap();
    assert_eq!(v, rustls::ProtocolVersion::TLSv1_2);
}

#[tokio::test]
async fn server_config_from_files_reads_the_pem_files() {
    let pki = Pki::local();
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    // A chain file (leaf first, then the CA) must work too: DSM exports chains like this.
    std::fs::write(&cert, format!("{}{}", pki.cert_pem, pki.ca_pem)).unwrap();
    std::fs::write(&key, &pki.key_pem).unwrap();
    let server = tls::server_config_from_files(&cert, &key).unwrap();
    handshake(server, client_tls(&pki), "127.0.0.1").await.unwrap();
}

#[test]
fn server_config_errors_are_specific() {
    let pki = Pki::local();
    let other = Pki::local();
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&key, &pki.key_pem).unwrap();

    assert!(matches!(tls::server_config_from_files(&missing, &key), Err(TlsError::Io(_))));
    // A key where the certificate should be, and a certificate where the key should be.
    assert!(matches!(tls::server_config(pki.key_pem.as_bytes(), pki.key_pem.as_bytes()), Err(TlsError::NoCertificate)));
    assert!(matches!(tls::server_config(pki.cert_pem.as_bytes(), pki.cert_pem.as_bytes()), Err(TlsError::NoPrivateKey)));
    assert!(matches!(tls::server_config(b"", pki.key_pem.as_bytes()), Err(TlsError::NoCertificate)));
    // Certificate and key from different key pairs: refused at startup, not at the first handshake.
    assert!(tls::server_config(pki.cert_pem.as_bytes(), other.key_pem.as_bytes()).is_err());
}

#[tokio::test]
async fn client_config_with_roots_verifies_chain_and_host_name() {
    let pki = Pki::new(&["worker.example"]);
    let client = tls::client_config_with_roots(vec![pki.ca_der.clone()]).unwrap();
    handshake(server_tls(&pki), client.clone(), "worker.example").await.unwrap();
    // Same trusted chain, wrong name.
    assert!(handshake(server_tls(&pki), client, "other.example").await.is_err());
    // Name right, but signed by a CA the client does not trust.
    let stranger = Pki::new(&["worker.example"]);
    let client = tls::client_config_with_roots(vec![stranger.ca_der.clone()]).unwrap();
    assert!(handshake(server_tls(&pki), client, "worker.example").await.is_err());
}

#[tokio::test]
async fn client_config_speaks_tls12_and_tls13() {
    let pki = Pki::local();
    let client = tls::client_config_with_roots(vec![pki.ca_der.clone()]).unwrap();
    let v12 = handshake(server_tls_versions(&pki, &[&rustls::version::TLS12]), client.clone(), "127.0.0.1").await.unwrap();
    let v13 = handshake(server_tls_versions(&pki, &[&rustls::version::TLS13]), client, "127.0.0.1").await.unwrap();
    assert_eq!((v12, v13), (rustls::ProtocolVersion::TLSv1_2, rustls::ProtocolVersion::TLSv1_3));
}

#[tokio::test]
async fn default_client_config_uses_public_roots_only() {
    // webpki-roots (Mozilla) must not trust a private test CA; the Worker's real cert is public.
    let pki = Pki::local();
    let err = handshake(server_tls(&pki), tls::client_config(), "127.0.0.1").await;
    assert!(err.is_err(), "a self-made CA must not be trusted by the production client config");
}
