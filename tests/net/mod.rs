//! Shared helpers for the TLS, HTTP client, Worker API and poller tests. Everything runs on 127.0.0.1 inside the test process: a test PKI
//! generated at test time with rcgen, one-shot raw HTTPS servers and a fake inbound Worker that
//! speaks contract v1 (or v0). Nothing touches the network or Cloudflare; the token is a dummy.
//!
//! The helpers build their rustls configs directly (not through `synology_mail_server::tls`), so
//! the HTTP/Worker/poller tests fail only on their own module.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use synology_mail_server::inbound::Clock;

pub type ServerStream = TlsStream<TcpStream>;

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// // Test PKI

/// A fresh test CA and one leaf certificate signed by it.
pub struct Pki {
    pub ca_der: CertificateDer<'static>,
    pub ca_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub cert_pem: String,
    pub key_der: Vec<u8>, // PKCS#8
    pub key_pem: String,
}

impl Pki {
    /// `names`: DNS names or IP literals for the leaf's subjectAltName.
    pub fn new(names: &[&str]) -> Pki {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "SSM test CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca =
            rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
                .unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params =
            rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, names[0]);
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &*ca).unwrap();

        Pki {
            ca_der: ca.der().clone(),
            ca_pem: ca.pem(),
            cert_der: leaf.der().clone(),
            cert_pem: leaf.pem(),
            key_der: leaf_key.serialize_der(),
            key_pem: leaf_key.serialize_pem(),
        }
    }

    /// The usual server identity for these tests: 127.0.0.1 (IP SAN) and localhost.
    pub fn local() -> Pki {
        Pki::new(&["127.0.0.1", "localhost"])
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}

/// Server config built directly with rustls (TLS 1.2 + 1.3, ring).
pub fn server_tls(pki: &Pki) -> Arc<rustls::ServerConfig> {
    server_tls_versions(pki, rustls::DEFAULT_VERSIONS)
}

pub fn server_tls_versions(
    pki: &Pki,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![pki.cert_der.clone()], pki.key())
            .unwrap(),
    )
}

/// Client config built directly with rustls that trusts only `pki`'s CA.
pub fn client_tls(pki: &Pki) -> Arc<rustls::ClientConfig> {
    client_tls_versions(pki, rustls::DEFAULT_VERSIONS)
}

pub fn client_tls_versions(
    pki: &Pki,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub fn base_url(addr: SocketAddr) -> String {
    format!("https://127.0.0.1:{}", addr.port())
}

// // One-shot raw HTTPS server

/// Read a request head (up to and including the blank line). Requests here never have a body.
pub async fn read_head(s: &mut ServerStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 128 * 1024 {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

pub struct Served {
    pub addr: SocketAddr,
    pub url: String,
    /// The raw request head the client sent (empty if the handshake failed).
    pub request: oneshot::Receiver<Vec<u8>>,
}

/// Accept ONE TLS connection with `tls`, read its request head, then hand the stream to `handler`.
pub async fn serve_one<F, Fut>(tls: Arc<rustls::ServerConfig>, handler: F) -> Served
where
    F: FnOnce(ServerStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        match TlsAcceptor::from(tls).accept(tcp).await {
            Ok(mut s) => {
                let head = read_head(&mut s).await;
                let _ = tx.send(head);
                handler(s).await;
            }
            Err(_) => {
                let _ = tx.send(Vec::new());
            }
        }
    });
    Served {
        addr,
        url: base_url(addr),
        request: rx,
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Close {
    /// TLS close_notify, then TCP close.
    Notify,
    /// TCP close without close_notify (a truncation attack looks like this).
    Abrupt,
    /// Keep the connection open (and silent) this long, then close_notify.
    KeepOpen(Duration),
}

/// One connection: write `response` verbatim, then close as `close` says.
pub async fn serve_raw(pki: &Pki, response: Vec<u8>, close: Close) -> Served {
    serve_one(server_tls(pki), move |mut s| async move {
        let _ = s.write_all(&response).await;
        let _ = s.flush().await;
        finish(s, close).await;
    })
    .await
}

pub async fn finish(mut s: ServerStream, close: Close) {
    match close {
        Close::Notify => {
            let _ = s.shutdown().await;
        }
        Close::Abrupt => {
            // Dropping the tokio-rustls stream closes TCP without sending close_notify.
            drop(s);
        }
        Close::KeepOpen(d) => {
            tokio::time::sleep(d).await;
            let _ = s.shutdown().await;
        }
    }
}

/// (method, path, headers) of a raw request head.
pub fn parse_request(head: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(head).expect("request head parses");
    assert!(
        status.is_complete(),
        "complete request head: {:?}",
        String::from_utf8_lossy(head)
    );
    let hs = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    (
        req.method.unwrap().to_string(),
        req.path.unwrap().to_string(),
        hs,
    )
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// // Percent-encoding as the Worker does it (JavaScript encodeURIComponent)

pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

// // Simulated clock for the poll loop

/// `sleep` advances simulated time at once. A sleep that would reach `limit` never returns and
/// signals `done`, so a test can stop `Poller::run` after N simulated hours.
pub struct SimClock {
    now: Mutex<Duration>,
    limit: Duration,
    pub done: Notify,
    pub sleeps: Mutex<Vec<Duration>>,
}

impl SimClock {
    pub fn new(limit: Duration) -> Arc<SimClock> {
        Arc::new(SimClock {
            now: Mutex::new(Duration::ZERO),
            limit,
            done: Notify::new(),
            sleeps: Mutex::new(Vec::new()),
        })
    }
}

impl Clock for SimClock {
    fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.sleeps.lock().unwrap().push(d);
        let mut now = self.now.lock().unwrap();
        let t = *now + d;
        if t >= self.limit {
            self.done.notify_one();
            return Box::pin(std::future::pending());
        }
        *now = t;
        Box::pin(tokio::task::yield_now())
    }
}

pub fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 3600)
}

pub fn mins(m: u64) -> Duration {
    Duration::from_secs(m * 60)
}

// // Fake inbound Worker (contract v1; v0 when `v0` is set)

pub const TOKEN: &str = "test-token-not-a-secret";

#[derive(Clone, Debug)]
pub struct StoredMsg {
    pub body: Vec<u8>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Value of X-SSM-Size; None = the real body length.
    pub size_header: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    /// Percent-decoded path.
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Simulated time (Duration::ZERO without a SimClock).
    pub at: Duration,
}

#[derive(Default)]
pub struct State {
    pub kv: BTreeMap<String, StoredMsg>,
    pub requests: Vec<Req>,
    /// Keys per list response (KV returns up to 1,000); None = all.
    pub page_size: Option<usize>,
    /// `complete:false` on every list.
    pub never_complete: bool,
    /// Deployed v0 Worker: `{"ids":[..]}` only, and no X-SSM-* headers on GET.
    pub v0: bool,
    /// List ids newest first (to check that the poller orders by key itself).
    pub reverse_list: bool,
    /// Force this status on GET /messages.
    pub list_status: Option<u16>,
    /// Answer 401 to everything while simulated time < this.
    pub unauthorized_until: Option<Duration>,
    /// Force a status on GET /messages/<key>.
    pub get_status: HashMap<String, u16>,
    /// Answer 500 to this many DELETEs of a key first (u32::MAX = always).
    pub delete_failures: HashMap<String, u32>,
    /// After a DELETE the key is still listed this many more times (KV list is eventually consistent).
    pub stale_lists_after_delete: u32,
    ghosts: BTreeMap<String, u32>,
}

pub struct FakeWorker {
    pub addr: SocketAddr,
    pub url: String,
    pub state: Arc<Mutex<State>>,
}

impl FakeWorker {
    pub async fn start(pki: &Pki, clock: Option<Arc<SimClock>>) -> FakeWorker {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let acceptor = TlsAcceptor::from(server_tls(pki));
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let st = st.clone();
                let clock = clock.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let head = read_head(&mut s).await;
                    if head.is_empty() {
                        return;
                    }
                    let now = clock.as_ref().map(|c| c.now()).unwrap_or(Duration::ZERO);
                    let response = handle(&st, &head, now);
                    let _ = s.write_all(&response).await;
                    let _ = s.flush().await;
                    let _ = s.shutdown().await;
                });
            }
        });
        FakeWorker {
            addr,
            url: base_url(addr),
            state,
        }
    }

    /// Store a message the way the v1 Worker's email() does (metadata from/to).
    pub fn put(&self, key: &str, from: &str, to: &str, body: &[u8]) {
        self.with(|s| {
            s.kv.insert(
                key.to_string(),
                StoredMsg {
                    body: body.to_vec(),
                    from: Some(from.to_string()),
                    to: Some(to.to_string()),
                    size_header: None,
                },
            )
        });
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn keys(&self) -> Vec<String> {
        self.with(|s| s.kv.keys().cloned().collect())
    }

    pub fn requests(&self) -> Vec<Req> {
        self.with(|s| s.requests.clone())
    }

    /// Requests with this method whose decoded path is exactly `path`.
    pub fn count(&self, method: &str, path: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method && r.path == path)
            .count()
    }

    pub fn lists(&self) -> Vec<Duration> {
        self.requests()
            .iter()
            .filter(|r| r.method == "GET" && r.path == "/messages")
            .map(|r| r.at)
            .collect()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn response(status: u16, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status)).into_bytes();
    for (n, v) in headers {
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    if status != 204 {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"connection: close\r\n\r\n");
    if status != 204 {
        out.extend_from_slice(body);
    }
    out
}

fn handle(st: &Mutex<State>, head: &[u8], now: Duration) -> Vec<u8> {
    let (method, raw_path, headers) = parse_request(head);
    let path = percent_decode(&raw_path);
    let mut s = st.lock().unwrap();
    s.requests.push(Req {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
        at: now,
    });

    let authorized = header(&headers, "authorization") == Some(&format!("Bearer {TOKEN}"));
    let locked = s.unauthorized_until.is_some_and(|until| now < until);
    if !authorized || locked {
        return response(
            401,
            &[("content-type", "text/plain".into())],
            b"unauthorized",
        );
    }

    if path == "/messages" && method == "GET" {
        if let Some(code) = s.list_status {
            return response(code, &[("content-type", "text/plain".into())], b"error");
        }
        let mut ids: Vec<String> = s.kv.keys().cloned().collect();
        let ghosts: Vec<String> = s
            .ghosts
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(k, _)| k.clone())
            .collect();
        for g in ghosts {
            *s.ghosts.get_mut(&g).unwrap() -= 1;
            if !ids.contains(&g) {
                ids.push(g);
            }
        }
        ids.sort();
        if s.reverse_list {
            ids.reverse();
        }
        let total = ids.len();
        if let Some(n) = s.page_size {
            ids.truncate(n);
        }
        let complete = !s.never_complete && ids.len() == total;
        let json = if s.v0 {
            serde_json::json!({ "ids": ids })
        } else {
            serde_json::json!({ "ids": ids, "complete": complete })
        };
        return response(
            200,
            &[("content-type", "application/json".into())],
            json.to_string().as_bytes(),
        );
    }

    if let Some(id) = path.strip_prefix("/messages/") {
        let id = id.to_string();
        if method == "GET" {
            if let Some(code) = s.get_status.get(&id) {
                return response(*code, &[("content-type", "text/plain".into())], b"error");
            }
            let Some(m) = s.kv.get(&id) else {
                return response(404, &[("content-type", "text/plain".into())], b"not found");
            };
            let mut hs = vec![("content-type", "message/rfc822".to_string())];
            if !s.v0 {
                hs.push((
                    "x-ssm-size",
                    m.size_header
                        .clone()
                        .unwrap_or_else(|| m.body.len().to_string()),
                ));
                if let Some(to) = &m.to {
                    hs.push(("x-ssm-envelope-to", encode_uri_component(to)));
                }
                if let Some(from) = &m.from {
                    hs.push(("x-ssm-envelope-from", encode_uri_component(from)));
                }
            }
            return response(200, &hs, &m.body.clone());
        }
        if method == "DELETE" {
            if let Some(n) = s.delete_failures.get_mut(&id)
                && *n > 0
            {
                if *n != u32::MAX {
                    *n -= 1;
                }
                return response(500, &[("content-type", "text/plain".into())], b"kv error");
            }
            if s.kv.remove(&id).is_some() && s.stale_lists_after_delete > 0 {
                let n = s.stale_lists_after_delete;
                s.ghosts.insert(id, n);
            }
            return response(204, &[], b"");
        }
    }
    response(404, &[("content-type", "text/plain".into())], b"not found")
}
