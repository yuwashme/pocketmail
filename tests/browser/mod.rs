//! Harness for the settings web server tests. A real `web::WebServer` and `imap::ImapServer` run
//! in-process on 127.0.0.1, sharing one store (tempdir), one TLS config (test certificate from
//! `net::Pki::local`) and one `ManualClock`. The client below is deliberately small: it writes
//! raw request bytes (the tests send Host themselves) and reads Content-Length framed responses.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;

use synology_mail_server::imap::{ImapServer, ServerConfig};
use synology_mail_server::store::Store;
use synology_mail_server::web::{WebConfig, WebServer};

use crate::harness::{ManualClock, TIMEOUT};
use crate::net::{Pki, client_tls};

pub const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
pub const CSS_CACHE: &str = "max-age=31536000, immutable";
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(10);
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
pub const FORM: &str = "application/x-www-form-urlencoded";

/// The stylesheet's path for this build.
pub fn css_path() -> String {
    format!("/style-{}.css", env!("CARGO_PKG_VERSION"))
}

/// The stylesheet as it is in the source tree.
pub fn css_source() -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/style.css")).expect("src/web/style.css")
}

pub struct WebHarness {
    pub tmp: tempfile::TempDir,
    pub store: Arc<Store>,
    pub clock: Arc<ManualClock>,
    pub pki: Pki,
    pub tls: Arc<rustls::ServerConfig>,
    pub addr: SocketAddr,
    pub imap_addr: SocketAddr,
    pub server: WebServer,
    pub imap: ImapServer,
}

impl WebHarness {
    pub async fn start() -> WebHarness {
        WebHarness::start_with(|_| {}).await
    }

    /// `WebConfig::new` (the design's defaults), then `tweak`.
    pub async fn start_with(tweak: impl FnOnce(&mut WebConfig)) -> WebHarness {
        WebHarness::start_seeded(|_| {}, tweak).await
    }

    /// `start_with`, with `seed` run on the store before the web server starts.
    pub async fn start_seeded(seed: impl FnOnce(&Store), tweak: impl FnOnce(&mut WebConfig)) -> WebHarness {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&tmp.path().join("data")).unwrap());
        seed(&store);
        let pki = Pki::local();
        let tls = synology_mail_server::tls::server_config(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
        let clock = ManualClock::new();

        let mut config = WebConfig::new(tls.clone());
        tweak(&mut config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = WebServer::start(listener, store.clone(), config, clock.clone()).unwrap();

        let imap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let imap = ImapServer::start(imap_listener, store.clone(), ServerConfig::new(tls.clone()), clock.clone()).unwrap();

        let (addr, imap_addr) = (server.local_addr(), imap.local_addr());
        WebHarness { tmp, store, clock, pki, tls, addr, imap_addr, server, imap }
    }

    pub fn host(&self) -> String {
        format!("localhost:{}", self.addr.port())
    }

    /// A TLS connection (TLS 1.3, no ALPN).
    pub async fn open(&self) -> Web {
        Web::open(self.addr, client_tls(&self.pki)).await.expect("TLS handshake with the web server")
    }

    /// `GET <path>` with Host on a fresh connection; the response.
    pub async fn get(&self, path: &str) -> Resp {
        let mut w = self.open().await;
        w.get(&self.host(), path).await
    }

    /// Raw request bytes on a fresh connection; the first response, if any.
    pub async fn raw(&self, bytes: &[u8]) -> (Web, Option<Resp>) {
        let mut w = self.open().await;
        let _ = w.try_write(bytes).await;
        let r = w.read_response(false).await;
        (w, r)
    }
}

/// `METHOD path HTTP/1.1`, Host, the extra header lines, a blank line, then `body`.
pub fn request(method: &str, path: &str, host: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// A POST with Content-Type and Content-Length set for `body`.
pub fn post(path: &str, host: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let ct = format!("Content-Type: {content_type}");
    let cl = format!("Content-Length: {}", body.len());
    request("POST", path, host, &[&ct, &cl], body)
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }

    /// The response says the server closes after it (`Connection: close`).
    pub fn closes(&self) -> bool {
        self.all("connection").iter().any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub struct Web {
    s: TlsStream<TcpStream>,
    buf: Vec<u8>,
}

impl Web {
    pub async fn open(addr: SocketAddr, tls: Arc<rustls::ClientConfig>) -> std::io::Result<Web> {
        let tcp = TcpStream::connect(addr).await?;
        let name = ServerName::try_from("localhost").unwrap();
        let s = tokio::time::timeout(TIMEOUT, tokio_rustls::TlsConnector::from(tls).connect(name, tcp))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
        Ok(Web { s, buf: Vec::new() })
    }

    pub fn tls_version(&self) -> Option<rustls::ProtocolVersion> {
        self.s.get_ref().1.protocol_version()
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.s.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
    }

    pub fn peer_certificate(&self) -> Option<CertificateDer<'static>> {
        self.s.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.clone().into_owned())
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        self.try_write(bytes).await.expect("write to the web server");
    }

    pub async fn try_write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.s.write_all(bytes).await?;
        self.s.flush().await
    }

    /// TLS close_notify and TCP write shutdown; the read side stays open.
    pub async fn shutdown(&mut self) {
        let _ = self.s.shutdown().await;
    }

    /// Send `GET path` and read its response.
    pub async fn get(&mut self, host: &str, path: &str) -> Resp {
        self.write(&request("GET", path, host, &[], b"")).await;
        self.read_response(false).await.unwrap_or_else(|| panic!("no response to GET {path}"))
    }

    /// Ok(false) on EOF or a transport error; panics when nothing arrives within TIMEOUT.
    async fn fill(&mut self) -> bool {
        let mut chunk = vec![0u8; 16 * 1024];
        match tokio::time::timeout(TIMEOUT, self.s.read(&mut chunk)).await {
            Err(_) => panic!("nothing from the web server within {TIMEOUT:?} (buffered: {:?})", String::from_utf8_lossy(&self.buf)),
            Ok(Ok(0)) | Ok(Err(_)) => false,
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
        }
    }

    /// One response; None if the connection closes first. `head_request`: the request was HEAD,
    /// so Content-Length describes a body that is not sent.
    pub async fn read_response(&mut self, head_request: bool) -> Option<Resp> {
        let end = loop {
            if let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            if !self.fill().await {
                assert!(self.buf.is_empty(), "connection closed inside a response head: {:?}", String::from_utf8_lossy(&self.buf));
                return None;
            }
        };
        let mut hs = [httparse::EMPTY_HEADER; 64];
        let mut r = httparse::Response::new(&mut hs);
        let parsed = r.parse(&self.buf[..end]).unwrap_or_else(|e| panic!("bad response head ({e}): {:?}", String::from_utf8_lossy(&self.buf[..end])));
        assert!(parsed.is_complete());
        assert_eq!(r.version, Some(1), "responses are HTTP/1.1");
        let status = r.code.unwrap();
        let headers: Vec<(String, String)> =
            r.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect();
        let lengths: Vec<&str> = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.as_str()).collect();
        assert_eq!(lengths.len(), 1, "every response carries exactly one Content-Length: {headers:?}");
        let len: usize = lengths[0].trim().parse().expect("numeric Content-Length");
        self.buf.drain(..end);
        let body = if head_request {
            Vec::new()
        } else {
            while self.buf.len() < len {
                assert!(self.fill().await, "connection closed inside a {len}-byte body");
            }
            self.buf.drain(..len).collect()
        };
        Some(Resp { status, headers, body })
    }

    /// Read until the server closes; returns whatever came. Panics if it stays open past TIMEOUT.
    pub async fn expect_closed(&mut self) -> Vec<u8> {
        while self.fill().await {}
        std::mem::take(&mut self.buf)
    }

    /// True when nothing arrives (and the connection stays open) for `d` of real time.
    pub async fn nothing_within(&mut self, d: Duration) -> bool {
        if !self.buf.is_empty() {
            return false;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(d, self.s.read(&mut chunk)).await {
            Err(_) => true,
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                false
            }
            Ok(Err(_)) => false,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sessions, logins and pages

pub const COOKIE: &str = "__Host-ssm_session";
pub const CSRF_FIELD: &str = "csrf";
pub const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
pub const SESSION_MAX: Duration = Duration::from_secs(12 * 3600);
pub const LOCK_WINDOW: Duration = Duration::from_secs(15 * 60);

impl WebHarness {
    pub fn origin(&self) -> String {
        format!("https://{}", self.host())
    }

    pub fn browser(&self) -> Browser<'_> {
        Browser::new(self)
    }

    /// Account `login` with password `harness::password(login)` and the address `login`.
    pub fn user(&self, login: &str) {
        self.store.create_account(login, &crate::harness::password(login)).unwrap();
        self.store.add_address(login, login).unwrap();
    }

    /// Names of the user name and password inputs of the sign-in form on GET /login.
    pub async fn login_fields(&self) -> (String, String) {
        let r = self.get("/login").await;
        assert_eq!(r.status, 200, "GET /login: {}", r.text());
        login_fields(&r.text())
    }
}

/// A browser on the home network: one cookie, Host and (on POST) Origin sent as a browser
/// would, the CSRF token of the last page that had one added to its forms. One connection per
/// request (`Connection: close`), so moving the clock never leaves a stale keep-alive behind.
/// A failed password check holds the answer until the clock moves 2 s: `send` moves it when the
/// server arms that sleep and records it in `delayed`.
pub struct Browser<'h> {
    pub h: &'h WebHarness,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    /// Sent with every POST; None sends no Origin.
    pub origin: Option<String>,
    /// The last answer came only after the clock moved `AUTH_DELAY`.
    pub delayed: bool,
}

impl<'h> Browser<'h> {
    pub fn new(h: &'h WebHarness) -> Browser<'h> {
        Browser { h, cookie: None, csrf: None, origin: Some(h.origin()), delayed: false }
    }

    pub fn forget(&mut self) {
        self.cookie = None;
        self.csrf = None;
    }

    /// The bytes this browser sends: Host, `Connection: close`, its cookie, and with a form body
    /// its Origin and the form headers.
    pub fn request(&self, method: &str, path: &str, form: Option<&str>) -> Vec<u8> {
        let mut headers = vec!["Connection: close".to_string()];
        if let Some(c) = &self.cookie {
            headers.push(format!("Cookie: {COOKIE}={c}"));
        }
        if let Some(body) = form {
            if let Some(o) = &self.origin {
                headers.push(format!("Origin: {o}"));
            }
            headers.push(format!("Content-Type: {FORM}"));
            headers.push(format!("Content-Length: {}", body.len()));
        }
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        request(method, path, &self.h.host(), &refs, form.unwrap_or_default().as_bytes())
    }

    /// Send `bytes` on a fresh connection and read the answer, moving the clock past a failed
    /// password check's delay. The cookie and CSRF token are taken from the answer.
    pub async fn send(&mut self, bytes: &[u8]) -> Resp {
        let mark = self.h.clock.mark();
        let mut w = self.h.open().await;
        w.write(bytes).await;
        let (r, delayed) = advancing_auth_delay(&self.h.clock, mark, w.read_response(false)).await;
        let r = r.unwrap_or_else(|| panic!("no answer to {:?}", String::from_utf8_lossy(bytes)));
        self.delayed = delayed;
        self.absorb(&r);
        r
    }

    pub fn absorb(&mut self, r: &Resp) {
        for c in r.all("set-cookie").into_iter().map(SetCookie::parse) {
            if c.name == COOKIE {
                self.cookie = (!c.clears()).then(|| c.value.clone());
            }
        }
        if let Some(t) = csrf_token(&r.text()) {
            self.csrf = Some(t);
        }
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        let bytes = self.request("GET", path, None);
        self.send(&bytes).await
    }

    /// POST `form`, plus the CSRF token of the last page unless `form` has one.
    pub async fn post(&mut self, path: &str, form: &[(&str, &str)]) -> Resp {
        let mut form = form.to_vec();
        let token = self.csrf.clone();
        if let Some(t) = &token
            && !form.iter().any(|(k, _)| *k == CSRF_FIELD)
        {
            form.push((CSRF_FIELD, t));
        }
        self.post_exact(path, &form).await
    }

    /// POST exactly `form`.
    pub async fn post_exact(&mut self, path: &str, form: &[(&str, &str)]) -> Resp {
        let bytes = self.request("POST", path, Some(&form_body(form)));
        self.send(&bytes).await
    }

    pub async fn raw(&mut self, bytes: &[u8]) -> Resp {
        self.send(bytes).await
    }

    /// Follow redirects (GET) until a non-redirect answer.
    pub async fn follow(&mut self, mut r: Resp) -> Resp {
        for _ in 0..5 {
            if !matches!(r.status, 301 | 302 | 303 | 307 | 308) {
                return r;
            }
            let to = location(&r);
            r = self.get(&to).await;
        }
        panic!("more than 5 redirects, last to {:?}", r.header("location"));
    }

    /// Sign in through the form on /login.
    pub async fn sign_in(&mut self, login: &str, password: &str) -> Resp {
        let (user, pw) = self.h.login_fields().await;
        self.csrf = None;
        self.post_exact("/login", &[(&user, login), (&pw, password)]).await
    }

    /// Change the own password through the form on /me.
    pub async fn change_password(&mut self, current: &str, new: &str, again: &str) -> Resp {
        let page = self.get("/me").await;
        assert_eq!(page.status, 200, "GET /me before changing the password: {} {:?}", page.status, page.header("location"));
        let (c, n, a) = password_fields(&page.text());
        self.post("/me/password", &[(&c, current), (&n, new), (&a, again)]).await
    }

    /// IMAP LOGIN with `login` and `password` (literals); true on OK.
    pub async fn imap_login(&self, login: &str, password: &str) -> bool {
        use crate::harness::{Client, Part};
        let mut c = Client::open(self.h.imap_addr, &self.h.pki).await.expect("TLS to IMAP");
        let g = c.read_response().await.expect("IMAP greeting");
        assert!(g.starts_with(b"* OK"), "IMAP greeting: {}", String::from_utf8_lossy(&g));
        let mark = self.h.clock.mark();
        let parts = [Part::Text("LOGIN "), Part::Lit(login.as_bytes()), Part::Text(" "), Part::Lit(password.as_bytes())];
        let (d, _) = advancing_auth_delay(&self.h.clock, mark, c.cmd_parts("L1", &parts)).await;
        d.status() == "OK"
    }
}

/// Await `answer`; if meanwhile a sleep of `AUTH_DELAY` is armed on the clock (after `mark`),
/// move the clock by it. Returns the answer and whether the clock was moved.
pub async fn advancing_auth_delay<T>(clock: &ManualClock, mark: u64, answer: impl std::future::Future<Output = T>) -> (T, bool) {
    let moved = std::cell::Cell::new(false);
    let mover = async {
        loop {
            if !moved.get() && clock.has_sleep_since(mark, crate::harness::AUTH_DELAY) {
                moved.set(true);
                clock.advance(crate::harness::AUTH_DELAY);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! {
        t = answer => (t, moved.get()),
        _ = mover => unreachable!(),
    }
}

/// Wait (real time) until no server timer is pending: sessions and limits expire lazily.
pub async fn no_timers_left(clock: &ManualClock, what: &str) {
    let start = std::time::Instant::now();
    while !clock.pending().is_empty() {
        assert!(start.elapsed() < TIMEOUT, "{what}: timers still pending: {:?}", clock.pending());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub fn form_body(form: &[(&str, &str)]) -> String {
    form.iter()
        .map(|(k, v)| format!("{}={}", crate::net::encode_uri_component(k), crate::net::encode_uri_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The Location header; panics without one.
pub fn location(r: &Resp) -> String {
    r.header("location").unwrap_or_else(|| panic!("{} without Location: {:?}", r.status, r.headers)).to_string()
}

/// The Location's path, without the query.
pub fn location_path(r: &Resp) -> String {
    location(r).split('?').next().unwrap_or_default().to_string()
}

/// 303 to the sign-in page.
#[track_caller]
pub fn assert_to_login(r: &Resp, what: &str) {
    assert_eq!(r.status, 303, "{what}: 303 to /login, got {} {:?} {}", r.status, r.header("location"), r.text());
    assert_eq!(location_path(r), "/login", "{what}");
}

/// No session cookie is set (a clearing one is allowed).
#[track_caller]
pub fn assert_no_session_cookie(r: &Resp, what: &str) {
    for c in r.all("set-cookie").into_iter().map(SetCookie::parse) {
        assert!(c.name != COOKIE || c.clears(), "{what}: no session cookie, got {c:?}");
    }
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    /// Lower-cased attribute names with their values ("" for flags).
    pub attrs: Vec<(String, String)>,
}

impl SetCookie {
    pub fn parse(v: &str) -> SetCookie {
        let mut parts = v.split(';');
        let (name, value) = parts.next().unwrap_or_default().split_once('=').unwrap_or((v, ""));
        let attrs = parts
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
                None => (p.trim().to_ascii_lowercase(), String::new()),
            })
            .collect();
        SetCookie { name: name.trim().to_string(), value: value.trim().to_string(), attrs }
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.attr(name).is_some()
    }

    /// Tells the browser to drop the cookie.
    pub fn clears(&self) -> bool {
        self.value.is_empty() || self.attr("max-age") == Some("0") || self.has("expires")
    }
}

// ---- a small HTML reader for the pages (double-quoted attributes) ----

#[derive(Debug, Clone)]
pub struct Tag {
    pub name: String,
    /// Lower-cased names; values with entities decoded ("" for a bare attribute).
    pub attrs: Vec<(String, String)>,
    /// Byte offsets of `<` and just past `>`.
    pub start: usize,
    pub end: usize,
}

impl Tag {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.attr(name).is_some()
    }
}

/// Every start tag in `html`, in order.
pub fn all_tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = html[i..].find('<') {
        let start = i + p;
        let mut j = start + 1;
        if !b.get(j).is_some_and(u8::is_ascii_alphabetic) {
            i = j;
            continue;
        }
        while b.get(j).is_some_and(|c| c.is_ascii_alphanumeric()) {
            j += 1;
        }
        let name = html[start + 1..j].to_ascii_lowercase();
        let mut attrs = Vec::new();
        loop {
            while b.get(j).is_some_and(u8::is_ascii_whitespace) {
                j += 1;
            }
            match b.get(j) {
                None => break,
                Some(b'>') => {
                    j += 1;
                    break;
                }
                Some(b'/') => {
                    j += 1;
                    continue;
                }
                _ => {}
            }
            let k0 = j;
            while b.get(j).is_some_and(|&c| !c.is_ascii_whitespace() && c != b'=' && c != b'>' && c != b'/') {
                j += 1;
            }
            let key = html[k0..j].to_ascii_lowercase();
            let mut value = String::new();
            if b.get(j) == Some(&b'=') {
                j += 1;
                match b.get(j) {
                    Some(&q) if q == b'"' || q == b'\'' => {
                        let v0 = j + 1;
                        let v1 = html[v0..].find(q as char).map_or(html.len(), |e| v0 + e);
                        value = unescape(&html[v0..v1]);
                        j = (v1 + 1).min(html.len());
                    }
                    _ => {
                        let v0 = j;
                        while b.get(j).is_some_and(|&c| !c.is_ascii_whitespace() && c != b'>') {
                            j += 1;
                        }
                        value = unescape(&html[v0..j]);
                    }
                }
            }
            if key.is_empty() {
                j += 1;
                continue;
            }
            attrs.push((key, value));
        }
        out.push(Tag { name, attrs, start, end: j });
        i = j.max(start + 1);
    }
    out
}

pub fn tags(html: &str, name: &str) -> Vec<Tag> {
    all_tags(html).into_iter().filter(|t| t.name == name).collect()
}

/// Each form with the inputs inside it.
pub fn forms(html: &str) -> Vec<(Tag, Vec<Tag>)> {
    let all = all_tags(html);
    all.iter()
        .filter(|t| t.name == "form")
        .map(|f| {
            let close = html[f.end..].find("</form>").map_or(html.len(), |e| f.end + e);
            let inputs = all.iter().filter(|t| t.name == "input" && t.start > f.start && t.start < close).cloned().collect();
            (f.clone(), inputs)
        })
        .collect()
}

/// The inputs of the POST form with `action` (query ignored); panics if there is none.
pub fn form_inputs(html: &str, action: &str) -> Vec<Tag> {
    let found: Vec<_> = forms(html)
        .into_iter()
        .filter(|(f, _)| f.attr("action").is_some_and(|a| a.split('?').next() == Some(action)))
        .collect();
    assert_eq!(found.len(), 1, "one form with action={action:?} in:\n{html}");
    let (form, inputs) = found.into_iter().next().unwrap();
    assert!(form.attr("method").is_some_and(|m| m.eq_ignore_ascii_case("post")), "the {action} form posts: {form:?}");
    inputs
}

fn names_by_autocomplete(inputs: &[Tag], autocomplete: &str) -> Vec<String> {
    inputs
        .iter()
        .filter(|i| i.attr("autocomplete") == Some(autocomplete))
        .map(|i| i.attr("name").unwrap_or_else(|| panic!("input without a name: {i:?}")).to_string())
        .collect()
}

/// The sign-in form's user name and password inputs, found by their autocomplete tokens
/// (WCAG 1.3.5): `username` and `current-password`.
pub fn login_fields(html: &str) -> (String, String) {
    let inputs = form_inputs(html, "/login");
    let user = names_by_autocomplete(&inputs, "username");
    let pw = names_by_autocomplete(&inputs, "current-password");
    assert!(user.len() == 1 && pw.len() == 1, "sign-in form: one autocomplete=username and one current-password input: {inputs:?}");
    (user[0].clone(), pw[0].clone())
}

/// The change-password form's current, new and repeated inputs: `current-password`, then two
/// `new-password`, in page order.
pub fn password_fields(html: &str) -> (String, String, String) {
    let inputs = form_inputs(html, "/me/password");
    let current = names_by_autocomplete(&inputs, "current-password");
    let new = names_by_autocomplete(&inputs, "new-password");
    assert!(current.len() == 1 && new.len() == 2, "change-password form: one current-password and two new-password inputs: {inputs:?}");
    (current[0].clone(), new[0].clone(), new[1].clone())
}

/// The value of the first `<input name="csrf">`.
pub fn csrf_token(html: &str) -> Option<String> {
    tags(html, "input").into_iter().find(|t| t.attr("name") == Some(CSRF_FIELD)).and_then(|t| t.attr("value").map(str::to_string))
}

/// Text of the element with `id` (tags stripped, entities decoded, trimmed).
pub fn text_of_id(html: &str, id: &str) -> Option<String> {
    let t = all_tags(html).into_iter().find(|t| t.attr("id") == Some(id))?;
    let close = html[t.end..].find(&format!("</{}>", t.name)).map_or(t.end, |e| t.end + e);
    let mut text = String::new();
    let mut in_tag = false;
    for c in html[t.end..close].chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    Some(unescape(text.trim()))
}

pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let c = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => u32::from_str_radix(&entity[2..], 16).ok().and_then(char::from_u32),
            _ if entity.starts_with('#') => entity[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------------------------
// Admin pages and the setup link

impl WebHarness {
    /// `user`, made admin.
    pub fn admin(&self, login: &str) {
        self.user(login);
        self.store.set_admin(login, true).unwrap();
    }

    /// The account id of `login`; panics if there is none.
    pub fn id(&self, login: &str) -> i64 {
        self.store.account_id(login).unwrap().unwrap_or_else(|| panic!("no account {login}")).0
    }

    pub fn account(&self, login: &str) -> synology_mail_server::store::Account {
        self.store.accounts().unwrap().into_iter().find(|a| a.login == login).unwrap_or_else(|| panic!("no account {login}"))
    }

    /// Every account (login, admin, disabled, auth_stamp) and address (address, login): what a
    /// refused request must leave as it was.
    pub fn snapshot(&self) -> Snapshot {
        let accounts = self.store.accounts().unwrap().into_iter().map(|a| (a.login, a.admin, a.disabled, a.auth_stamp)).collect();
        Snapshot { accounts, addresses: self.store.addresses().unwrap() }
    }

    /// A browser signed in as `login` with `harness::password(login)`.
    pub async fn signed_in(&self, login: &str) -> Browser<'_> {
        let mut b = self.browser();
        let r = b.sign_in(login, &crate::harness::password(login)).await;
        assert_eq!(r.status, 303, "sign-in as {login}: {}", r.text());
        b
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub accounts: Vec<(String, bool, bool, i64)>,
    pub addresses: Vec<(String, String)>,
}

/// A POST form as a page renders it.
#[derive(Debug, Clone)]
pub struct PostForm {
    /// As written in the page, query included.
    pub action: String,
    /// Hidden inputs and the submit button's name and value: what a browser sends unasked.
    pub sent: Vec<(String, String)>,
    /// Inputs a person fills in, in page order.
    pub fields: Vec<Tag>,
    /// The form's markup.
    pub html: String,
}

impl PostForm {
    /// Names of the fields of type password, in page order.
    pub fn password_fields(&self) -> Vec<String> {
        self.fields.iter().filter(|f| f.attr("type") == Some("password")).map(|f| f.attr("name").unwrap_or_default().to_string()).collect()
    }

    /// The one text input; panics unless there is exactly one.
    pub fn text_field(&self) -> String {
        let text: Vec<&Tag> = self.fields.iter().filter(|f| matches!(f.attr("type"), None|Some("text")|Some("email"))).collect();
        assert_eq!(text.len(), 1, "one text field in the {} form: {:?}", self.action, self.fields);
        text[0].attr("name").unwrap_or_else(|| panic!("a field without a name: {:?}", text[0])).to_string()
    }

    /// The value sent for `name`, if any.
    pub fn sent(&self, name: &str) -> Option<&str> {
        self.sent.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The same form with `name` sent as `value` (replaced, or added).
    pub fn with(&self, name: &str, value: &str) -> PostForm {
        let mut f = self.clone();
        match f.sent.iter_mut().find(|(k, _)| k == name) {
            Some(pair) => pair.1 = value.to_string(),
            None => f.sent.push((name.to_string(), value.to_string())),
        }
        f
    }

    /// The same form without `name`.
    pub fn without(&self, name: &str) -> PostForm {
        let mut f = self.clone();
        f.sent.retain(|(k, _)| k != name);
        f
    }
}

/// Every POST form whose action's path is `action`.
pub fn post_forms(html: &str, action: &str) -> Vec<PostForm> {
    let all = all_tags(html);
    all.iter()
        .filter(|t| t.name == "form" && t.attr("method").is_some_and(|m| m.eq_ignore_ascii_case("post")))
        .filter(|f| f.attr("action").is_some_and(|a| a.split('?').next() == Some(action)))
        .map(|f| {
            let close = html[f.end..].find("</form>").map_or(html.len(), |e| f.end + e);
            let inside: Vec<&Tag> = all.iter().filter(|t| t.start > f.start && t.start < close).collect();
            let mut sent = Vec::new();
            let mut fields = Vec::new();
            for t in inside.iter().filter(|t| t.name == "input") {
                match t.attr("type") {
                    Some("hidden") => sent.push((t.attr("name").unwrap_or_default().to_string(), t.attr("value").unwrap_or_default().to_string())),
                    Some("submit" | "button") => {}
                    _ => fields.push((*t).clone()),
                }
            }
            if let Some(button) = inside.iter().find(|t| t.name == "button" && t.attr("type").is_none_or(|v| v == "submit"))
                && let Some(name) = button.attr("name")
            {
                sent.push((name.to_string(), button.attr("value").unwrap_or_default().to_string()));
            }
            PostForm { action: f.attr("action").unwrap().to_string(), sent, fields, html: html[f.start..close].to_string() }
        })
        .collect()
}

/// The one POST form to `action`; panics unless there is exactly one.
#[track_caller]
pub fn post_form(html: &str, action: &str) -> PostForm {
    let mut found = post_forms(html, action);
    assert_eq!(found.len(), 1, "one form with action={action:?} in:\n{html}");
    found.remove(0)
}

/// The page links to the account's page by id.
pub fn account_href(id: i64) -> String {
    format!("/account?id={id}")
}

impl Browser<'_> {
    /// Submit `form` as a browser would: what it sends unasked, then `fill`.
    pub async fn submit(&mut self, form: &PostForm, fill: &[(&str, &str)]) -> Resp {
        let mut body: Vec<(&str, &str)> = form.sent.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        body.extend_from_slice(fill);
        let bytes = self.request("POST", &form.action, Some(&form_body(&body)));
        self.send(&bytes).await
    }

    /// GET the account's page; it must be there.
    pub async fn account_page(&mut self, login: &str) -> String {
        let id = self.h.id(login);
        let r = self.get(&account_href(id)).await;
        assert_eq!(r.status, 200, "GET the page of {login}: {} {:?}", r.status, r.header("location"));
        r.text()
    }

    /// The one form to `action` on the account's page.
    pub async fn account_form(&mut self, login: &str, action: &str) -> PostForm {
        let page = self.account_page(login).await;
        post_form(&page, action)
    }

    /// Fill in and send the new-account form on /accounts.
    pub async fn create_account(&mut self, login: &str, password: &str, again: &str) -> Resp {
        let page = self.get("/accounts").await;
        assert_eq!(page.status, 200, "GET /accounts: {} {:?}", page.status, page.header("location"));
        let form = post_form(&page.text(), "/accounts");
        let (user, pw) = (form.text_field(), form.password_fields());
        assert_eq!(pw.len(), 2, "the new-account form takes the password twice: {:?}", form.fields);
        self.submit(&form, &[(&user, login), (&pw[0], password), (&pw[1], again)]).await
    }

    /// Fill in and send the set-password form on the account's page.
    pub async fn set_password(&mut self, login: &str, password: &str, again: &str) -> Resp {
        let form = self.account_form(login, "/account/password").await;
        let pw = form.password_fields();
        assert!(pw.len() == 2 && form.fields.len() == 2, "the set-password form takes the password twice, nothing else: {:?}", form.fields);
        self.submit(&form, &[(&pw[0], password), (&pw[1], again)]).await
    }

    /// Press the button of the one form to `action` on the account's page.
    pub async fn press(&mut self, login: &str, action: &str) -> Resp {
        let form = self.account_form(login, action).await;
        assert!(form.fields.is_empty(), "{action} is a button: {:?}", form.fields);
        self.submit(&form, &[]).await
    }

    pub async fn add_address(&mut self, login: &str, address: &str) -> Resp {
        let form = self.account_form(login, "/account/address/add").await;
        let field = form.text_field();
        self.submit(&form, &[(&field, address)]).await
    }

    /// The remove form of `address` on the account's page: the one that sends the address.
    pub async fn remove_form(&mut self, login: &str, address: &str) -> PostForm {
        let page = self.account_page(login).await;
        let mut found: Vec<PostForm> = post_forms(&page, "/account/address/remove").into_iter().filter(|f| f.sent.iter().any(|(_, v)| v == address)).collect();
        assert_eq!(found.len(), 1, "one remove form for {address} on the page of {login}:\n{page}");
        found.remove(0)
    }

    pub async fn remove_address(&mut self, login: &str, address: &str) -> Resp {
        let form = self.remove_form(login, address).await;
        self.submit(&form, &[]).await
    }

    /// The setup page's forms at `path`: (make an existing account admin, create a new admin),
    /// told apart by their password fields (one, two).
    pub async fn setup_forms(&mut self, path: &str) -> (PostForm, PostForm) {
        let r = self.get(path).await;
        assert_eq!(r.status, 200, "GET the setup link: {}", r.text());
        let forms = post_forms(&r.text(), "/setup");
        let pick = |n: usize| {
            let f: Vec<&PostForm> = forms.iter().filter(|f| f.password_fields().len() == n).collect();
            assert_eq!(f.len(), 1, "one setup form with {n} password field(s):\n{}", r.text());
            f[0].clone()
        };
        (pick(1), pick(2))
    }

    pub async fn setup_promote(&mut self, path: &str, login: &str, password: &str) -> Resp {
        let (form, _) = self.setup_forms(path).await;
        let (user, pw) = (form.text_field(), form.password_fields());
        self.submit(&form, &[(&user, login), (&pw[0], password)]).await
    }

    pub async fn setup_create(&mut self, path: &str, login: &str, password: &str, again: &str) -> Resp {
        let (_, form) = self.setup_forms(path).await;
        let (user, pw) = (form.text_field(), form.password_fields());
        self.submit(&form, &[(&user, login), (&pw[0], password), (&pw[1], again)]).await
    }
}

/// 303 with a fixed `done=` code (letters and dashes only, so nothing typed is echoed) to an
/// account page or the list.
#[track_caller]
pub fn assert_done(r: &Resp, what: &str) {
    assert_eq!(r.status, 303, "{what}: 303, got {} {}", r.status, r.text());
    let to = location(r);
    let (path, query) = to.split_once('?').unwrap_or((to.as_str(), ""));
    assert!(path == "/account" || path == "/accounts", "{what}: back to an account page or the list: {to}");
    let done = query.split('&').find_map(|p| p.strip_prefix("done=")).unwrap_or_else(|| panic!("{what}: a done= code in {to}"));
    assert!(!done.is_empty() && done.bytes().all(|c| c.is_ascii_lowercase() || c == b'-'), "{what}: a fixed code: {to}");
}

/// The input named `name` in `form` is marked invalid and points to its message.
#[track_caller]
pub fn assert_field_error(html: &str, action: &str, name: &str, what: &str) {
    let form = post_forms(html, action).into_iter().next().unwrap_or_else(|| panic!("{what}: the {action} form is shown again:\n{html}"));
    let field = form.fields.iter().find(|f| f.attr("name") == Some(name)).unwrap_or_else(|| panic!("{what}: field {name:?} in {:?}", form.fields));
    assert_eq!(field.attr("aria-invalid"), Some("true"), "{what}: {name} is marked invalid: {field:?}");
    let by = field.attr("aria-describedby").unwrap_or_else(|| panic!("{what}: {name} points to its message: {field:?}"));
    assert!(text_of_id(html, by).is_some_and(|t| !t.is_empty()), "{what}: the message {by:?} has text");
}

/// The value the input named `name` of the form to `action` is shown with.
pub fn field_value(html: &str, action: &str, name: &str) -> Option<String> {
    post_forms(html, action).into_iter().next()?.fields.iter().find(|f| f.attr("name") == Some(name))?.attr("value").map(str::to_string)
}

/// The page's text, tags stripped and entities decoded, whitespace collapsed.
pub fn visible_text(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    unescape(&text).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first table: each row's cell texts (th or td) and markup.
pub fn table_rows(html: &str) -> Vec<(Vec<String>, String)> {
    let Some(start) = html.find("<table") else { return Vec::new() };
    let end = html[start..].find("</table>").map_or(html.len(), |e| start + e);
    html[start..end]
        .split("<tr")
        .skip(1)
        .map(|row| {
            let row = row.split("</tr>").next().unwrap_or_default();
            let mut cells = Vec::new();
            let mut rest = row;
            while let Some(p) = [rest.find("<th"), rest.find("<td")].into_iter().flatten().min() {
                let tag = &rest[p + 1..p + 3];
                let open_end = rest[p..].find('>').map_or(rest.len(), |e| p + e + 1);
                let close = rest[open_end..].find(&format!("</{tag}>")).map_or(rest.len(), |e| open_end + e);
                cells.push(visible_text(&rest[open_end..close]));
                rest = &rest[close..];
            }
            (cells, row.to_string())
        })
        .collect()
}

/// YYYY-MM-DD (UTC) of a unix time.
pub fn date(unix: i64) -> String {
    let (y, m, d, ..) = synology_mail_server::time::civil(unix);
    format!("{y:04}-{m:02}-{d:02}")
}

/// One hex digit of `t` changed.
pub fn one_off(t: &str) -> String {
    let mut s = t.to_string();
    let last = s.pop().unwrap();
    s.push(if last == '0' { '1' } else { '0' });
    s
}

/// The token of a setup path `/setup?t=<hex>`.
pub fn setup_token(path: &str) -> &str {
    path.strip_prefix("/setup?t=").unwrap_or_else(|| panic!("a setup path is /setup?t=<hex>: {path}"))
}
