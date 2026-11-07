//! Settings web server, transport and HTTP layer: HTTPS only on the IMAP certificate, home network
//! only (refused before TLS), no requests through a reverse proxy unless opened up, request limits
//! and timeouts on the injected clock, the security headers on every response, and the cached
//! stylesheet. The pages behind it are tested in the other web_* files; here `/` is a redirect
//! and `/no-such-page` a 404.

mod browser;
mod harness;
mod net;

use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use browser::*;
use harness::{ManualClock, TIMEOUT};
use net::client_tls_versions;
use synology_mail_server::web::{WebConfig, is_home_network};

const MISSING: &str = "/no-such-page";

// ---------------------------------------------------------------------------------------------
// Helpers

/// The headers every response carries. `css`: the stylesheet, cached for a year; anything else
/// is never cached.
fn assert_security_headers(r: &Resp, css: bool, what: &str) {
    let one = |name: &str| {
        let v = r.all(name);
        assert_eq!(v.len(), 1, "{what}: exactly one {name}, got {v:?} in {:?}", r.headers);
        v[0].to_string()
    };
    assert_eq!(one("content-security-policy"), CSP, "{what}");
    assert_eq!(one("x-content-type-options"), "nosniff", "{what}");
    assert_eq!(one("referrer-policy"), "same-origin", "{what}: a form POST must carry its Origin");
    assert!(one("x-frame-options").eq_ignore_ascii_case("DENY"), "{what}");
    assert_eq!(one("cache-control"), if css { CSS_CACHE } else { "no-store" }, "{what}");
    assert!(r.header("strict-transport-security").is_none(), "{what}: no HSTS on a self-signed certificate");
    if !r.body.is_empty() {
        assert!(r.header("content-type").is_some(), "{what}: a body needs a Content-Type (nosniff)");
    }
    // RFC 9110 6.6.1: an origin server with a clock sends Date on 2xx-4xx (IMF-fixdate).
    if r.status < 500 {
        let date = one("date");
        assert!(date.len() == 29 && date.ends_with(" GMT") && date.as_bytes()[3] == b',', "{what}: IMF-fixdate Date, got {date:?}");
    }
}

/// The response is followed by a close: `Connection: close`, then EOF with nothing more.
async fn assert_closes(w: &mut Web, r: &Resp, what: &str) {
    assert!(r.closes(), "{what}: Connection: close before closing, got {:?}", r.headers);
    let rest = w.expect_closed().await;
    assert!(rest.is_empty(), "{what}: nothing after the response, got {:?}", String::from_utf8_lossy(&rest));
}

async fn status_of(h: &WebHarness, bytes: &[u8]) -> (Web, Resp) {
    let (w, r) = h.raw(bytes).await;
    let r = r.unwrap_or_else(|| panic!("no response to {:?}", String::from_utf8_lossy(bytes)));
    (w, r)
}

/// The connection is closed by the server; an optional 408 before the close is allowed.
async fn assert_timed_out(w: &mut Web, what: &str) {
    let rest = w.expect_closed().await;
    if !rest.is_empty() {
        assert!(rest.starts_with(b"HTTP/1.1 408"), "{what}: close, or 408 then close; got {:?}", String::from_utf8_lossy(&rest));
    }
}

/// Open a connection and wait until its request head timer is armed. The first sleep after
/// `mark` is the TLS handshake timeout; the head timeout is the next 10 s sleep.
async fn open_with_head_timer(h: &WebHarness) -> Web {
    let mark = h.clock.mark();
    let w = h.open().await;
    h.clock.wait_sleep_since(mark + 1, HEAD_TIMEOUT, "the request head timeout").await;
    w
}

async fn wait_no_pending(clock: &ManualClock, what: &str) {
    let start = std::time::Instant::now();
    while !clock.pending().is_empty() {
        assert!(start.elapsed() < TIMEOUT, "{what}: timers still pending: {:?}", clock.pending());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn assert_refused_connection(h: &WebHarness) {
    match Web::open(h.addr, net::client_tls(&h.pki)).await {
        Err(_) => {}
        Ok(mut w) => {
            let _ = w.try_write(&request("GET", &css_path(), &h.host(), &[], b"")).await;
            assert!(w.read_response(false).await.is_none(), "a connection over the cap must be closed, not served");
        }
    }
}

async fn assert_accepted_eventually(h: &WebHarness) {
    let start = std::time::Instant::now();
    loop {
        if let Ok(mut w) = Web::open(h.addr, net::client_tls(&h.pki)).await {
            let _ = w.try_write(&request("GET", &css_path(), &h.host(), &[], b"")).await;
            if let Some(r) = w.read_response(false).await
                && r.status == 200
            {
                return;
            }
        }
        assert!(start.elapsed() < TIMEOUT, "a slot freed by a closed connection is never reused");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// TLS 1.1 ClientHello by hand (rustls cannot send one).
fn tls11_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x02];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x04, 0x00, 0x2f, 0x00, 0xff]);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend_from_slice(&hs);
    rec
}

async fn read_raw_until_closed(tcp: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = tokio::time::timeout(TIMEOUT, async {
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the server must close the connection");
    got
}

// ---------------------------------------------------------------------------------------------
// Configuration

#[tokio::test]
async fn web_config_defaults_match_the_design() {
    let pki = net::Pki::local();
    let tls = synology_mail_server::tls::server_config(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    let c = WebConfig::new(tls);
    assert_eq!(c.max_conn, 32);
    assert_eq!(c.max_conn_per_ip, 8);
    assert_eq!(c.handshake_timeout, HANDSHAKE_TIMEOUT);
    assert_eq!(c.head_timeout, HEAD_TIMEOUT);
    assert_eq!(c.body_timeout, BODY_TIMEOUT);
    assert_eq!(c.keepalive_idle, KEEPALIVE_IDLE);
    assert_eq!(c.max_requests, 100);
    assert!(!c.allow_public);
    assert!((c.is_allowed)("192.168.1.10".parse().unwrap()), "default is_allowed is is_home_network");
    assert!(!(c.is_allowed)("8.8.8.8".parse().unwrap()), "default is_allowed is is_home_network");
}

// ---------------------------------------------------------------------------------------------
// TLS

#[tokio::test]
async fn https_only_plain_http_gets_no_http_bytes() {
    let h = WebHarness::start().await;
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let _ = tcp.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", css_path(), h.host()).as_bytes()).await;
    let got = read_raw_until_closed(&mut tcp).await;
    assert!(!got.windows(5).any(|w| w == b"HTTP/"), "plain HTTP was answered: {:?}", String::from_utf8_lossy(&got));
    assert!(got.is_empty() || got[0] == 0x15, "expected a TLS alert or a close, got {:02x?}", &got[..got.len().min(16)]);
}

#[tokio::test]
async fn same_certificate_as_imap() {
    let h = WebHarness::start().await;
    // In-process both listeners get the same config; tests/web_serve.rs checks the real wiring.
    let web = h.open().await;
    assert_eq!(web.peer_certificate().expect("web certificate"), h.pki.cert_der);

    // TLS 1.2 is accepted too (as on IMAP), and ALPN is never negotiated (HTTP/1.1 only).
    let mut alpn = (*client_tls_versions(&h.pki, &[&rustls::version::TLS12])).clone();
    alpn.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut w12 = Web::open(h.addr, std::sync::Arc::new(alpn)).await.expect("TLS 1.2 with ALPN offered");
    assert_eq!(w12.tls_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    assert_eq!(w12.alpn(), None, "no ALPN: h2 must never be selected");
    assert_eq!(w12.get(&h.host(), &css_path()).await.status, 200);
}

#[tokio::test]
async fn tls_1_1_refused() {
    let h = WebHarness::start().await;
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    tcp.write_all(&tls11_client_hello()).await.unwrap();
    let got = read_raw_until_closed(&mut tcp).await;
    let server_hello = got.len() >= 6 && got[0] == 0x16 && got[5] == 0x02;
    assert!(!server_hello, "TLS 1.1 got a ServerHello: {:02x?}", &got[..got.len().min(16)]);
    assert!(got.is_empty() || got[0] == 0x15, "expected an alert or a close, got {:02x?}", &got[..got.len().min(16)]);
}

#[tokio::test]
async fn tls_handshake_times_out_after_10_s() {
    let h = WebHarness::start().await;
    let mark = h.clock.mark();
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    h.clock.wait_sleep_since(mark, HANDSHAKE_TIMEOUT, "the TLS handshake timeout").await;
    h.clock.advance(HANDSHAKE_TIMEOUT - Duration::from_secs(1));
    let mut b = [0u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), tcp.read(&mut b)).await.is_err(),
        "closed before the 10 s handshake timeout"
    );
    h.clock.advance(Duration::from_secs(1));
    read_raw_until_closed(&mut tcp).await;
}

// ---------------------------------------------------------------------------------------------
// Who may connect

#[test]
fn home_network_table() {
    let allowed = [
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "169.254.0.1",
        "169.254.255.254",
        "::1",
        "fc00::1",
        "fd12:3456:789a::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "fe80::1",
        "febf:ffff::1",
        "::ffff:192.168.1.10",
        "::ffff:127.0.0.1",
        "::ffff:10.1.2.3",
        "::ffff:172.16.5.4",
        "::ffff:169.254.1.1",
    ];
    let refused = [
        "0.0.0.0",
        "8.8.8.8",
        "1.1.1.1",
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.1",
        "192.167.255.255",
        "192.169.0.1",
        "169.253.255.255",
        "169.255.0.1",
        "100.64.0.1",
        "128.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "2001:db8::1",
        "2606:4700::1",
        "fbff::1",
        "fec0::1",
        "ff02::1",
        "::ffff:8.8.8.8",
        "::ffff:172.32.0.1",
        "::ffff:100.64.0.1",
        "::127.0.0.1",
        "64:ff9b::c0a8:10a",
    ];
    for a in allowed {
        assert!(is_home_network(a.parse().unwrap()), "{a} is on the home network");
    }
    for a in refused {
        assert!(!is_home_network(a.parse().unwrap()), "{a} is not on the home network");
    }
}

#[tokio::test]
async fn refused_peer_dropped_before_tls() {
    let h = WebHarness::start_with(|c| c.is_allowed = |ip| !ip.is_loopback()).await;
    let mark = h.clock.mark();
    let open = Web::open(h.addr, net::client_tls(&h.pki)).await;
    assert!(open.is_err(), "a peer outside the home network is closed before the TLS handshake, not answered over TLS");
    assert!(!h.clock.has_sleep_since(mark, HANDSHAKE_TIMEOUT), "no handshake is started for a refused peer");

    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let got = read_raw_until_closed(&mut tcp).await;
    assert!(got.is_empty(), "nothing is sent to a refused peer: {:02x?}", &got[..got.len().min(16)]);
    wait_no_pending(&h.clock, "after refused peers").await;
}

const PROXY_HEADERS: [&str; 4] = ["Forwarded: for=192.168.1.10", "X-Forwarded-For: 192.168.1.10", "X-Real-IP: 192.168.1.10", "CF-Connecting-IP: 192.168.1.10"];

#[tokio::test]
async fn proxied_request_403_unless_public() {
    let h = WebHarness::start().await;
    let host = h.host();
    h.user("user@example.com");
    let (u, p) = h.login_fields().await;
    for header in PROXY_HEADERS {
        for (what, bytes) in [
            ("GET stylesheet", request("GET", &css_path(), &host, &[header], b"")),
            ("GET /login", request("GET", "/login", &host, &[header], b"")),
            ("GET /", request("GET", "/", &host, &[header], b"")),
        ] {
            let (_, r) = status_of(&h, &bytes).await;
            assert_eq!(r.status, 403, "{what} with {header:?} from loopback: a reverse proxy hides the client, so the home-network check cannot hold");
            assert_security_headers(&r, false, &format!("403 to {what} with {header:?}"));
        }
        let mut b = h.browser();
        let form = form_body(&[(&u, "user@example.com"), (&p, &harness::password("user@example.com"))]);
        let mut bytes = b.request("POST", "/login", Some(&form));
        let at = bytes.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
        bytes.splice(at..at, format!("{header}\r\n").into_bytes());
        let r = b.raw(&bytes).await;
        assert_eq!(r.status, 403, "POST /login with {header:?}: {}", r.text());
        assert_no_session_cookie(&r, "a proxied sign-in");
    }

    let public = WebHarness::start_with(|c| {
        c.is_allowed = |_| false;
        c.allow_public = true;
    })
    .await;
    for header in PROXY_HEADERS {
        let (_, r) = status_of(&public, &request("GET", &css_path(), &public.host(), &[header], b"")).await;
        assert_eq!(r.status, 200, "with allow_public a proxied request is served ({header:?})");
        let (_, r) = status_of(&public, &request("GET", "/login", &public.host(), &[header], b"")).await;
        assert_eq!(r.status, 200, "with allow_public the sign-in page is served ({header:?})");
    }
}

#[tokio::test]
async fn allow_public_opens_it() {
    let h = WebHarness::start_with(|c| {
        c.is_allowed = |_| false;
        c.allow_public = true;
    })
    .await;
    let r = h.get(&css_path()).await;
    assert_eq!(r.status, 200);
}

// ---------------------------------------------------------------------------------------------
// Headers on every response

#[tokio::test]
async fn every_response_has_csp_nosniff_no_store_deny() {
    let h = WebHarness::start().await;
    let host = h.host();
    let long_head = request("GET", MISSING, &host, &[&format!("X-Pad: {}", "a".repeat(9000))], b"");
    let cases: Vec<(&str, Vec<u8>, bool, bool)> = vec![
        ("200 stylesheet", request("GET", &css_path(), &host, &[], b""), true, false),
        ("200 page", request("GET", "/login", &host, &[], b""), false, false),
        ("303 redirect", request("GET", "/", &host, &[], b""), false, false),
        ("HEAD stylesheet", request("HEAD", &css_path(), &host, &[], b""), true, true),
        ("404", request("GET", MISSING, &host, &[], b""), false, false),
        ("HEAD 404", request("HEAD", MISSING, &host, &[], b""), false, true),
        ("405", request("PUT", MISSING, &host, &[], b""), false, false),
        ("400 malformed", b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n".to_vec(), false, false),
        ("400 no Host", b"GET / HTTP/1.1\r\n\r\n".to_vec(), false, false),
        ("431", long_head, false, false),
        ("413", request("POST", MISSING, &host, &[&format!("Content-Type: {FORM}"), "Content-Length: 16385"], b""), false, false),
        ("415", post(MISSING, &host, "text/plain", b"a=b"), false, false),
        ("411", request("POST", MISSING, &host, &[&format!("Content-Type: {FORM}")], b""), false, false),
        ("501", request("POST", MISSING, &host, &[&format!("Content-Type: {FORM}"), "Transfer-Encoding: chunked"], b"0\r\n\r\n"), false, false),
    ];
    for (what, bytes, css, head) in cases {
        let mut w = h.open().await;
        let _ = w.try_write(&bytes).await;
        let r = w.read_response(head).await.unwrap_or_else(|| panic!("{what}: no response"));
        assert_security_headers(&r, css, what);
    }
}

#[tokio::test]
async fn css_cached_pages_not() {
    let h = WebHarness::start().await;
    let css = css_source();
    assert!(!css.is_empty() && css.len() <= 8 * 1024, "src/web/style.css is small ({} bytes)", css.len());
    let text = String::from_utf8(css.clone()).expect("UTF-8 stylesheet");
    assert!(!text.contains("url(") && !text.contains("@import"), "CSP default-src 'none' blocks anything the stylesheet loads");

    let r = h.get(&css_path()).await;
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").is_some_and(|t| t.to_ascii_lowercase().starts_with("text/css")), "{:?}", r.headers);
    assert_eq!(r.header("cache-control"), Some(CSS_CACHE));
    assert_eq!(r.body, css, "the stylesheet is served as built in");

    let upper = css_path().to_ascii_uppercase();
    for path in ["/style.css", "/style-0.0.0.css", &upper, MISSING] {
        let r = h.get(path).await;
        assert_eq!(r.status, 404, "{path}");
        assert_eq!(r.header("cache-control"), Some("no-store"), "{path}");
    }
}

#[tokio::test]
async fn head_has_get_headers_no_body() {
    let h = WebHarness::start().await;
    let host = h.host();
    let mut w = h.open().await;
    for path in [css_path(), MISSING.to_string()] {
        w.write(&request("HEAD", &path, &host, &[], b"")).await;
        let head = w.read_response(true).await.expect("HEAD response");
        // If HEAD sent a body, those bytes would be read as the next response head here.
        let get = w.get(&host, &path).await;
        assert_eq!(head.status, get.status, "{path}");
        let without_date = |r: &Resp| r.headers.iter().filter(|(n, _)| !n.eq_ignore_ascii_case("date")).cloned().collect::<Vec<_>>();
        assert_eq!(without_date(&head), without_date(&get), "{path}: HEAD carries GET's headers");
        assert_eq!(head.header("content-length"), Some(get.body.len().to_string().as_str()), "{path}");
    }
}

// ---------------------------------------------------------------------------------------------
// Limits

#[tokio::test]
async fn head_over_8_kib_431() {
    let h = WebHarness::start().await;
    let host = h.host();
    let padded = |total: usize| {
        let bare = request("GET", &css_path(), &host, &["X-Pad: "], b"").len();
        request("GET", &css_path(), &host, &[&format!("X-Pad: {}", "a".repeat(total - bare))], b"")
    };
    let at = padded(8192);
    assert_eq!(at.len(), 8192);
    let (_, r) = status_of(&h, &at).await;
    assert_eq!(r.status, 200, "a head of exactly 8 KiB (blank line included) is accepted");

    let (mut w, r) = status_of(&h, &padded(8193)).await;
    assert_eq!(r.status, 431);
    assert_closes(&mut w, &r, "431").await;

    // 32 header fields (Host included) are fine, 33 are not.
    let fields = |n: usize| (1..n).map(|i| format!("X-H{i}: v")).collect::<Vec<_>>();
    let f32 = fields(32);
    let (_, r) = status_of(&h, &request("GET", &css_path(), &host, &f32.iter().map(String::as_str).collect::<Vec<_>>(), b"")).await;
    assert_eq!(r.status, 200, "32 header fields");
    let f33 = fields(33);
    let (mut w, r) = status_of(&h, &request("GET", &css_path(), &host, &f33.iter().map(String::as_str).collect::<Vec<_>>(), b"")).await;
    assert_eq!(r.status, 431, "33 header fields");
    assert_closes(&mut w, &r, "431 for 33 fields").await;

    // A head that never ends gets the 431 as soon as it passes 8 KiB, not at the head timeout.
    let mut w = h.open().await;
    let mut endless = format!("GET / HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    endless.extend_from_slice(format!("X-Pad: {}", "a".repeat(9000)).as_bytes());
    let _ = w.try_write(&endless).await;
    let r = w.read_response(false).await.expect("431 without waiting for the end of the head");
    assert_eq!(r.status, 431);
    assert_closes(&mut w, &r, "431 for an endless head").await;
}

#[tokio::test]
async fn body_over_16_kib_413_unread() {
    let h = WebHarness::start().await;
    let host = h.host();
    let ct = format!("Content-Type: {FORM}");

    // 16 KiB exactly is read (and the unknown path is a 404).
    let body = format!("a={}", "b".repeat(16 * 1024 - 2));
    let (_, r) = status_of(&h, &post(MISSING, &host, FORM, body.as_bytes())).await;
    assert_eq!(r.status, 404, "a 16 KiB form body is within the limit");

    // One byte more: 413 at once, without waiting for (or reading) the body, then close.
    let mut w = h.open().await;
    w.write(&request("POST", MISSING, &host, &[&ct, "Content-Length: 16385"], b"")).await;
    let r = w.read_response(false).await.expect("413 before any body byte is sent");
    assert_eq!(r.status, 413);
    assert_closes(&mut w, &r, "413").await;

    // Also for huge announced lengths, even past u64 (RFC 9110 8.6: no overflow parsing errors).
    for cl in ["Content-Length: 1000000000000", "Content-Length: 99999999999999999999999999"] {
        let (mut w, r) = status_of(&h, &request("POST", MISSING, &host, &[&ct, cl], b"")).await;
        assert_eq!(r.status, 413, "{cl}");
        assert_closes(&mut w, &r, cl).await;
    }
}

#[tokio::test]
async fn post_without_content_length_411() {
    let h = WebHarness::start().await;
    let (_, r) = status_of(&h, &request("POST", MISSING, &h.host(), &[&format!("Content-Type: {FORM}")], b"")).await;
    assert_eq!(r.status, 411);
}

// ---------------------------------------------------------------------------------------------
// Timeouts (on the injected clock)

#[tokio::test]
async fn slow_head_times_out() {
    let h = WebHarness::start().await;
    let mut w = open_with_head_timer(&h).await;
    w.write(b"GET /style").await;
    h.clock.advance(Duration::from_secs(5));
    // More bytes do not restart the timer: the whole head has 10 s.
    w.write(format!("-{}.css HTTP/1.1\r\n", env!("CARGO_PKG_VERSION")).as_bytes()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.clock.advance(Duration::from_secs(4));
    assert!(w.nothing_within(Duration::from_millis(100)).await, "closed before the 10 s head timeout");
    h.clock.advance(Duration::from_secs(1));
    assert_timed_out(&mut w, "slow head").await;
}

#[tokio::test]
async fn slow_body_times_out() {
    let h = WebHarness::start().await;
    let mut w = open_with_head_timer(&h).await;
    h.clock.advance(Duration::from_secs(5));
    let mark = h.clock.mark();
    let ct = format!("Content-Type: {FORM}");
    w.write(&request("POST", MISSING, &h.host(), &[&ct, "Content-Length: 100"], b"a=0123456789")).await;
    h.clock.wait_sleep_since(mark, BODY_TIMEOUT, "the body timeout").await;
    // The body has 10 s from the end of the head, not from the start of the connection.
    h.clock.advance(BODY_TIMEOUT - Duration::from_secs(1));
    assert!(w.nothing_within(Duration::from_millis(100)).await, "closed before the 10 s body timeout");
    h.clock.advance(Duration::from_secs(1));
    assert_timed_out(&mut w, "slow body").await;
}

#[tokio::test]
async fn keepalive_idle_closes_after_15_s() {
    let h = WebHarness::start().await;
    let mut w = h.open().await;
    let mark = h.clock.mark();
    let r = w.get(&h.host(), &css_path()).await;
    assert!(!r.closes(), "HTTP/1.1 keeps the connection open");
    h.clock.wait_sleep_since(mark, KEEPALIVE_IDLE, "the keep-alive idle timeout").await;
    h.clock.advance(KEEPALIVE_IDLE - Duration::from_secs(1));
    assert!(w.nothing_within(Duration::from_millis(100)).await, "closed before 15 s idle");

    // Still usable; the next request restarts the idle time.
    let mark = h.clock.mark();
    assert_eq!(w.get(&h.host(), &css_path()).await.status, 200);
    h.clock.wait_sleep_since(mark, KEEPALIVE_IDLE, "the keep-alive idle timeout").await;
    h.clock.advance(KEEPALIVE_IDLE);
    assert_timed_out(&mut w, "keep-alive idle").await;

    // Connection: close from the client is honoured.
    let mut w = h.open().await;
    w.write(&request("GET", &css_path(), &h.host(), &["Connection: close"], b"")).await;
    let r = w.read_response(false).await.expect("response");
    assert_eq!(r.status, 200);
    assert_closes(&mut w, &r, "client asked for close").await;
}

#[tokio::test]
async fn hundred_requests_per_connection() {
    let h = WebHarness::start().await;
    let mut w = h.open().await;
    for i in 1..=100 {
        let r = w.get(&h.host(), &css_path()).await;
        assert_eq!(r.status, 200, "request {i}");
        if i < 100 {
            assert!(!r.closes(), "request {i} keeps the connection");
        } else {
            assert_closes(&mut w, &r, "the 100th request").await;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Methods and malformed requests

#[tokio::test]
async fn put_and_delete_405() {
    let h = WebHarness::start().await;
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"] {
        for path in [css_path(), MISSING.to_string()] {
            let (_, r) = status_of(&h, &request(method, &path, &h.host(), &[], b"")).await;
            assert_eq!(r.status, 405, "{method} {path}");
            let allow = r.header("allow").unwrap_or_else(|| panic!("{method}: 405 needs Allow"));
            let mut got: Vec<String> = allow.split(',').map(|m| m.trim().to_string()).collect();
            got.sort();
            assert_eq!(got, ["GET", "HEAD", "POST"], "{method}: Allow");
        }
    }
    let (_, r) = status_of(&h, &request("FOO", MISSING, &h.host(), &[], b"")).await;
    assert!(r.status == 405 || r.status == 501, "unknown method: 405 or 501, got {}", r.status);
}

#[tokio::test]
async fn malformed_400() {
    let h = WebHarness::start().await;
    let host = h.host();
    let ct = format!("Content-Type: {FORM}");
    let mut cases: Vec<Vec<u8>> = vec![
        b"GET\r\n\r\n".to_vec(),
        b"GET  / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET / FOO/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\n Host: localhost\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n: no-name\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nBad Name: x\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX: a\x00b\r\n\r\n".to_vec(),
        b"GET /\xff HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    ];
    for cl in [
        vec!["Content-Length: abc"],
        vec!["Content-Length: -1"],
        vec!["Content-Length: +3"],
        vec!["Content-Length: 3 3"],
        vec!["Content-Length: 0x3"],
        vec!["Content-Length: 3", "Content-Length: 3"],
        vec!["Content-Length: 3", "Content-Length: 4"],
        vec!["Content-Length:"],
    ] {
        let mut hs = vec![ct.as_str()];
        hs.extend(cl);
        cases.push(request("POST", MISSING, &host, &hs, b"a=b"));
    }
    for bytes in cases {
        let what = String::from_utf8_lossy(&bytes).into_owned();
        let (mut w, r) = status_of(&h, &bytes).await;
        assert_eq!(r.status, 400, "{what:?}");
        assert_closes(&mut w, &r, &what).await;
    }
}

#[tokio::test]
async fn missing_host_400() {
    let h = WebHarness::start().await;
    for bytes in [
        format!("GET {} HTTP/1.1\r\n\r\n", css_path()),
        format!("GET {} HTTP/1.1\r\nHost: {}\r\nHost: {}\r\n\r\n", css_path(), h.host(), h.host()),
    ] {
        let (mut w, r) = status_of(&h, bytes.as_bytes()).await;
        assert_eq!(r.status, 400, "{bytes:?}");
        assert_closes(&mut w, &r, &bytes).await;
    }
    // HTTP/1.0 needs no Host; it is answered (as HTTP/1.1) and closed.
    let (mut w, r) = status_of(&h, format!("GET {} HTTP/1.0\r\n\r\n", css_path()).as_bytes()).await;
    assert_eq!(r.status, 200);
    assert_closes(&mut w, &r, "HTTP/1.0").await;
}

#[tokio::test]
async fn transfer_encoding_501() {
    let h = WebHarness::start().await;
    let ct = format!("Content-Type: {FORM}");
    for te in ["Transfer-Encoding: chunked", "Transfer-Encoding: gzip, chunked"] {
        let (mut w, r) = status_of(&h, &request("POST", MISSING, &h.host(), &[&ct, te], b"3\r\na=b\r\n0\r\n\r\n")).await;
        assert_eq!(r.status, 501, "{te}");
        assert_closes(&mut w, &r, te).await;
    }
    let (mut w, r) = status_of(&h, &request("GET", &css_path(), &h.host(), &["Transfer-Encoding: chunked"], b"0\r\n\r\n")).await;
    assert_eq!(r.status, 501, "GET with Transfer-Encoding");
    assert_closes(&mut w, &r, "GET with Transfer-Encoding").await;
}

#[tokio::test]
async fn cl_and_te_400() {
    let h = WebHarness::start().await;
    let ct = format!("Content-Type: {FORM}");
    for hs in [[ct.as_str(), "Content-Length: 3", "Transfer-Encoding: chunked"], [ct.as_str(), "Transfer-Encoding: chunked", "Content-Length: 3"]] {
        let (mut w, r) = status_of(&h, &request("POST", MISSING, &h.host(), &hs, b"a=b")).await;
        assert_eq!(r.status, 400, "{hs:?}");
        assert_closes(&mut w, &r, "Content-Length with Transfer-Encoding").await;
    }
}

#[tokio::test]
async fn non_form_415() {
    let h = WebHarness::start().await;
    for ct in ["text/plain", "multipart/form-data; boundary=x", "application/json", "application/x-www-form-urlencodedx"] {
        let (_, r) = status_of(&h, &post(MISSING, &h.host(), ct, b"a=b")).await;
        assert_eq!(r.status, 415, "{ct}");
    }
    let (_, r) = status_of(&h, &request("POST", MISSING, &h.host(), &["Content-Length: 3"], b"a=b")).await;
    assert_eq!(r.status, 415, "no Content-Type");
    for ct in [FORM, "application/x-www-form-urlencoded; charset=UTF-8", "Application/X-WWW-Form-URLEncoded"] {
        let (_, r) = status_of(&h, &post(MISSING, &h.host(), ct, b"a=b")).await;
        assert_eq!(r.status, 404, "{ct} is a form (and the path is unknown)");
    }
}

#[tokio::test]
async fn bad_percent_or_utf8_400() {
    let h = WebHarness::start().await;
    for path in ["/%", "/%4", "/%ZZ", "/%G0", "/a%2", "/%C3%28", "/%FF", "/%E2%82%28", "/%ED%A0%80"] {
        let (_, r) = status_of(&h, &request("GET", path, &h.host(), &[], b"")).await;
        assert_eq!(r.status, 400, "{path}");
    }
    let r = h.get("/%C5%A0").await;
    assert_eq!(r.status, 404, "valid percent-encoded UTF-8 is just an unknown path");
}

#[test]
fn form_decoder() {
    use synology_mail_server::web::http::decode_form;
    let ok = |b: &[u8]| decode_form(b).unwrap_or_else(|| panic!("{:?} decodes", String::from_utf8_lossy(b)));
    let pairs = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();

    assert_eq!(ok(b""), pairs(&[]));
    assert_eq!(
        ok(b"login=test%40example.com&password=a+b%2Bc"),
        pairs(&[("login", "test@example.com"), ("password", "a b+c")])
    );
    assert_eq!(ok(b"a=1&a=2&b=3"), pairs(&[("a", "1"), ("a", "2"), ("b", "3")]), "order and repeats kept");
    assert_eq!(ok(b"flag&x="), pairs(&[("flag", ""), ("x", "")]));
    assert_eq!(ok(b"a=1&&b=2&"), pairs(&[("a", "1"), ("b", "2")]), "empty pieces skipped");
    assert_eq!(ok(b"k=x=y"), pairs(&[("k", "x=y")]), "the first = splits");
    assert_eq!(ok(b"k=a%3Db%26c"), pairs(&[("k", "a=b&c")]));
    assert_eq!(ok(b"k=%C5%A0tefan&n=%c4%8d"), pairs(&[("k", "Štefan"), ("n", "č")]));
    assert_eq!(ok(b"a+b=c+d"), pairs(&[("a b", "c d")]), "+ is a space in names too");
    assert_eq!(ok("k=Š".as_bytes()), pairs(&[("k", "Š")]), "raw UTF-8");

    for bad in [
        &b"%"[..],
        b"a=%",
        b"a=%4",
        b"a=%ZZ",
        b"a=%G1",
        b"a=%C3%28",
        b"a=%FF",
        b"%FF=a",
        b"a=%E2%82",
        b"a=\xff",
        b"\xc3=a",
    ] {
        assert_eq!(decode_form(bad), None, "{:?} is refused", String::from_utf8_lossy(bad));
    }
}

// ---------------------------------------------------------------------------------------------
// Robustness and resources

static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Record panics on this test's thread (the current-thread runtime runs the server tasks here).
fn watch_panics() -> String {
    let me = std::thread::current().name().unwrap_or("").to_string();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let name = std::thread::current().name().unwrap_or("").to_string();
        PANICS.lock().unwrap_or_else(|e| e.into_inner()).push(format!("{name}: {info}"));
        prev(info);
    }));
    me
}

struct Lcg(u64);
impl Lcg {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (self.0 >> 33) as u8
            })
            .collect()
    }
}

#[tokio::test]
async fn garbage_never_crashes_then_get_works() {
    let me = watch_panics();
    let h = WebHarness::start().await;
    let host = h.host();
    let mut rng = Lcg(0x5eed);

    // Before TLS.
    for n in [1, 5, 300, 5000] {
        let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
        let _ = tcp.write_all(&rng.bytes(n)).await;
        let _ = tcp.shutdown().await;
        read_raw_until_closed(&mut tcp).await;
    }

    // Inside TLS.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for n in [1, 64, 2000, 8000, 20000] {
        cases.push(rng.bytes(n));
        let mut c = b"GET ".to_vec();
        c.extend(rng.bytes(n));
        c.extend_from_slice(b"\r\n\r\n");
        cases.push(c);
        let mut c = format!("GET / HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
        c.extend(rng.bytes(n));
        c.extend_from_slice(b"\r\n\r\n");
        cases.push(c);
    }
    cases.push(b"\r\n".repeat(10000));
    cases.push(format!("GET /{} HTTP/1.1\r\nHost: {host}\r\n\r\n", "a".repeat(9000)).into_bytes());
    cases.push(format!("GET / HTTP/1.1\r\nHost: {host}\r\nX: é\r\n\r\n").into_bytes());
    cases.push(request("POST", MISSING, &host, &[&format!("Content-Type: {FORM}"), "Content-Length: 18446744073709551616"], b""));
    cases.push(post(MISSING, &host, FORM, b"%%%%%%%%%%"));
    cases.push(post(MISSING, &host, FORM, b"a=\xff\xfe&\xc3"));
    cases.push(request("GET", "/%%%%", &host, &[], b""));
    cases.push(request("GET", "*", &host, &[], b""));
    cases.push(request("GET", "http://example.com/x", &host, &[], b""));
    cases.push(request("GET", &css_path(), &host, &["Range: bytes=0-1", "Expect: 100-continue", "Upgrade: h2c", "Connection: Upgrade, HTTP2-Settings"], b""));
    let mut pipelined = request("GET", &css_path(), &host, &[], b"").repeat(50);
    pipelined.extend(rng.bytes(500));
    cases.push(pipelined);
    for bytes in cases {
        let mut w = h.open().await;
        let _ = w.try_write(&bytes).await;
        w.shutdown().await;
        w.expect_closed().await;
    }

    let r = h.get(&css_path()).await;
    assert_eq!(r.status, 200, "the server still answers after the garbage");
    wait_no_pending(&h.clock, "after the garbage").await;
    let mine: Vec<String> = PANICS.lock().unwrap().iter().filter(|p| p.starts_with(&format!("{me}:"))).cloned().collect();
    assert!(mine.is_empty(), "the server panicked (an abort in release builds): {mine:?}");
}

#[tokio::test]
async fn per_ip_and_total_caps() {
    // Defaults: 8 per IP.
    let h = WebHarness::start().await;
    let mut open = Vec::new();
    for _ in 0..8 {
        let mut w = h.open().await;
        assert_eq!(w.get(&h.host(), &css_path()).await.status, 200);
        open.push(w);
    }
    assert_refused_connection(&h).await;
    drop(open.remove(0));
    assert_accepted_eventually(&h).await;

    // 32 in total by default; a smaller total here so one IP can reach it.
    let h = WebHarness::start_with(|c| c.max_conn = 3).await;
    let mut open = Vec::new();
    for _ in 0..3 {
        let mut w = h.open().await;
        assert_eq!(w.get(&h.host(), &css_path()).await.status, 200);
        open.push(w);
    }
    assert_refused_connection(&h).await;
    drop(open.remove(0));
    assert_accepted_eventually(&h).await;
}

#[tokio::test]
async fn idle_server_has_no_pending_timers() {
    let h = WebHarness::start().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.clock.pending(), Vec::<Duration>::new(), "no timers without connections");

    // The server closes (Connection: close).
    let mut w = h.open().await;
    w.write(&request("GET", &css_path(), &h.host(), &["Connection: close"], b"")).await;
    let r = w.read_response(false).await.expect("response");
    assert_closes(&mut w, &r, "Connection: close").await;
    wait_no_pending(&h.clock, "after the server closed").await;

    // The client goes away during keep-alive.
    let mut w = h.open().await;
    assert_eq!(w.get(&h.host(), &css_path()).await.status, 200);
    drop(w);
    wait_no_pending(&h.clock, "after the client left a kept-alive connection").await;

    // The client goes away before TLS.
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    drop(tcp);
    wait_no_pending(&h.clock, "after a TCP connection without TLS").await;

    // A refused peer.
    let r = WebHarness::start_with(|c| c.is_allowed = |_| false).await;
    drop(Web::open(r.addr, net::client_tls(&r.pki)).await);
    wait_no_pending(&r.clock, "after a refused peer").await;
}
