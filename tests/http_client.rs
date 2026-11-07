//! inbound/http.rs: the hand-written HTTP/1.1 client.
//! Each test runs a one-shot HTTPS server on 127.0.0.1 that writes a raw response, so every
//! framing case of RFC 9112 section 6.3 can be produced exactly.

mod net;
use net::*;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use synology_mail_server::inbound::http::{HttpClient, HttpError, MAX_HEAD_BYTES, Method};

const LIMIT: u64 = 1 << 20;

fn client(pki: &Pki) -> HttpClient {
    HttpClient::new(client_tls(pki))
}

/// Guard so an implementation that waits for something that never comes fails instead of hanging.
async fn within<T>(secs: u64, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), f).await.expect("client must not hang")
}

async fn get(pki: &Pki, response: &[u8], close: Close) -> Result<(u16, Vec<u8>), HttpError> {
    let srv = serve_raw(pki, response.to_vec(), close).await;
    within(5, client(pki).send(Method::Get, &format!("{}/x", srv.url), &[], LIMIT))
        .await
        .map(|(h, b)| (h.status, b))
}

#[tokio::test]
async fn content_length_body_and_the_request_it_sends() {
    let pki = Pki::local();
    let srv = serve_raw(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: a\r\n\r\nhello".to_vec(), Close::Notify).await;
    let (head, body) = within(
        5,
        client(&pki).send(Method::Get, &format!("{}/messages", srv.url), &[("Authorization", "Bearer t0k")], LIMIT),
    )
    .await
    .unwrap();
    assert_eq!(head.status, 200);
    assert_eq!(body, b"hello");
    assert_eq!(head.header("x-test"), Some("a"), "header lookup is case-insensitive");
    assert_eq!(head.header("X-TEST"), Some("a"));
    assert_eq!(head.header("x-missing"), None);

    let raw = srv.request.await.unwrap();
    assert!(raw.starts_with(b"GET /messages HTTP/1.1\r\n"), "{:?}", String::from_utf8_lossy(&raw));
    let (_, _, hs) = parse_request(&raw);
    assert_eq!(header(&hs, "host"), Some(format!("127.0.0.1:{}", srv.addr.port()).as_str()));
    assert_eq!(header(&hs, "connection").map(str::to_ascii_lowercase), Some("close".into()));
    assert_eq!(header(&hs, "authorization"), Some("Bearer t0k"));
    assert_eq!(header(&hs, "accept-encoding"), None, "no compression: bodies are stored byte-exact");
    assert_eq!(hs.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).count(), 1);
}

#[tokio::test]
async fn delete_sends_the_delete_method() {
    let pki = Pki::local();
    let srv = serve_raw(&pki, b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), Close::Notify).await;
    let (head, body) = within(5, client(&pki).send(Method::Delete, &format!("{}/messages/k1", srv.url), &[], LIMIT)).await.unwrap();
    assert_eq!((head.status, body.len()), (204, 0));
    assert!(srv.request.await.unwrap().starts_with(b"DELETE /messages/k1 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn content_length_body_is_complete_without_close_notify_or_close() {
    // RFC 9112 9.8: a response with as much data as Content-Length says is complete, even if the
    // TLS connection then ends without close_notify, and the client must not wait for the close.
    let pki = Pki::local();
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    assert_eq!(get(&pki, ok, Close::Abrupt).await.unwrap(), (200, b"hello".to_vec()));
    assert_eq!(get(&pki, ok, Close::KeepOpen(Duration::from_secs(30))).await.unwrap(), (200, b"hello".to_vec()));
}

#[tokio::test]
async fn short_content_length_body_is_truncated() {
    let pki = Pki::local();
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
    assert!(matches!(get(&pki, short, Close::Notify).await, Err(HttpError::Truncated)));
    assert!(matches!(get(&pki, short, Close::Abrupt).await, Err(HttpError::Truncated)));
}

#[tokio::test]
async fn chunked_body() {
    let pki = Pki::local();
    let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    assert_eq!(get(&pki, r, Close::Notify).await.unwrap(), (200, b"hello world".to_vec()));
}

#[tokio::test]
async fn chunked_body_with_extensions_uppercase_hex_and_trailers() {
    let pki = Pki::local();
    let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    r.extend_from_slice(b"A;name=value\r\n0123456789\r\n");
    r.extend_from_slice(b"1a ; q=\"x;y\"\r\nabcdefghijklmnopqrstuvwxyz\r\n");
    r.extend_from_slice(b"0;last\r\nX-Trailer: t\r\nX-Other: o\r\n\r\n");
    let (_, body) = get(&pki, &r, Close::Notify).await.unwrap();
    assert_eq!(body, b"0123456789abcdefghijklmnopqrstuvwxyz");
}

#[tokio::test]
async fn chunked_body_is_complete_at_the_last_chunk_without_waiting_for_close() {
    let pki = Pki::local();
    let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
    assert_eq!(get(&pki, r, Close::KeepOpen(Duration::from_secs(30))).await.unwrap(), (200, b"ok".to_vec()));
}

#[tokio::test]
async fn chunked_body_without_last_chunk_is_truncated() {
    let pki = Pki::local();
    let no_last = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    assert!(matches!(get(&pki, no_last, Close::Notify).await, Err(HttpError::Truncated)));
    let short_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nhello";
    assert!(matches!(get(&pki, short_chunk, Close::Abrupt).await, Err(HttpError::Truncated)));
}

#[tokio::test]
async fn bad_chunk_sizes_are_malformed() {
    let pki = Pki::local();
    let not_hex = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n";
    assert!(matches!(get(&pki, not_hex, Close::Notify).await, Err(HttpError::Malformed(_))));
    // 2^80: must be an error, not an overflow panic or a giant allocation.
    let huge = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000000000000000000\r\nhello\r\n0\r\n\r\n";
    assert!(matches!(get(&pki, huge, Close::Notify).await, Err(HttpError::Malformed(_))));
}

#[tokio::test]
async fn close_delimited_body_needs_close_notify() {
    // No Content-Length, no chunked: the body runs to the close (RFC 9112 6.3 rule 8), and is only
    // complete with a TLS closure alert (RFC 9112 9.8); a bare TCP close may be a truncation.
    let pki = Pki::local();
    let r = b"HTTP/1.1 200 OK\r\nContent-Type: message/rfc822\r\n\r\nhello world";
    assert_eq!(get(&pki, r, Close::Notify).await.unwrap(), (200, b"hello world".to_vec()));
    assert!(matches!(get(&pki, r, Close::Abrupt).await, Err(HttpError::Truncated)));
}

#[tokio::test]
async fn status_204_has_no_body_even_if_the_server_keeps_the_connection_open() {
    let pki = Pki::local();
    let r = b"HTTP/1.1 204 No Content\r\n\r\n";
    assert_eq!(get(&pki, r, Close::KeepOpen(Duration::from_secs(30))).await.unwrap(), (204, Vec::new()));
}

#[tokio::test]
async fn non_2xx_status_is_a_response_not_an_error() {
    let pki = Pki::local();
    let r = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy";
    assert_eq!(get(&pki, r, Close::Notify).await.unwrap(), (503, b"busy".to_vec()));
}

#[tokio::test]
async fn conflicting_content_lengths_are_malformed() {
    // RFC 9112 6.3 rule 5: an invalid Content-Length is an unrecoverable error.
    let pki = Pki::local();
    let two = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    assert!(matches!(get(&pki, two, Close::Notify).await, Err(HttpError::Malformed(_))));
    let list = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello!";
    assert!(matches!(get(&pki, list, Close::Notify).await, Err(HttpError::Malformed(_))));
    let neg = b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nhello";
    assert!(matches!(get(&pki, neg, Close::Notify).await, Err(HttpError::Malformed(_))));
}

#[tokio::test]
async fn garbage_status_line_is_malformed() {
    let pki = Pki::local();
    assert!(matches!(get(&pki, b"220 smtp.example ESMTP\r\n\r\n", Close::Notify).await, Err(HttpError::Malformed(_))));
}

#[tokio::test]
async fn header_block_is_capped_at_64_kib() {
    let pki = Pki::local();
    let big = |n: usize| {
        let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec();
        r.extend_from_slice(format!("X-Big: {}\r\n\r\nok", "a".repeat(n)).as_bytes());
        r
    };
    // Just under the cap is fine...
    assert_eq!(get(&pki, &big(MAX_HEAD_BYTES - 1024), Close::Notify).await.unwrap(), (200, b"ok".to_vec()));
    // ...over it is refused, without reading on forever.
    assert!(matches!(get(&pki, &big(MAX_HEAD_BYTES + 1024), Close::Notify).await, Err(HttpError::HeadTooLarge)));
    assert!(matches!(get(&pki, &big(4 * MAX_HEAD_BYTES), Close::KeepOpen(Duration::from_secs(30))).await, Err(HttpError::HeadTooLarge)));
}

#[tokio::test]
async fn body_over_max_body_is_refused() {
    let pki = Pki::local();
    let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n".to_vec();
    r.extend_from_slice(&[b'x'; 2000]);
    let srv = serve_raw(&pki, r, Close::Notify).await;
    let res = within(5, client(&pki).send(Method::Get, &format!("{}/x", srv.url), &[], 1000)).await;
    assert!(matches!(res, Err(HttpError::BodyTooLarge { limit: 1000 })), "{res:?}");
}

#[tokio::test]
async fn untrusted_certificate_is_a_tls_error() {
    let pki = Pki::local();
    let stranger = Pki::local();
    let srv = serve_raw(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(), Close::Notify).await;
    let res = within(5, client(&stranger).send(Method::Get, &format!("{}/x", srv.url), &[], LIMIT)).await;
    assert!(matches!(res, Err(HttpError::Tls(_))), "{res:?}");
}

#[tokio::test]
async fn wrong_host_name_is_a_tls_error() {
    // Trusted CA, but the certificate is for worker.example, not 127.0.0.1.
    let pki = Pki::new(&["worker.example"]);
    let srv = serve_raw(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(), Close::Notify).await;
    let res = within(5, client(&pki).send(Method::Get, &format!("{}/x", srv.url), &[], LIMIT)).await;
    assert!(matches!(res, Err(HttpError::Tls(_))), "{res:?}");
}

#[tokio::test]
async fn connection_refused_is_an_io_error() {
    let pki = Pki::local();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let res = within(5, client(&pki).send(Method::Get, &format!("https://127.0.0.1:{port}/x"), &[], LIMIT)).await;
    assert!(matches!(res, Err(HttpError::Io(_))), "{res:?}");
}

#[tokio::test]
async fn stalled_server_hits_the_idle_timeout() {
    let pki = Pki::local();
    let srv = serve_raw(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec(), Close::KeepOpen(Duration::from_secs(30))).await;
    let c = client(&pki).with_idle_timeout(Duration::from_millis(300));
    let t = std::time::Instant::now();
    let res = within(5, c.send(Method::Get, &format!("{}/x", srv.url), &[], LIMIT)).await;
    assert!(matches!(res, Err(HttpError::Timeout)), "{res:?}");
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn invalid_urls_are_refused_before_connecting() {
    let pki = Pki::local();
    let c = client(&pki);
    for url in [
        "",
        "http://127.0.0.1/messages", // the pull is HTTPS only
        "ftp://127.0.0.1/x",
        "https://",
        "https:///messages",
        "https://127.0.0.1:99999/x",
        "https://127.0.0.1:abc/x",
        "https://user@127.0.0.1/x",
        "127.0.0.1/messages",
    ] {
        let res = within(5, c.send(Method::Get, url, &[], LIMIT)).await;
        assert!(matches!(res, Err(HttpError::InvalidUrl(_))), "{url:?}: {res:?}");
    }
}

#[tokio::test]
async fn get_to_file_streams_the_body_into_a_0600_file_deleted_on_drop() {
    let pki = Pki::local();
    let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(&body);
    let srv = serve_raw(&pki, r, Close::Notify).await;
    let dir = tempfile::tempdir().unwrap();
    let (head, file) = within(5, client(&pki).get_to_file(&format!("{}/m", srv.url), &[], dir.path())).await.unwrap();
    assert_eq!(head.status, 200);
    assert_eq!(file.len(), body.len() as u64);
    assert!(file.path().starts_with(dir.path()));
    assert_eq!(std::fs::read(file.path()).unwrap(), body);
    let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mail is private: files 0600");
    let mut via_open = Vec::new();
    std::io::Read::read_to_end(&mut file.open().unwrap(), &mut via_open).unwrap();
    assert_eq!(via_open, body);
    drop(file);
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none(), "file removed on drop");
}

#[tokio::test]
async fn get_to_file_dechunks() {
    let pki = Pki::local();
    let r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nSubjec\r\n4;x=y\r\nt: a\r\n0\r\n\r\n";
    let srv = serve_raw(&pki, r.to_vec(), Close::Notify).await;
    let dir = tempfile::tempdir().unwrap();
    let (_, file) = within(5, client(&pki).get_to_file(&format!("{}/m", srv.url), &[], dir.path())).await.unwrap();
    assert_eq!(std::fs::read(file.path()).unwrap(), b"Subject: a");
}

#[tokio::test]
async fn get_to_file_keeps_no_file_when_the_body_is_truncated() {
    let pki = Pki::local();
    let dir = tempfile::tempdir().unwrap();
    let cases: Vec<(Vec<u8>, Close)> = vec![
        ([b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n".as_slice(), &[b'x'; 50_000]].concat(), Close::Abrupt),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".to_vec(), Close::Notify),
        (b"HTTP/1.1 200 OK\r\n\r\nclose-delimited, no close_notify".to_vec(), Close::Abrupt),
    ];
    for (r, close) in cases {
        let srv = serve_raw(&pki, r, close).await;
        let res = within(5, client(&pki).get_to_file(&format!("{}/m", srv.url), &[], dir.path())).await;
        assert!(matches!(res, Err(HttpError::Truncated)), "{close:?}: {res:?}");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none(), "no partial file kept ({close:?})");
    }
}
