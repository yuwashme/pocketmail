//! inbound/worker_api.rs: the pull API client, contract v1 (and the v0 contract).
//! Runs against the fake Worker in tests/net.

mod net;
use net::*;

use std::path::Path;
use std::time::Duration;

use synology_mail_server::inbound::http::{HttpClient, HttpError};
use synology_mail_server::inbound::worker_api::{self, ApiError, Fetch, Listing, WorkerApi};

const MS: i64 = 1_773_576_000_123;

fn key(n: i64) -> String {
    format!("msg:{:013}:00000000-0000-4000-8000-{:012}", MS + n, n)
}

fn api_with(pki: &Pki, url: &str, token: &str) -> WorkerApi {
    WorkerApi::new(HttpClient::new(client_tls(pki)), url, token).unwrap()
}

async fn setup() -> (Pki, FakeWorker, WorkerApi) {
    let pki = Pki::local();
    let fake = FakeWorker::start(&pki, None).await;
    let api = api_with(&pki, &fake.url, TOKEN);
    (pki, fake, api)
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("no hang")
}

fn is_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p).unwrap().next().is_none()
}

#[test]
fn parse_key_accepts_only_the_contract_format() {
    assert_eq!(worker_api::parse_key(&key(0)), Some(MS));
    assert_eq!(worker_api::parse_key("msg:0000000000001:x"), Some(1));
    for bad in [
        "",
        "msg:",
        "msg:177357600012:x",   // 12 digits
        "msg:17735760001234:x", // 14 digits
        "msg:1773576000123",    // no id
        "msg:1773576000123:",   // empty id
        "msg:17735760001a3:x",
        "msg:+773576000123:x",
        "MSG:1773576000123:x",
        "foo:1773576000123:x",
    ] {
        assert_eq!(worker_api::parse_key(bad), None, "{bad:?}");
    }
}

#[test]
fn read_token_file_trims_and_refuses_empty() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pull_token");
    std::fs::write(&p, "  dummy-token \n").unwrap();
    assert_eq!(worker_api::read_token_file(&p).unwrap(), "dummy-token");
    std::fs::write(&p, " \n").unwrap();
    assert_eq!(
        worker_api::read_token_file(&p).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        worker_api::read_token_file(&dir.path().join("missing"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn new_refuses_a_plain_http_base_url() {
    let pki = Pki::local();
    let r = WorkerApi::new(
        HttpClient::new(client_tls(&pki)),
        "http://ssm-inbound.example.workers.dev",
        TOKEN,
    );
    assert!(matches!(r, Err(ApiError::Http(HttpError::InvalidUrl(_)))));
}

#[tokio::test]
async fn list_returns_ids_and_complete_with_one_bearer_request() {
    let (_pki, fake, api) = setup().await;
    fake.put(&key(1), "a@example.test", "test@example.com", b"one");
    fake.put(&key(2), "a@example.test", "test@example.com", b"two");
    let l = within(api.list()).await.unwrap();
    assert_eq!(
        l,
        Listing {
            ids: vec![key(1), key(2)],
            complete: true
        }
    );
    let reqs = fake.requests();
    assert_eq!(
        reqs.len(),
        1,
        "exactly one request per list (KV list quota)"
    );
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.as_str()),
        ("GET", "/messages")
    );
    assert_eq!(
        header(&reqs[0].headers, "authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

#[tokio::test]
async fn list_reports_incomplete_pages() {
    let (_pki, fake, api) = setup().await;
    for n in 1..=3 {
        fake.put(&key(n), "a@example.test", "test@example.com", b"x");
    }
    fake.with(|s| s.page_size = Some(2));
    assert_eq!(
        within(api.list()).await.unwrap(),
        Listing {
            ids: vec![key(1), key(2)],
            complete: false
        }
    );
}

#[tokio::test]
async fn v0_list_without_complete_counts_as_complete() {
    let (_pki, fake, api) = setup().await;
    fake.put(&key(1), "a@example.test", "test@example.com", b"x");
    fake.with(|s| s.v0 = true);
    assert_eq!(
        within(api.list()).await.unwrap(),
        Listing {
            ids: vec![key(1)],
            complete: true
        }
    );
}

#[tokio::test]
async fn base_url_trailing_slash_and_path_prefix() {
    let (pki, fake, _) = setup().await;
    within(api_with(&pki, &format!("{}/", fake.url), TOKEN).list())
        .await
        .unwrap();
    let _ = within(api_with(&pki, &format!("{}/pull", fake.url), TOKEN).list()).await; // fake answers 404 there
    let paths: Vec<String> = fake.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        vec!["/messages".to_string(), "/pull/messages".to_string()]
    );
}

#[tokio::test]
async fn list_errors_are_typed() {
    let (pki, fake, api) = setup().await;
    let wrong = api_with(&pki, &fake.url, "wrong-token");
    assert!(matches!(
        within(wrong.list()).await,
        Err(ApiError::Unauthorized)
    ));
    fake.with(|s| s.list_status = Some(503));
    assert!(matches!(
        within(api.list()).await,
        Err(ApiError::Status(503))
    ));
}

#[tokio::test]
async fn list_with_a_bad_body_is_a_bad_response() {
    let pki = Pki::local();
    for body in [
        "not json",
        r#"{"ids":"nope","complete":true}"#,
        r#"{"ids":[1,2],"complete":true}"#,
        r#"{"complete":true}"#,
        r#"{"ids":["msg:1773576000123:x"],"complete":"yes"}"#,
        r#"["msg:1773576000123:x"]"#,
    ] {
        let r = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let srv = serve_raw(&pki, r.into_bytes(), Close::Notify).await;
        let res = within(api_with(&pki, &srv.url, TOKEN).list()).await;
        assert!(
            matches!(res, Err(ApiError::BadResponse(_))),
            "{body}: {res:?}"
        );
    }
}

#[tokio::test]
async fn fetch_decodes_the_envelope_and_streams_the_body_to_tmp() {
    let (_pki, fake, api) = setup().await;
    let body = b"From: a@example.test\r\nSubject: hi\r\n\r\nhello\r\n";
    fake.put(
        &key(1),
        "bounce+x=y@example.test",
        "\u{161}ef@example.com",
        body,
    );
    let tmp = tempfile::tempdir().unwrap();
    let Fetch::Message(m) = within(api.fetch(&key(1), tmp.path())).await.unwrap() else {
        panic!("expected a message")
    };
    assert_eq!(m.envelope_from, "bounce+x=y@example.test");
    assert_eq!(m.envelope_to, "šef@example.com", "percent-decoded UTF-8");
    assert_eq!(m.size, body.len() as u64);
    assert_eq!(m.body.len(), body.len() as u64);
    assert!(
        m.body.path().starts_with(tmp.path()),
        "downloads go to the given tmp dir"
    );
    assert_eq!(std::fs::read(m.body.path()).unwrap(), body);
    let reqs = fake.requests();
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.clone()),
        ("GET", format!("/messages/{}", key(1)))
    );
    drop(m);
    assert!(is_empty_dir(tmp.path()));
}

#[tokio::test]
async fn fetch_keeps_the_null_sender_empty() {
    let (_pki, fake, api) = setup().await;
    fake.put(&key(1), "", "test@example.com", b"x");
    let tmp = tempfile::tempdir().unwrap();
    let Fetch::Message(m) = within(api.fetch(&key(1), tmp.path())).await.unwrap() else {
        panic!()
    };
    assert_eq!(m.envelope_from, "");
}

#[tokio::test]
async fn fetch_percent_encodes_the_id_in_the_path() {
    let (_pki, fake, api) = setup().await;
    let odd = format!("msg:{MS}:a b%2F?#");
    fake.put(&odd, "a@example.test", "test@example.com", b"odd");
    let tmp = tempfile::tempdir().unwrap();
    let Fetch::Message(m) = within(api.fetch(&odd, tmp.path())).await.unwrap() else {
        panic!("expected a message")
    };
    assert_eq!(std::fs::read(m.body.path()).unwrap(), b"odd");
}

#[tokio::test]
async fn fetch_404_is_gone_and_errors_are_typed_with_no_file_left() {
    let (pki, fake, api) = setup().await;
    fake.put(&key(2), "a@example.test", "test@example.com", b"x");
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        within(api.fetch(&key(1), tmp.path())).await,
        Ok(Fetch::Gone)
    ));
    assert!(is_empty_dir(tmp.path()));
    let wrong = api_with(&pki, &fake.url, "wrong-token");
    assert!(matches!(
        within(wrong.fetch(&key(2), tmp.path())).await,
        Err(ApiError::Unauthorized)
    ));
    assert!(is_empty_dir(tmp.path()));
    fake.with(|s| s.get_status.insert(key(2), 500));
    assert!(matches!(
        within(api.fetch(&key(2), tmp.path())).await,
        Err(ApiError::Status(500))
    ));
    assert!(is_empty_dir(tmp.path()));
}

#[tokio::test]
async fn fetch_checks_x_ssm_size() {
    let (_pki, fake, api) = setup().await;
    let tmp = tempfile::tempdir().unwrap();
    fake.put(&key(1), "a@example.test", "test@example.com", b"0123456789");
    fake.with(|s| s.kv.get_mut(&key(1)).unwrap().size_header = Some("999".into()));
    let res = within(api.fetch(&key(1), tmp.path())).await;
    assert!(
        matches!(
            res,
            Err(ApiError::SizeMismatch {
                expected: 999,
                actual: 10
            })
        ),
        "{res:?}"
    );
    assert!(is_empty_dir(tmp.path()), "no tmp file kept");
    fake.with(|s| s.kv.get_mut(&key(1)).unwrap().size_header = Some("ten".into()));
    assert!(matches!(
        within(api.fetch(&key(1), tmp.path())).await,
        Err(ApiError::BadResponse(_))
    ));
    assert!(is_empty_dir(tmp.path()));
}

#[tokio::test]
async fn v0_fetch_without_x_ssm_headers_gives_an_empty_envelope() {
    // The deployed v0 Worker sends no envelope or size headers: the message is still fetched
    // (the poller quarantines it, nothing is lost) and its size is the HTTP-framed body length.
    let (_pki, fake, api) = setup().await;
    fake.put(&key(1), "a@example.test", "test@example.com", b"legacy");
    fake.with(|s| s.v0 = true);
    let tmp = tempfile::tempdir().unwrap();
    let Fetch::Message(m) = within(api.fetch(&key(1), tmp.path())).await.unwrap() else {
        panic!()
    };
    assert_eq!(
        (m.envelope_from.as_str(), m.envelope_to.as_str(), m.size),
        ("", "", 6)
    );
}

#[tokio::test]
async fn fetch_with_bad_percent_encoding_is_a_bad_response() {
    let pki = Pki::local();
    let tmp = tempfile::tempdir().unwrap();
    for to in [
        "%zz@example.com",
        "%C5@example.com",
        "%FF%FE@example.com",
        "test%4@example.com",
    ] {
        let r = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-SSM-Size: 1\r\nX-SSM-Envelope-From: a%40example.test\r\nX-SSM-Envelope-To: {to}\r\n\r\nx"
        );
        let srv = serve_raw(&pki, r.into_bytes(), Close::Notify).await;
        let res = within(api_with(&pki, &srv.url, TOKEN).fetch(&key(1), tmp.path())).await;
        assert!(
            matches!(res, Err(ApiError::BadResponse(_))),
            "{to}: {res:?}"
        );
        assert!(is_empty_dir(tmp.path()), "{to}");
    }
}

#[tokio::test]
async fn delete_is_ok_on_204_even_for_a_missing_id() {
    let (pki, fake, api) = setup().await;
    fake.put(&key(1), "a@example.test", "test@example.com", b"x");
    within(api.delete(&key(1))).await.unwrap();
    assert!(fake.keys().is_empty());
    within(api.delete(&key(1))).await.unwrap();
    assert_eq!(fake.count("DELETE", &format!("/messages/{}", key(1))), 2);
    fake.with(|s| s.delete_failures.insert(key(2), u32::MAX));
    assert!(matches!(
        within(api.delete(&key(2))).await,
        Err(ApiError::Status(500))
    ));
    let wrong = api_with(&pki, &fake.url, "wrong-token");
    assert!(matches!(
        within(wrong.delete(&key(3))).await,
        Err(ApiError::Unauthorized)
    ));
}
