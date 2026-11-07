//! Group E, session level: greeting, CAPABILITY, LOGIN / AUTHENTICATE PLAIN, wrong-state commands,
//! the pre-login BAD limit, LOGOUT, NOOP, autologout on the injected clock, connection caps,
//! plaintext / TLS 1.1 refused, line and literal limits .

mod harness;
mod net;

use std::time::Duration;

use harness::*;
use net::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USER: &str = "test@example.com";

#[tokio::test]
async fn config_defaults_match_the_design() {
    let pki = Pki::local();
    let tls = synology_mail_server::tls::server_config(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    let c = synology_mail_server::imap::ServerConfig::new(tls);
    assert_eq!(c.max_conn, 100);
    assert_eq!(c.max_conn_per_ip, 10);
    assert_eq!(c.max_line, 64 * 1024);
    assert_eq!(c.max_literal, 64 * 1024);
    assert_eq!(c.autologout, AUTOLOGOUT);
    assert_eq!(c.auth_failure_delay, AUTH_DELAY);
    assert_eq!(c.max_bad_before_login, 3);
}

#[tokio::test]
async fn greeting_and_capability_in_every_state() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    for (state, tag) in [("not authenticated", "C1"), ("authenticated", "C2"), ("selected", "C3")] {
        if tag == "C2" {
            c.cmd("L", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
        }
        if tag == "C3" {
            c.cmd("S", "SELECT INBOX").await.assert_ok();
        }
        let d = c.cmd(tag, "CAPABILITY").await;
        d.assert_ok();
        let caps = d.data("CAPABILITY");
        assert_eq!(caps.len(), 1, "{state}: one * CAPABILITY line:\n{}", d.transcript());
        let set: std::collections::BTreeSet<String> = caps[0][2..].iter().map(|t| t.atom().to_ascii_uppercase()).collect();
        assert_eq!(set, flags(&["IMAP4REV1", "AUTH=PLAIN"]).iter().map(|s| s.to_ascii_uppercase()).collect(), "{state}");
    }
}

#[tokio::test]
async fn noop_is_ok_in_every_state() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    c.cmd("N1", "NOOP").await.assert_ok();
    c.cmd("L", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
    c.cmd("N2", "noop").await.assert_ok();
    c.cmd("S", "SELECT INBOX").await.assert_ok();
    c.cmd("N3", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn login_with_quoted_strings_atoms_and_literals() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let pw = password(USER);

    let mut c = h.connect().await;
    c.cmd("A1", &format!("LOGIN \"{USER}\" \"{pw}\"")).await.assert_ok();
    c.cmd("A2", "LIST \"\" INBOX").await.assert_ok();

    let mut c = h.connect().await;
    c.cmd("B1", &format!("login {USER} {pw}")).await.assert_ok();

    // RFC 3501 6.2.3 with synchronizing literals: each `{n}` waits for `+` before the data.
    let mut c = h.connect().await;
    c.cmd_parts("C1", &[Part::Text("LOGIN "), Part::Lit(USER.as_bytes()), Part::Text(" "), Part::Lit(pw.as_bytes())])
        .await
        .assert_ok();
    c.cmd("C2", "SELECT INBOX").await.assert_ok();
}

#[tokio::test]
async fn failed_login_waits_two_seconds_on_the_clock_then_authenticationfailed() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    let mark = h.clock.mark();
    c.write(format!("F1 LOGIN {USER} wrong-password\r\n").as_bytes()).await;
    h.clock.wait_sleep_since(mark, AUTH_DELAY, "the failed-login delay").await;
    assert!(c.nothing_within(Duration::from_millis(200)).await, "no answer before the clock moves 2 s");

    // The delay is per connection: another client is served meanwhile.
    let mut other = h.connect().await;
    other.cmd("O1", "CAPABILITY").await.assert_ok();

    h.clock.advance(AUTH_DELAY);
    let d = c.read_until_tagged("F1").await;
    d.assert_no().assert_code("AUTHENTICATIONFAILED");
    // Still not authenticated, still usable.
    c.cmd("F2", "SELECT INBOX").await.assert_refused();
    c.cmd("F3", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
}

#[tokio::test]
async fn unknown_login_fails_the_same_way() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    let mark = h.clock.mark();
    c.write(b"U1 LOGIN nobody@example.com whatever\r\n").await;
    h.clock.wait_sleep_since(mark, AUTH_DELAY, "the failed-login delay (unknown login)").await;
    assert!(c.nothing_within(Duration::from_millis(200)).await);
    h.clock.advance(AUTH_DELAY);
    c.read_until_tagged("U1").await.assert_no().assert_code("AUTHENTICATIONFAILED");
}

#[tokio::test]
async fn authenticate_plain_success() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    c.write(b"P1 AUTHENTICATE PLAIN\r\n").await;
    let cont = c.read_response().await.unwrap();
    assert!(cont.starts_with(b"+"), "continuation expected, got {}", show(&cont));
    let resp = base64(format!("\0{USER}\0{}", password(USER)).as_bytes());
    c.write(format!("{resp}\r\n").as_bytes()).await;
    c.read_until_tagged("P1").await.assert_ok();
    c.cmd("P2", "SELECT INBOX").await.assert_ok();

    // authzid equal to the login is allowed too.
    let mut c = h.connect().await;
    c.write(b"P3 AUTHENTICATE PLAIN\r\n").await;
    assert!(c.read_response().await.unwrap().starts_with(b"+"));
    let resp = base64(format!("{USER}\0{USER}\0{}", password(USER)).as_bytes());
    c.write(format!("{resp}\r\n").as_bytes()).await;
    c.read_until_tagged("P3").await.assert_ok();
}

#[tokio::test]
async fn authenticate_plain_rejects_wrong_password_and_foreign_authzid() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    h.simple_account("other@example.com", 1);

    let mut c = h.connect().await;
    let mark = h.clock.mark();
    c.write(b"P1 AUTHENTICATE PLAIN\r\n").await;
    assert!(c.read_response().await.unwrap().starts_with(b"+"));
    c.write(format!("{}\r\n", base64(format!("\0{USER}\0nope").as_bytes())).as_bytes()).await;
    h.finish_auth(&mut c, "P1", mark).await.assert_no().assert_code("AUTHENTICATIONFAILED");

    // authzid must equal the login, even with the right password.
    let mut c = h.connect().await;
    let mark = h.clock.mark();
    c.write(b"P2 AUTHENTICATE PLAIN\r\n").await;
    assert!(c.read_response().await.unwrap().starts_with(b"+"));
    let resp = base64(format!("other@example.com\0{USER}\0{}", password(USER)).as_bytes());
    c.write(format!("{resp}\r\n").as_bytes()).await;
    h.finish_auth(&mut c, "P2", mark).await.assert_no();
    c.cmd("P3", "SELECT INBOX").await.assert_refused();
}

#[tokio::test]
async fn authenticate_plain_cancelled_with_star_is_bad() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    c.write(b"P1 AUTHENTICATE PLAIN\r\n").await;
    assert!(c.read_response().await.unwrap().starts_with(b"+"));
    c.write(b"*\r\n").await;
    c.read_until_tagged("P1").await.assert_bad();
    c.cmd("P2", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
}

#[tokio::test]
async fn authenticate_other_mechanism_is_refused() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    c.cmd("M1", "AUTHENTICATE CRAM-MD5").await.assert_refused();
}

#[tokio::test]
async fn commands_in_the_wrong_state_before_login_are_refused() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    // At most two refusals per connection: three BADs before login close it (tested below).
    let groups: [&[&str]; 4] = [
        &["SELECT INBOX", "EXAMINE INBOX"],
        &["LIST \"\" *", "STATUS INBOX (MESSAGES)"],
        &["FETCH 1 FLAGS", "STORE 1 +FLAGS (\\Seen)"],
        &["SEARCH ALL", "UID FETCH 1 FLAGS"],
    ];
    for cmds in groups {
        let mut c = h.connect().await;
        for (i, cmd) in cmds.iter().enumerate() {
            let d = c.cmd(&format!("W{i}"), cmd).await;
            d.assert_refused();
            assert!(d.data("LIST").is_empty() && d.data("STATUS").is_empty() && d.data("FETCH").is_empty(), "{cmd} leaked data");
        }
        c.cmd("W9", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
    }
}

#[tokio::test]
async fn commands_in_the_wrong_state_after_login_are_refused() {
    let h = Harness::start().await;
    h.simple_account(USER, 2);
    let mut c = h.login(USER).await;
    for (i, cmd) in [
        format!("LOGIN {USER} {}", password(USER)),
        "AUTHENTICATE PLAIN".to_string(),
        "FETCH 1 FLAGS".into(),
        "UID FETCH 1 FLAGS".into(),
        "STORE 1 +FLAGS (\\Seen)".into(),
        "SEARCH ALL".into(),
        "EXPUNGE".into(),
        "CLOSE".into(),
        "CHECK".into(),
        "COPY 1 INBOX".into(),
    ]
    .iter()
    .enumerate()
    {
        let d = c.cmd(&format!("X{i}"), cmd).await;
        d.assert_refused();
        assert!(d.data("FETCH").is_empty() && d.data("SEARCH").is_empty(), "{cmd} leaked data:\n{}", d.transcript());
    }
    // BADs after login never close the connection.
    c.cmd("X99", "SELECT INBOX").await.assert_ok();
    c.cmd("X100", "LOGIN a b").await.assert_refused();
}

#[tokio::test]
async fn three_bad_commands_before_login_close_the_connection() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.connect().await;
    c.cmd("B1", "FROBNICATE").await.assert_bad();
    c.cmd("B2", "LOGIN").await.assert_bad();
    c.write(b"B3 ???\r\n").await;
    let rest = c.expect_closed().await;
    let all = show_all(&rest);
    assert!(all.contains("BAD") || all.contains("BYE"), "third BAD (or BYE) before close, got:\n{all}");
}

#[tokio::test]
async fn bad_commands_after_login_do_not_close() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.login(USER).await;
    for i in 0..6 {
        c.cmd(&format!("B{i}"), "FROBNICATE now").await.assert_bad();
    }
    c.cmd("N", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn out_of_scope_extensions_are_refused() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.select(USER).await;
    for (i, cmd) in ["IDLE", "STARTTLS", "NAMESPACE", "ID NIL", "UNSELECT", "UID EXPUNGE 1", "MOVE 1 INBOX", "ENABLE CONDSTORE"]
        .iter()
        .enumerate()
    {
        c.cmd(&format!("E{i}"), cmd).await.assert_refused();
    }
    c.cmd("N", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn logout_sends_bye_then_ok_then_closes() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    for state in ["not authenticated", "authenticated", "selected"] {
        let mut c = match state {
            "not authenticated" => h.connect().await,
            "authenticated" => h.login(USER).await,
            _ => h.select(USER).await,
        };
        let d = c.cmd("Z1", "LOGOUT").await;
        d.assert_ok();
        assert!(
            d.untagged.iter().any(|l| l.to_ascii_uppercase().starts_with(b"* BYE")),
            "{state}: * BYE before the tagged OK:\n{}",
            d.transcript()
        );
        let after = c.expect_closed().await;
        assert!(after.is_empty(), "{state}: nothing after LOGOUT's OK, got:\n{}", show_all(&after));
    }
}

#[tokio::test]
async fn autologout_after_thirty_idle_minutes_with_activity_resetting_it() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mark = h.clock.mark();
    let mut c = h.select(USER).await;
    h.clock.wait_sleep_since(mark, AUTOLOGOUT, "autologout").await;

    h.clock.advance(Duration::from_secs(29 * 60));
    let mark = h.clock.mark();
    c.cmd("N1", "NOOP").await.assert_ok();
    h.clock.wait_sleep_since(mark, AUTOLOGOUT, "autologout re-armed after NOOP").await;

    // 58 min since login, 29 since the NOOP: still connected.
    h.clock.advance(Duration::from_secs(29 * 60));
    let mark = h.clock.mark();
    c.cmd("N2", "NOOP").await.assert_ok();
    h.clock.wait_sleep_since(mark, AUTOLOGOUT, "autologout re-armed after NOOP").await;

    h.clock.advance(AUTOLOGOUT + Duration::from_secs(1));
    let rest = c.expect_closed().await;
    assert!(
        rest.iter().any(|l| l.to_ascii_uppercase().starts_with(b"* BYE")),
        "autologout sends * BYE before closing, got:\n{}",
        show_all(&rest)
    );
}

#[tokio::test]
async fn autologout_applies_before_login_too() {
    let h = Harness::start().await;
    let mark = h.clock.mark();
    let mut c = h.connect().await;
    h.clock.wait_sleep_since(mark, AUTOLOGOUT, "pre-login autologout").await;
    assert!(c.nothing_within(Duration::from_millis(100)).await);
    h.clock.advance(AUTOLOGOUT + Duration::from_secs(1));
    c.expect_closed().await;
}

/// A connection over the cap gets no `* OK` greeting: `* BYE` or an immediate close.
async fn assert_refused_connection(h: &Harness) {
    match Client::open(h.addr, &h.pki).await {
        Err(_) => {}
        Ok(mut c) => match c.read_response().await {
            None => {}
            Some(r) => {
                assert!(r.to_ascii_uppercase().starts_with(b"* BYE"), "over the cap: * BYE or close, got {}", show(&r));
                c.expect_closed().await;
            }
        },
    }
}

async fn assert_accepted_eventually(h: &Harness) {
    let start = std::time::Instant::now();
    loop {
        if let Ok(mut c) = Client::open(h.addr, &h.pki).await
            && let Some(g) = c.read_response().await
            && g.starts_with(b"* OK")
        {
            return;
        }
        assert!(start.elapsed() < TIMEOUT, "a slot freed by a closed connection is never reused");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn per_ip_connection_cap() {
    let h = Harness::start_with(|c| {
        c.max_conn_per_ip = 3;
        c.max_conn = 100;
    })
    .await;
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(h.connect().await);
    }
    assert_refused_connection(&h).await;
    let mut first = open.remove(0);
    first.cmd("Z", "LOGOUT").await.assert_ok();
    drop(first);
    assert_accepted_eventually(&h).await;
}

#[tokio::test]
async fn total_connection_cap() {
    let h = Harness::start_with(|c| {
        c.max_conn_per_ip = 100;
        c.max_conn = 2;
    })
    .await;
    let a = h.connect().await;
    let _b = h.connect().await;
    assert_refused_connection(&h).await;
    drop(a);
    assert_accepted_eventually(&h).await;
}

#[tokio::test]
async fn stalled_tls_handshake_is_dropped_after_sixty_seconds_and_frees_its_slot() {
    let h = Harness::start_with(|c| {
        c.max_conn_per_ip = 1;
        c.max_conn = 100;
    })
    .await;
    let mark = h.clock.mark();
    let mut stalled = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    h.clock.wait_sleep_since(mark, Duration::from_secs(60), "the TLS handshake timeout").await;
    assert_refused_connection(&h).await;
    h.clock.advance(Duration::from_secs(61));
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(TIMEOUT, stalled.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))), "a silent client must be closed after the handshake timeout");
    assert_accepted_eventually(&h).await;
}

#[tokio::test]
async fn plaintext_imap_gets_no_imap_bytes() {
    let h = Harness::start().await;
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    // A plaintext server would greet first; an implicit-TLS one waits for a ClientHello.
    let mut buf = vec![0u8; 4096];
    let early = tokio::time::timeout(Duration::from_millis(300), tcp.read(&mut buf)).await;
    if let Ok(Ok(n)) = early {
        assert!(!buf[..n].starts_with(b"* "), "plaintext greeting sent: {}", show(&buf[..n]));
    }
    let _ = tcp.write_all(b"a1 CAPABILITY\r\na2 LOGIN test@example.com pw\r\n").await;
    let mut got = Vec::new();
    let closed = tokio::time::timeout(TIMEOUT, async {
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the server must close a plaintext connection");
    let text = String::from_utf8_lossy(&got).to_ascii_uppercase();
    assert!(!text.contains("* OK") && !text.contains("CAPABILITY") && !text.contains("A1 "), "IMAP answered in plaintext: {text}");
}

/// TLS 1.1 ClientHello by hand (rustls cannot send one): record 0x16 0x0301, client_version
/// 0x0302, TLS_RSA_WITH_AES_128_CBC_SHA + SCSV, no extensions.
fn tls11_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x02];
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x04, 0x00, 0x2f, 0x00, 0xff]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn tls_1_1_is_refused() {
    let h = Harness::start().await;
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    tcp.write_all(&tls11_client_hello()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(TIMEOUT, async {
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    // A ServerHello is a handshake record (0x16) whose first message type is 2.
    let server_hello = got.len() >= 6 && got[0] == 0x16 && got[5] == 0x02;
    assert!(!server_hello, "TLS 1.1 got a ServerHello: {:02x?}", &got[..got.len().min(16)]);
    assert!(got.is_empty() || got[0] == 0x15, "expected an alert or a close, got {:02x?}", &got[..got.len().min(16)]);
}

#[tokio::test]
async fn tls_1_2_and_1_3_are_accepted() {
    let h = Harness::start().await;
    let c12 = Client::open_with(h.addr, client_tls_versions(&h.pki, &[&rustls::version::TLS12])).await.expect("TLS 1.2");
    assert_eq!(c12.tls_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    let mut c12 = c12;
    assert!(c12.read_response().await.unwrap().starts_with(b"* OK"));
    let c13 = h.connect().await;
    assert_eq!(c13.tls_version(), Some(rustls::ProtocolVersion::TLSv1_3));
}

#[tokio::test]
async fn command_line_limit_is_64_kib() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.select(USER).await;
    // 60 000 bytes: under the limit, an ordinary (empty) search.
    let d = c.cmd("L1", &format!("SEARCH SUBJECT \"{}\"", "q".repeat(60_000))).await;
    d.assert_ok();
    assert_eq!(d.search(), Vec::<u32>::new());

    // 70 000 bytes: BAD, then the connection is closed.
    let _ = c.try_write(format!("L2 SEARCH SUBJECT \"{}\"\r\n", "q".repeat(70_000)).as_bytes()).await;
    let rest = c.expect_closed().await;
    let all = show_all(&rest);
    assert!(all.contains("BAD") || all.contains("BYE"), "over-size line: BAD before close, got:\n{all}");
    assert!(!all.contains("L2 OK"), "over-size line was executed");
}

#[tokio::test]
async fn literal_limit_is_64_kib() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.select(USER).await;
    let small = vec![b'q'; 60_000];
    let d = c.cmd_parts("T1", &[Part::Text("SEARCH SUBJECT "), Part::Lit(&small)]).await;
    d.assert_ok();
    assert_eq!(d.search(), Vec::<u32>::new());

    // Over-size literal: no `+` continuation, a BAD, then close.
    c.write(b"T2 SEARCH SUBJECT {70000}\r\n").await;
    let first = c.read_response().await;
    if let Some(r) = &first {
        assert!(!r.starts_with(b"+"), "over-size literal must not get a continuation");
    }
    let mut rest = first.into_iter().collect::<Vec<_>>();
    rest.extend(c.expect_closed().await);
    let all = show_all(&rest);
    assert!(all.contains("BAD"), "over-size literal: BAD before close, got:\n{all}");
}
