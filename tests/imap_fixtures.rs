//! Self-checks for the IMAP test harness and the hand-written goldens (no server involved): these
//! pass before the server exists, so a later failure in tests/imap_*.rs points at the server.

mod harness;
mod net;

use std::time::Duration;

use harness::*;
use net::*;
use synology_mail_server::imap::Clock;

#[test]
fn goldens_are_well_formed_and_agree_with_the_fixtures() {
    for name in FIXTURES {
        let env = golden(name, "envelope");
        assert_eq!(
            env.list().len(),
            10,
            "{name}.envelope has the 10 RFC 3501 fields"
        );
        for (i, f) in env.list().iter().enumerate().skip(2).take(6) {
            assert!(
                f.is_nil() || f.list().iter().all(|a| a.list().len() == 4),
                "{name}.envelope field {i}: address lists"
            );
        }
        let bs = golden(name, "bodystructure");
        // Single-part text: size and line count must match the raw fixture body.
        if let Tok::Str(t) = &bs.list()[0]
            && t.eq_ignore_ascii_case(b"TEXT")
        {
            let body = split_message(&fixture(name)).1;
            assert_eq!(
                bs.list()[6],
                Tok::Atom(body.len().to_string()),
                "{name}: size"
            );
            assert_eq!(
                bs.list()[7],
                Tok::Atom(body.iter().filter(|&&b| b == b'\n').count().to_string()),
                "{name}: lines"
            );
            assert_eq!(
                bs.list().len(),
                12,
                "{name}: text part with md5 dsp lang loc"
            );
        }
    }
    for name in ["01-plain", "03-mixed", "04-rfc822"] {
        golden(name, "body");
    }
    // The fixtures are stored byte-exact (CRLF, except the bare-LF one).
    let lf = fixture("10-barelf");
    assert!(!lf.contains(&b'\r'));
    let crlf = fixture("01-plain");
    assert!(
        crlf.windows(2).filter(|w| w == b"\r\n").count()
            == crlf.iter().filter(|&&b| b == b'\n').count()
    );
}

#[test]
fn tokenizer_handles_quotes_literals_sections_and_nil() {
    let line = b"* 3 FETCH (UID 3 BODY[HEADER.FIELDS (SUBJECT FROM)]<0> {5}\r\nab\"c)\r\n FLAGS (\\Seen $x) ENVELOPE (NIL \"q\\\"t\" nil))\r\n";
    let t = tokenize(line);
    assert_eq!(t[0], Tok::Atom("*".into()));
    assert_eq!(t[2], Tok::Atom("FETCH".into()));
    let items = t[3].list();
    assert_eq!(
        items[2],
        Tok::Atom("BODY[HEADER.FIELDS (SUBJECT FROM)]<0>".into())
    );
    assert_eq!(items[3], Tok::Str(b"ab\"c)".to_vec()));
    assert_eq!(flag_set(&items[5]), flags(&["\\seen", "$x"]));
    assert_eq!(
        items[7].list(),
        &[Tok::Nil, Tok::Str(b"q\"t".to_vec()), Tok::Nil]
    );
    assert_eq!(
        norm_key("body[header.fields (\"Subject\"  From)]"),
        "BODY[HEADER.FIELDS (SUBJECT FROM)]"
    );
    assert!(tok_eq(
        &tokenize(b"(\"TEXT\" 1)")[0],
        &tokenize(b"(\"text\" 1)")[0],
        true
    ));
    assert!(!tok_eq(
        &tokenize(b"(\"TEXT\" 1)")[0],
        &tokenize(b"(\"text\" 1)")[0],
        false
    ));
}

#[test]
fn base64_vectors() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"\0a\0b"), "AGEAYg==");
}

#[tokio::test]
async fn manual_clock_only_moves_when_advanced() {
    let clock = ManualClock::new();
    let mark = clock.mark();
    let c2 = clock.clone();
    let t = tokio::spawn(async move { c2.sleep(Duration::from_secs(60)).await });
    clock
        .wait_sleep_since(mark, Duration::from_secs(60), "test sleep")
        .await;
    clock.advance(Duration::from_secs(59));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!t.is_finished());
    clock.advance(Duration::from_secs(1));
    tokio::time::timeout(Duration::from_secs(1), t)
        .await
        .unwrap()
        .unwrap();
    assert!(
        clock.pending().is_empty(),
        "completed sleeps are no longer pending"
    );
    assert_eq!(clock.now(), Duration::from_secs(60));
    // A dropped sleep is removed too.
    drop(clock.sleep(Duration::from_secs(5)));
    assert!(clock.pending().is_empty());
}

/// A scripted TLS "server" that greets, then answers each complete command (literals included,
/// with `+` continuations) from `script` by tag, closing after LOGOUT.
async fn scripted(pki: &Pki, script: Vec<(&'static str, Vec<u8>)>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = server_tls(pki);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut s = tokio_rustls::TlsAcceptor::from(tls)
            .accept(tcp)
            .await
            .unwrap();
        s.write_all(b"* OK scripted\r\n").await.unwrap();
        let mut cmd = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if s.read(&mut b).await.unwrap_or(0) == 0 {
                return;
            }
            cmd.push(b[0]);
            if !cmd.ends_with(b"\r\n") {
                continue;
            }
            if cmd.ends_with(b"}\r\n") {
                let open = cmd.iter().rposition(|&c| c == b'{').unwrap();
                let n: usize = std::str::from_utf8(&cmd[open + 1..cmd.len() - 3])
                    .unwrap()
                    .parse()
                    .unwrap();
                s.write_all(b"+ go\r\n").await.unwrap();
                let mut lit = vec![0u8; n];
                s.read_exact(&mut lit).await.unwrap();
                cmd.extend_from_slice(&lit);
                continue;
            }
            let tag = String::from_utf8_lossy(&cmd[..cmd.iter().position(|&c| c == b' ').unwrap()])
                .to_string();
            let (_, reply) = script
                .iter()
                .find(|(t, _)| *t == tag)
                .expect("scripted tag");
            s.write_all(reply).await.unwrap();
            if tag == "Z" {
                let _ = s.shutdown().await;
                return;
            }
            cmd.clear();
        }
    });
    addr
}

#[tokio::test]
async fn client_reads_literals_continuations_and_close() {
    let pki = Pki::local();
    let addr = scripted(
        &pki,
        vec![
            ("A1", b"* 1 FETCH (UID 1 BODY[] {5}\r\nab\r\nc FLAGS (\\Seen))\r\n* 1 FETCH (RFC822.SIZE 5)\r\nA1 OK done\r\n".to_vec()),
            ("A2", b"A2 NO [AUTHENTICATIONFAILED] nope\r\n".to_vec()),
            ("A3", b"* SEARCH\r\nA3 OK\r\n".to_vec()),
            ("Z", b"* BYE bye\r\nZ OK\r\n".to_vec()),
        ],
    )
    .await;
    let mut c = Client::open(addr, &pki).await.unwrap();
    assert!(c.read_response().await.unwrap().starts_with(b"* OK"));

    let d = c.cmd("A1", "FETCH 1 (BODY[] RFC822.SIZE)").await;
    d.assert_ok();
    let m = d.fetch_map();
    assert_eq!(m[&1].bytes("BODY[]"), b"ab\r\nc");
    assert_eq!(m[&1].num("RFC822.SIZE"), 5);
    assert_eq!(m[&1].flags(), flags(&["\\Seen"]));

    let d = c
        .cmd_parts(
            "A2",
            &[
                Part::Text("LOGIN "),
                Part::Lit(b"user"),
                Part::Text(" "),
                Part::Lit(b"pass"),
            ],
        )
        .await;
    d.assert_no().assert_code("AUTHENTICATIONFAILED");

    assert_eq!(
        c.cmd("A3", "SEARCH DELETED").await.search(),
        Vec::<u32>::new()
    );

    let d = c.cmd("Z", "LOGOUT").await;
    d.assert_ok();
    assert!(d.untagged[0].starts_with(b"* BYE"));
    assert!(c.expect_closed().await.is_empty());
}
