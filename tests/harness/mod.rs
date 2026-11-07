//! Shared harness for the IMAP transcript tests. A real `imap::ImapServer` runs in-process on 127.0.0.1 with TLS
//! from `tls::server_config` and a test certificate generated at test time; the tests speak raw
//! IMAP lines to it over a rustls client. Time is a `ManualClock` the test advances by hand.
//!
//! Responses are checked with the small tokenizer below (atoms, NIL, quoted strings, literals,
//! lists), so quoted-vs-literal strings and the order of FETCH items do not matter, but every
//! value does. It is test code only: no IMAP parser crate is used or assumed.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::client::TlsStream;

use synology_mail_server::imap::{Clock, ImapServer, ServerConfig};
use synology_mail_server::store::Delivery;
use synology_mail_server::store::{DeliveryOutcome, FlagOp, Flags, MailboxId, Store};
use synology_mail_server::time::parse_imap_datetime;

use crate::net::{Pki, client_tls};

/// Real-time limit for any single wait on the server. A stub or a hang fails, never blocks.
pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const ENVELOPE_FROM: &str = "sender@example.test";
pub const AUTOLOGOUT: Duration = Duration::from_secs(30 * 60);
pub const AUTH_DELAY: Duration = Duration::from_secs(2);

pub fn password(login: &str) -> String {
    format!("pw-{login}")
}

/// Unix ms of an RFC 3501 date-time such as "01-Mar-2026 12:00:00 +0000".
pub fn ms(date_time: &str) -> i64 {
    parse_imap_datetime(date_time).expect("valid date-time") * 1000
}

// // Manual clock

/// A clock that only moves when the test calls `advance`. `sleep(d)` completes once `now()` has
/// reached the time of the call plus `d`. Sleeps that are still pending can be inspected, so a
/// test knows the server is waiting before it moves time.
pub struct ManualClock {
    now: watch::Sender<Duration>,
    _rx: watch::Receiver<Duration>,
    pending: Mutex<Vec<(u64, Duration)>>,
    next: AtomicU64,
}

struct PendingGuard<'a> {
    clock: &'a ManualClock,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.clock
            .pending
            .lock()
            .unwrap()
            .retain(|(id, _)| *id != self.id);
    }
}

impl ManualClock {
    pub fn new() -> Arc<ManualClock> {
        let (now, rx) = watch::channel(Duration::ZERO);
        Arc::new(ManualClock {
            now,
            _rx: rx,
            pending: Mutex::new(Vec::new()),
            next: AtomicU64::new(0),
        })
    }

    pub fn advance(&self, d: Duration) {
        self.now.send_modify(|t| *t += d);
    }

    /// Durations of the sleeps that have not completed yet.
    pub fn pending(&self) -> Vec<Duration> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(_, d)| *d)
            .collect()
    }

    /// Id the next `sleep` call will get. Take it before an action, then `wait_sleep_since` to know
    /// the server has armed a timer *after* that action (no race with a timer it is replacing).
    pub fn mark(&self) -> u64 {
        self.next.load(Ordering::SeqCst)
    }

    /// Is a sleep of exactly `d`, started at or after `mark`, pending now?
    pub fn has_sleep_since(&self, mark: u64, d: Duration) -> bool {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .any(|(id, p)| *id >= mark && *p == d)
    }

    /// Wait (real time) until a sleep of exactly `d`, started at or after `mark`, is pending.
    /// Panics after TIMEOUT with the pending list: every server timer must use the injected Clock.
    pub async fn wait_sleep_since(&self, mark: u64, d: Duration, what: &str) {
        let start = std::time::Instant::now();
        loop {
            if self
                .pending
                .lock()
                .unwrap()
                .iter()
                .any(|(id, p)| *id >= mark && *p == d)
            {
                return;
            }
            assert!(
                start.elapsed() < TIMEOUT,
                "the server never called Clock::sleep({d:?}) for {what} (pending: {:?}); all server \
                 timers must use the Clock passed to ImapServer::start",
                self.pending()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        *self.now.borrow()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let mut rx = self.now.subscribe();
        let deadline = rx.borrow().checked_add(d);
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.pending.lock().unwrap().push((id, d));
        let guard = PendingGuard { clock: self, id };
        Box::pin(async move {
            let _guard = guard;
            let Some(deadline) = deadline else {
                return std::future::pending().await;
            };
            loop {
                if *rx.borrow_and_update() >= deadline {
                    return;
                }
                if rx.changed().await.is_err() {
                    return std::future::pending().await;
                }
            }
        })
    }
}

// // Server harness

pub struct Harness {
    pub tmp: tempfile::TempDir,
    pub store: Arc<Store>,
    pub clock: Arc<ManualClock>,
    pub pki: Pki,
    pub addr: SocketAddr,
    pub server: ImapServer,
    seq: AtomicU64,
}

impl Harness {
    pub async fn start() -> Harness {
        Harness::start_with(|_| {}).await
    }

    /// Default `ServerConfig::new` (the design's limits), then `tweak`.
    pub async fn start_with(tweak: impl FnOnce(&mut ServerConfig)) -> Harness {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&tmp.path().join("data")).unwrap());
        let pki = Pki::local();
        let tls = synology_mail_server::tls::server_config(
            pki.cert_pem.as_bytes(),
            pki.key_pem.as_bytes(),
        )
        .unwrap();
        let mut config = ServerConfig::new(tls);
        tweak(&mut config);
        let clock = ManualClock::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = ImapServer::start(listener, store.clone(), config, clock.clone()).unwrap();
        let addr = server.local_addr();
        Harness {
            tmp,
            store,
            clock,
            pki,
            addr,
            server,
            seq: AtomicU64::new(1),
        }
    }

    /// Account `login` (password `password(login)`) with address `login`; returns its INBOX.
    pub fn account(&self, login: &str) -> MailboxId {
        let id = self.store.create_account(login, &password(login)).unwrap();
        self.store.add_address(login, login).unwrap();
        self.store
            .find_mailbox(id, "INBOX")
            .unwrap()
            .expect("INBOX")
            .id
    }

    /// Deliver `body` to `login` through the store; returns the new UID.
    pub fn deliver(&self, login: &str, body: &[u8], received_ms: i64) -> u32 {
        let n = self.seq.fetch_add(1, Ordering::SeqCst);
        let key = format!("msg:{received_ms:013}:00000000-0000-4000-8000-{n:012}");
        let d = Delivery {
            key: &key,
            envelope_from: ENVELOPE_FROM,
            envelope_to: login,
            received_ms,
            expected_size: body.len() as u64,
        };
        match self.store.deliver(&d, &mut &body[..]).unwrap() {
            DeliveryOutcome::Delivered { uid, .. } => uid,
            other => panic!("expected delivery, got {other:?}"),
        }
    }

    pub fn set_flags(&self, mailbox: MailboxId, uid: u32, flags: Flags) {
        self.store
            .store_flags(mailbox, &[uid], FlagOp::Replace, flags)
            .unwrap();
    }

    /// The stored message exactly as the server must serve it (Return-Path included).
    pub fn blob(&self, mailbox: MailboxId, uid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        self.store
            .open_message(mailbox, uid)
            .unwrap()
            .read_to_end_sync(&mut v);
        v
    }

    pub fn stored_flags(&self, mailbox: MailboxId, uid: u32) -> Flags {
        self.store
            .messages(mailbox)
            .unwrap()
            .into_iter()
            .find(|m| m.uid == uid)
            .expect("uid exists")
            .flags
    }

    pub fn uidvalidity(&self, mailbox: MailboxId) -> u32 {
        self.store.mailbox(mailbox).unwrap().uidvalidity
    }

    /// TLS connection whose greeting has been read and checked (`* OK`).
    pub async fn connect(&self) -> Client {
        let mut c = Client::open(self.addr, &self.pki)
            .await
            .expect("TLS handshake");
        let g = c.read_response().await.expect("greeting");
        assert!(
            g.starts_with(b"* OK"),
            "greeting must be * OK, got {}",
            show(&g)
        );
        c
    }

    pub async fn login(&self, login: &str) -> Client {
        let mut c = self.connect().await;
        c.cmd("L1", &format!("LOGIN \"{login}\" \"{}\"", password(login)))
            .await
            .assert_ok();
        c
    }

    pub async fn select(&self, login: &str) -> Client {
        let mut c = self.login(login).await;
        c.cmd("S1", "SELECT INBOX").await.assert_ok();
        c
    }

    //     // Mailbox setups

    /// "test@example.com" with every fixture of tests/fixtures/mail delivered in `FIXTURES` order
    /// (UID i+1, INTERNALDATE `fixture_received_ms(i)`), no flags, none claimed as \Recent.
    pub fn fixtures_account(&self) -> MailboxId {
        let mb = self.account(FIXTURE_LOGIN);
        for (i, name) in FIXTURES.iter().enumerate() {
            let uid = self.deliver(FIXTURE_LOGIN, &fixture(name), fixture_received_ms(i));
            assert_eq!(uid as usize, i + 1);
        }
        mb
    }

    /// "search@example.com": the six messages of `search_messages()`, flags set, 1-4 already claimed
    /// as \Recent by an earlier session (so only 5 and 6 are \Recent for the next SELECT).
    pub fn search_account(&self) -> MailboxId {
        let mb = self.account(SEARCH_LOGIN);
        for (i, m) in search_messages().into_iter().enumerate() {
            if i == 4 {
                self.store.claim_recent(mb).unwrap();
            }
            let uid = self.deliver(SEARCH_LOGIN, &m.body, m.received_ms);
            assert_eq!(uid as usize, i + 1);
            if m.flags != Flags::empty() {
                self.set_flags(mb, uid, m.flags);
            }
        }
        mb
    }

    /// `login` with `n` small plain messages (UIDs 1..=n), no flags, none claimed as \Recent.
    pub fn simple_account(&self, login: &str, n: u32) -> MailboxId {
        let mb = self.account(login);
        for i in 1..=n {
            let body = format!(
                "From: s{i}@example.test\r\nTo: {login}\r\nSubject: simple {i}\r\nDate: Sun, 1 Mar 2026 10:00:00 +0000\r\n\r\nbody {i}\r\n"
            );
            self.deliver(
                login,
                body.as_bytes(),
                ms("01-Mar-2026 10:00:00 +0000") + i as i64 * 1000,
            );
        }
        mb
    }
}

trait ReadAll {
    fn read_to_end_sync(self, v: &mut Vec<u8>);
}
impl ReadAll for std::fs::File {
    fn read_to_end_sync(mut self, v: &mut Vec<u8>) {
        std::io::Read::read_to_end(&mut self, v).unwrap();
    }
}

// // Fixtures

pub const FIXTURE_LOGIN: &str = "test@example.com";
pub const SEARCH_LOGIN: &str = "search@example.com";

pub const FIXTURES: [&str; 11] = [
    "01-plain",
    "02-alternative",
    "03-mixed",
    "04-rfc822",
    "05-encoded",
    "06-nodate",
    "07-group",
    "08-folded",
    "09-8bit",
    "10-barelf",
    "11-empty",
];

pub fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mail")
}

pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir().join(format!("{name}.eml"))).unwrap()
}

/// Sequence number (= UID) of a fixture in the fixtures account.
pub fn fixture_seq(name: &str) -> u32 {
    FIXTURES
        .iter()
        .position(|n| *n == name)
        .expect("known fixture") as u32
        + 1
}

/// INTERNALDATE of fixture i: 1 Apr 2026 10:00:00.250 UTC plus i days.
pub fn fixture_received_ms(i: usize) -> i64 {
    ms("01-Apr-2026 10:00:00 +0000") + 250 + i as i64 * 86_400_000
}

/// The hand-written golden `<name>.<kind>` (kind: envelope, bodystructure, body), tokenized.
pub fn golden(name: &str, kind: &str) -> Tok {
    let path = fixture_dir().join(format!("{name}.{kind}"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut toks = tokenize(&text);
    assert_eq!(
        toks.len(),
        1,
        "{} holds one parenthesized value",
        path.display()
    );
    toks.remove(0)
}

pub struct SearchMsg {
    pub body: Vec<u8>,
    pub received_ms: i64,
    pub flags: Flags,
}

/// The SEARCH mailbox (see tests/imap_search.rs for the expected results).
///   1 alice, Cc carol, "Quarterly report", sent 2-Feb, internal 1-Mar 12:00, \Seen
///   2 bob@example.org, Bcc hidden, "Lunch?", sent 3-Feb 23:30 -0500, internal 2-Mar, \Seen \Answered
///   3 alice -> dave, "Re: Quarterly report", sent 4-Feb 00:30 +0100, X-Priority 1,
///     internal 3-Mar 00:00:00, \Flagged
///   4 ISO-8859-2 "Štefan", UTF-8 subject "Šumniki čćž", 8-bit body, sent 5-Feb,
///     internal 3-Mar 23:59:59.999, \Draft
///   5 bob@example.org, "Big one", > 2,800 bytes, sent 6-Feb, internal 4-Mar, no flags  (\Recent)
///   6 Erin, "QUARTERLY numbers", quoted-printable body "Café tomorrow at nine.", sent 7-Feb,
///     internal 5-Mar, \Seen                                                           (\Recent)
pub fn search_messages() -> Vec<SearchMsg> {
    let big_body: String = (0..40).map(|_| format!("{}\r\n", "x".repeat(70))).collect();
    let m = |body: String, internal: &str, extra_ms: i64, flags: Flags| SearchMsg {
        body: body.into_bytes(),
        received_ms: ms(internal) + extra_ms,
        flags,
    };
    vec![
        m(
            "From: Alice Example <alice@example.test>\r\nTo: test@example.com\r\nCc: carol@example.test\r\n\
             Subject: Quarterly report\r\nDate: Mon, 2 Feb 2026 10:00:00 +0000\r\nMessage-ID: <s1@example.test>\r\n\
             \r\nThe numbers are in.\r\n"
                .into(),
            "01-Mar-2026 12:00:00 +0000",
            0,
            Flags::SEEN,
        ),
        m(
            "From: Bob <bob@example.org>\r\nTo: test@example.com\r\nBcc: hidden@example.test\r\nSubject: Lunch?\r\n\
             Date: Tue, 3 Feb 2026 23:30:00 -0500\r\nMessage-ID: <s2@example.org>\r\n\
             \r\nPizza at noon, report later.\r\n"
                .into(),
            "02-Mar-2026 12:00:00 +0000",
            0,
            Flags::SEEN | Flags::ANSWERED,
        ),
        m(
            "From: alice@example.test\r\nTo: dave@example.net\r\nSubject: Re: Quarterly report\r\n\
             Date: Wed, 4 Feb 2026 00:30:00 +0100\r\nMessage-ID: <s3@example.test>\r\nX-Priority: 1\r\n\
             \r\nLooks good.\r\n"
                .into(),
            "03-Mar-2026 00:00:00 +0000",
            0,
            Flags::FLAGGED,
        ),
        m(
            "From: =?ISO-8859-2?Q?=A9tefan?= <stefan@example.si>\r\nTo: test@example.com\r\n\
             Subject: =?UTF-8?B?xaB1bW5pa2kgxI3Eh8W+?=\r\nDate: Thu, 5 Feb 2026 12:00:00 +0000\r\n\
             Message-ID: <s4@example.si>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\nŽaba skače čez potok.\r\n"
                .into(),
            "03-Mar-2026 23:59:59 +0000",
            999,
            Flags::DRAFT,
        ),
        m(
            format!(
                "From: Bob <bob@example.org>\r\nTo: test@example.com\r\nSubject: Big one\r\n\
                 Date: Fri, 6 Feb 2026 12:00:00 +0000\r\nMessage-ID: <s5@example.org>\r\n\r\n{big_body}"
            ),
            "04-Mar-2026 12:00:00 +0000",
            0,
            Flags::empty(),
        ),
        m(
            "From: Erin <erin@example.test>\r\nTo: test@example.com\r\nSubject: QUARTERLY numbers\r\n\
             Date: Sat, 7 Feb 2026 12:00:00 +0000\r\nMessage-ID: <s6@example.test>\r\nMIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\
             \r\nCaf=C3=A9 tomorrow=\r\n at nine.\r\n"
                .into(),
            "05-Mar-2026 12:00:00 +0000",
            0,
            Flags::SEEN,
        ),
    ]
}

// // Client

pub struct Client {
    s: TlsStream<TcpStream>,
    buf: Vec<u8>,
}

/// A piece of a command: plain text, or a synchronizing literal (`{n}` CRLF, wait for `+`, data).
pub enum Part<'a> {
    Text(&'a str),
    Lit(&'a [u8]),
}

impl Client {
    pub async fn open(addr: SocketAddr, pki: &Pki) -> std::io::Result<Client> {
        Client::open_with(addr, client_tls(pki)).await
    }

    pub async fn open_with(
        addr: SocketAddr,
        tls: Arc<rustls::ClientConfig>,
    ) -> std::io::Result<Client> {
        let tcp = TcpStream::connect(addr).await?;
        let name = ServerName::try_from("localhost").unwrap();
        let s = tokio::time::timeout(
            TIMEOUT,
            tokio_rustls::TlsConnector::from(tls).connect(name, tcp),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;
        Ok(Client { s, buf: Vec::new() })
    }

    pub fn tls_version(&self) -> Option<rustls::ProtocolVersion> {
        self.s.get_ref().1.protocol_version()
    }

    /// Read more bytes into the buffer. Ok(false) on EOF or a transport error.
    async fn fill(&mut self) -> bool {
        let mut chunk = vec![0u8; 16 * 1024];
        match tokio::time::timeout(TIMEOUT, self.s.read(&mut chunk)).await {
            Err(_) => panic!(
                "no data from the server within {TIMEOUT:?} (buffered: {})",
                show(&self.buf)
            ),
            Ok(Ok(0)) | Ok(Err(_)) => false,
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
        }
    }

    /// One raw line including its line ending; None at EOF.
    pub async fn read_line(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(p) = self.buf.iter().position(|&b| b == b'\n') {
                return Some(self.buf.drain(..=p).collect());
            }
            if !self.fill().await {
                return None;
            }
        }
    }

    async fn read_exact_n(&mut self, n: usize) -> Option<Vec<u8>> {
        while self.buf.len() < n {
            if !self.fill().await {
                return None;
            }
        }
        Some(self.buf.drain(..n).collect())
    }

    /// One complete server response: a line plus any literals it announces (inline, raw).
    pub async fn read_response(&mut self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line().await?;
            out.extend_from_slice(&line);
            match literal_len(&line) {
                Some(n) => out.extend_from_slice(&self.read_exact_n(n).await?),
                None => return Some(out),
            }
        }
    }

    /// True when the server sends nothing for `d` (real time).
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

    pub async fn write(&mut self, bytes: &[u8]) {
        self.s.write_all(bytes).await.expect("write to server");
        self.s.flush().await.expect("flush");
    }

    pub async fn try_write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.s.write_all(bytes).await?;
        self.s.flush().await
    }

    /// Send `<tag> <text>` CRLF and read through the tagged completion.
    pub async fn cmd(&mut self, tag: &str, text: &str) -> Done {
        self.write(format!("{tag} {text}\r\n").as_bytes()).await;
        self.read_until_tagged(tag).await
    }

    /// Send a command made of text and synchronizing literals. If the server answers a literal
    /// announcement with a tagged response instead of `+`, that response ends the command.
    pub async fn cmd_parts(&mut self, tag: &str, parts: &[Part<'_>]) -> Done {
        let mut out = format!("{tag} ").into_bytes();
        let mut untagged = Vec::new();
        for p in parts {
            match p {
                Part::Text(t) => out.extend_from_slice(t.as_bytes()),
                Part::Lit(data) => {
                    out.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
                    self.write(&out).await;
                    out.clear();
                    loop {
                        let r = self
                            .read_response()
                            .await
                            .expect("continuation or tagged response");
                        if r.starts_with(b"+") {
                            break;
                        }
                        if is_tagged(&r, tag) {
                            return Done {
                                tag: tag.into(),
                                untagged,
                                tagged: r,
                            };
                        }
                        untagged.push(r);
                    }
                    out.extend_from_slice(data);
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        self.write(&out).await;
        let mut d = self.read_until_tagged(tag).await;
        untagged.append(&mut d.untagged);
        d.untagged = untagged;
        d
    }

    pub async fn read_until_tagged(&mut self, tag: &str) -> Done {
        let mut untagged = Vec::new();
        loop {
            let Some(r) = self.read_response().await else {
                panic!(
                    "connection closed before the tagged response to {tag}; got:\n{}",
                    show_all(&untagged)
                );
            };
            if is_tagged(&r, tag) {
                return Done {
                    tag: tag.into(),
                    untagged,
                    tagged: r,
                };
            }
            untagged.push(r);
        }
    }

    /// Read until EOF; panics if the server keeps the connection open past TIMEOUT.
    pub async fn expect_closed(&mut self) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        while let Some(r) = self.read_response().await {
            lines.push(r);
        }
        lines
    }
}

fn is_tagged(r: &[u8], tag: &str) -> bool {
    r.len() > tag.len() && r.starts_with(tag.as_bytes()) && r[tag.len()] == b' '
}

/// `{n}` or `{n+}` at the end of a line (before CRLF).
fn literal_len(line: &[u8]) -> Option<usize> {
    let l = line.strip_suffix(b"\n")?;
    let l = l.strip_suffix(b"\r").unwrap_or(l);
    let l = l.strip_suffix(b"}")?;
    let open = l.iter().rposition(|&b| b == b'{')?;
    let digits = &l[open + 1..];
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

pub fn show(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if s.len() > 2000 {
        format!("{}…[{} bytes]", &s[..s.floor_char_boundary(2000)], s.len())
    } else {
        s.into_owned()
    }
}

pub fn show_all(lines: &[Vec<u8>]) -> String {
    lines.iter().map(|l| show(l)).collect::<Vec<_>>().join("")
}

// // Completed command

#[derive(Debug)]
pub struct Done {
    pub tag: String,
    pub untagged: Vec<Vec<u8>>,
    pub tagged: Vec<u8>,
}

impl Done {
    pub fn transcript(&self) -> String {
        format!("{}{}", show_all(&self.untagged), show(&self.tagged))
    }

    /// OK, NO or BAD (upper-cased) from the tagged line.
    pub fn status(&self) -> String {
        let s = String::from_utf8_lossy(&self.tagged[self.tag.len() + 1..]).to_string();
        s.split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase()
    }

    /// Tagged line text after the status word (response code included).
    pub fn tagged_text(&self) -> String {
        let s = String::from_utf8_lossy(&self.tagged[self.tag.len() + 1..])
            .trim_end()
            .to_string();
        s.split_once(' ')
            .map(|(_, t)| t.to_string())
            .unwrap_or_default()
    }

    #[track_caller]
    pub fn assert_ok(&self) -> &Done {
        assert_eq!(self.status(), "OK", "expected OK:\n{}", self.transcript());
        self
    }

    #[track_caller]
    pub fn assert_no(&self) -> &Done {
        assert_eq!(self.status(), "NO", "expected NO:\n{}", self.transcript());
        self
    }

    #[track_caller]
    pub fn assert_bad(&self) -> &Done {
        assert_eq!(self.status(), "BAD", "expected BAD:\n{}", self.transcript());
        self
    }

    /// RFC 3501 section 6: a command in the wrong state gets BAD or NO (implementation's choice).
    #[track_caller]
    pub fn assert_refused(&self) -> &Done {
        let s = self.status();
        assert!(
            s == "NO" || s == "BAD",
            "expected NO or BAD:\n{}",
            self.transcript()
        );
        self
    }

    /// The tagged line carries response code `[<code> ...]` (case-insensitive).
    #[track_caller]
    pub fn assert_code(&self, code: &str) -> &Done {
        let t = self.tagged_text().to_ascii_uppercase();
        assert!(
            t.starts_with(&format!("[{}", code.to_ascii_uppercase())),
            "expected [{code}] in:\n{}",
            self.transcript()
        );
        self
    }

    /// Untagged lines that are responses of type `kind` (e.g. "LIST", "SEARCH", "FETCH", "EXISTS"),
    /// tokenized. `* <n> KIND ...` and `* KIND ...` both match.
    pub fn data(&self, kind: &str) -> Vec<Vec<Tok>> {
        self.untagged
            .iter()
            .filter(|l| {
                let s = String::from_utf8_lossy(&l[..l.len().min(64)]).to_string();
                let w: Vec<&str> = s.split_whitespace().collect();
                w.first() == Some(&"*")
                    && (w.get(1).is_some_and(|x| x.eq_ignore_ascii_case(kind))
                        || (w
                            .get(1)
                            .is_some_and(|x| x.bytes().all(|b| b.is_ascii_digit()))
                            && w.get(2).is_some_and(|x| x.eq_ignore_ascii_case(kind))))
            })
            .map(|l| tokenize(l))
            .collect()
    }

    /// `* <n> KIND` (EXISTS, RECENT): the number, if exactly one such line was sent.
    pub fn number(&self, kind: &str) -> Option<u32> {
        let v = self.data(kind);
        assert!(v.len() <= 1, "more than one {kind}:\n{}", self.transcript());
        v.first().map(|t| t[1].atom().parse().unwrap())
    }

    /// Value of response code `[NAME value]` on any untagged OK line or the tagged line.
    pub fn code(&self, name: &str) -> Option<String> {
        let pat = format!("[{} ", name.to_ascii_uppercase());
        let pat_bare = format!("[{}]", name.to_ascii_uppercase());
        for l in self.untagged.iter().chain(std::iter::once(&self.tagged)) {
            let s = String::from_utf8_lossy(l).to_string();
            let up = s.to_ascii_uppercase();
            if let Some(p) = up.find(&pat) {
                let rest = &s[p + pat.len()..];
                let end = matching_bracket(rest);
                return Some(rest[..end].to_string());
            }
            if up.contains(&pat_bare) {
                return Some(String::new());
            }
        }
        None
    }

    /// All FETCH responses in order: (sequence number, items).
    pub fn fetches(&self) -> Vec<(u32, Items)> {
        self.data("FETCH")
            .into_iter()
            .map(|t| {
                assert!(t.len() == 4, "FETCH response shape: {t:?}");
                let seq = t[1].atom().parse().unwrap();
                (seq, Items::from_list(t[3].list()))
            })
            .collect()
    }

    /// FETCH items per sequence number, merging several FETCH responses for the same message.
    pub fn fetch_map(&self) -> BTreeMap<u32, Items> {
        let mut m: BTreeMap<u32, Items> = BTreeMap::new();
        for (seq, items) in self.fetches() {
            m.entry(seq).or_default().0.extend(items.0);
        }
        m
    }

    /// Numbers of the single `* SEARCH` response, sorted.
    #[track_caller]
    pub fn search(&self) -> Vec<u32> {
        let v = self.data("SEARCH");
        assert_eq!(
            v.len(),
            1,
            "exactly one * SEARCH line expected:\n{}",
            self.transcript()
        );
        let mut n: Vec<u32> = v[0][2..]
            .iter()
            .map(|t| t.atom().parse().unwrap())
            .collect();
        n.sort();
        n
    }
}

fn matching_bracket(s: &str) -> usize {
    let mut depth = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ']' if depth == 0 => return i,
            _ => {}
        }
    }
    s.len()
}

/// FETCH data items; keys upper-cased with whitespace collapsed and quotes removed.
#[derive(Clone, Debug, Default)]
pub struct Items(pub Vec<(String, Tok)>);

impl Items {
    fn from_list(l: &[Tok]) -> Items {
        assert!(
            l.len().is_multiple_of(2),
            "FETCH items come in pairs: {l:?}"
        );
        Items(
            l.chunks(2)
                .map(|kv| (norm_key(kv[0].atom()), kv[1].clone()))
                .collect(),
        )
    }

    #[track_caller]
    pub fn get(&self, key: &str) -> &Tok {
        let k = norm_key(key);
        let v: Vec<&Tok> = self
            .0
            .iter()
            .filter(|(n, _)| *n == k)
            .map(|(_, v)| v)
            .collect();
        assert!(!v.is_empty(), "no {k} in FETCH items {:?}", self.keys());
        v[v.len() - 1]
    }

    pub fn has(&self, key: &str) -> bool {
        let k = norm_key(key);
        self.0.iter().any(|(n, _)| *n == k)
    }

    pub fn keys(&self) -> BTreeSet<String> {
        self.0.iter().map(|(k, _)| k.clone()).collect()
    }

    #[track_caller]
    pub fn bytes(&self, key: &str) -> Vec<u8> {
        self.get(key)
            .bytes()
            .unwrap_or_else(|| panic!("{key} is NIL"))
            .to_vec()
    }

    #[track_caller]
    pub fn num(&self, key: &str) -> u64 {
        self.get(key).atom().parse().unwrap()
    }

    /// FLAGS as a lower-cased set ("\\seen", "\\recent", ...).
    #[track_caller]
    pub fn flags(&self) -> BTreeSet<String> {
        flag_set(self.get("FLAGS"))
    }
}

pub fn flag_set(t: &Tok) -> BTreeSet<String> {
    t.list()
        .iter()
        .map(|f| f.atom().to_ascii_lowercase())
        .collect()
}

pub fn flags(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|f| f.to_ascii_lowercase()).collect()
}

pub fn norm_key(k: &str) -> String {
    k.replace('"', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

// // Tokenizer

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Atom(String),
    Nil,
    Str(Vec<u8>),
    List(Vec<Tok>),
}

impl Tok {
    #[track_caller]
    pub fn atom(&self) -> &str {
        match self {
            Tok::Atom(a) => a,
            other => panic!("expected an atom, got {other:?}"),
        }
    }

    #[track_caller]
    pub fn list(&self) -> &[Tok] {
        match self {
            Tok::List(l) => l,
            other => panic!("expected a list, got {other:?}"),
        }
    }

    /// String bytes; None for NIL; panics otherwise.
    #[track_caller]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Tok::Str(s) => Some(s),
            Tok::Nil => None,
            other => panic!("expected a string or NIL, got {other:?}"),
        }
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, Tok::Nil)
    }
}

/// Structural equality. Atoms (numbers, flags, NIL) compare case-insensitively; strings exactly,
/// or ASCII-case-insensitively when `ci_strings` (BODYSTRUCTURE: type, subtype, parameter names,
/// encodings and disposition types are case-insensitive in MIME).
pub fn tok_eq(a: &Tok, b: &Tok, ci_strings: bool) -> bool {
    match (a, b) {
        (Tok::Atom(x), Tok::Atom(y)) => x.eq_ignore_ascii_case(y),
        (Tok::Nil, Tok::Nil) => true,
        (Tok::Str(x), Tok::Str(y)) => {
            if ci_strings {
                x.eq_ignore_ascii_case(y)
            } else {
                x == y
            }
        }
        (Tok::List(x), Tok::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| tok_eq(p, q, ci_strings))
        }
        _ => false,
    }
}

/// Render for failure messages (all strings quoted).
pub fn render(t: &Tok) -> String {
    match t {
        Tok::Atom(a) => a.clone(),
        Tok::Nil => "NIL".into(),
        Tok::Str(s) => format!("{:?}", String::from_utf8_lossy(s)),
        Tok::List(l) => format!("({})", l.iter().map(render).collect::<Vec<_>>().join(" ")),
    }
}

/// Tokenize one response line (with inline literals) or a golden file.
pub fn tokenize(b: &[u8]) -> Vec<Tok> {
    let mut i = 0;
    parse_seq(b, &mut i, false)
}

fn parse_seq(b: &[u8], i: &mut usize, nested: bool) -> Vec<Tok> {
    let mut out = Vec::new();
    loop {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\r' | b'\n') {
            *i += 1;
        }
        if *i >= b.len() {
            assert!(!nested, "unbalanced parentheses in {}", show(b));
            return out;
        }
        match b[*i] {
            b'(' => {
                *i += 1;
                out.push(Tok::List(parse_seq(b, i, true)));
            }
            b')' => {
                assert!(nested, "unexpected ) in {}", show(b));
                *i += 1;
                return out;
            }
            b'"' => out.push(Tok::Str(parse_quoted(b, i))),
            b'{' => out.push(Tok::Str(parse_literal(b, i))),
            b'~' if b.get(*i + 1) == Some(&b'{') => {
                *i += 1;
                out.push(Tok::Str(parse_literal(b, i)));
            }
            _ => {
                let a = parse_atom(b, i);
                out.push(if a.eq_ignore_ascii_case("NIL") {
                    Tok::Nil
                } else {
                    Tok::Atom(a)
                });
            }
        }
    }
}

fn parse_quoted(b: &[u8], i: &mut usize) -> Vec<u8> {
    *i += 1;
    let mut s = Vec::new();
    while *i < b.len() {
        match b[*i] {
            b'\\' if *i + 1 < b.len() => {
                s.push(b[*i + 1]);
                *i += 2;
            }
            b'"' => {
                *i += 1;
                return s;
            }
            c => {
                s.push(c);
                *i += 1;
            }
        }
    }
    panic!("unterminated quoted string in {}", show(b));
}

fn parse_literal(b: &[u8], i: &mut usize) -> Vec<u8> {
    let close = b[*i..].iter().position(|&c| c == b'}').expect("literal }") + *i;
    let digits = std::str::from_utf8(&b[*i + 1..close])
        .unwrap()
        .trim_end_matches('+');
    let n: usize = digits.parse().expect("literal length");
    let mut p = close + 1;
    if b.get(p) == Some(&b'\r') {
        p += 1;
    }
    assert_eq!(
        b.get(p),
        Some(&b'\n'),
        "literal announcement ends with CRLF"
    );
    p += 1;
    let data = b[p..p + n].to_vec();
    *i = p + n;
    data
}

fn parse_atom(b: &[u8], i: &mut usize) -> String {
    let start = *i;
    while *i < b.len() {
        match b[*i] {
            b' ' | b'(' | b')' | b'\r' | b'\n' | b'"' => break,
            b'[' => {
                // section spec: everything up to the matching ']' belongs to the atom
                let close = b[*i..].iter().position(|&c| c == b']').expect("section ]") + *i;
                *i = close + 1;
            }
            _ => *i += 1,
        }
    }
    String::from_utf8_lossy(&b[start..*i]).into_owned()
}

// // Small helpers

/// Standard base64 with padding (AUTHENTICATE PLAIN); test code, no crate.
pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A mailbox name from LIST/LSUB/STATUS: atom or string, as text.
pub fn name_of(t: &Tok) -> String {
    match t {
        Tok::Atom(a) => a.clone(),
        Tok::Str(s) => String::from_utf8_lossy(s).into_owned(),
        other => panic!("expected a mailbox name, got {other:?}"),
    }
}

/// A `(KEY value KEY value ...)` list (STATUS) as an upper-cased map.
pub fn pairs(t: &Tok) -> BTreeMap<String, String> {
    t.list()
        .chunks(2)
        .map(|kv| (kv[0].atom().to_ascii_uppercase(), kv[1].atom().to_string()))
        .collect()
}

/// The text of the header block (through the blank line) and the body of a raw message.
pub fn split_message(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    for sep in [&b"\r\n\r\n"[..], &b"\n\n"[..]] {
        if let Some(p) = raw.windows(sep.len()).position(|w| w == sep) {
            return (raw[..p + sep.len()].to_vec(), raw[p + sep.len()..].to_vec());
        }
    }
    (raw.to_vec(), Vec::new())
}

/// Byte slice between the end of `start` and the beginning of the next `end` (both must exist).
pub fn between<'a>(raw: &'a [u8], start: &[u8], end: &[u8]) -> &'a [u8] {
    let s = raw
        .windows(start.len())
        .position(|w| w == start)
        .expect("start marker")
        + start.len();
    let e = raw[s..]
        .windows(end.len())
        .position(|w| w == end)
        .expect("end marker")
        + s;
    &raw[s..e]
}

impl Harness {
    /// Send `text` as command `tag`, then answer the failed-login delay: wait until the server sleeps
    /// `AUTH_DELAY` on the clock (or answers by itself) and advance it. Returns the completion.
    pub async fn auth_cmd(&self, c: &mut Client, tag: &str, text: &str) -> Done {
        let mark = self.clock.mark();
        c.write(format!("{tag} {text}\r\n").as_bytes()).await;
        self.finish_auth(c, tag, mark).await
    }

    /// Wait for `tag`'s completion, advancing the clock by `AUTH_DELAY` once if the server is
    /// sleeping on it (a failed login), without advancing when it answers on its own.
    pub async fn finish_auth(&self, c: &mut Client, tag: &str, mark: u64) -> Done {
        let start = std::time::Instant::now();
        loop {
            if !c.nothing_within(Duration::from_millis(20)).await {
                return c.read_until_tagged(tag).await;
            }
            let sleeping = self
                .clock
                .pending
                .lock()
                .unwrap()
                .iter()
                .any(|(id, d)| *id >= mark && *d == AUTH_DELAY);
            if sleeping {
                self.clock.advance(AUTH_DELAY);
                return c.read_until_tagged(tag).await;
            }
            assert!(
                start.elapsed() < TIMEOUT,
                "no answer to {tag} and no Clock::sleep({AUTH_DELAY:?})"
            );
        }
    }
}
