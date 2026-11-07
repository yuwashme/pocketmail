//! `serve` wiring of the settings web server: started with the IMAP certificate when TLS is
//! configured, off (with a warning) without TLS files, off with SSM_WEB_LISTEN=off, and off (with a
//! warning, IMAP still serving) when its address cannot be bound. Runs the real binary against a
//! temp data dir on 127.0.0.1.

mod browser;
mod harness;
mod net;

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use browser::{COOKIE, FORM, Resp, SetCookie, Web, css_path, csrf_token, form_body, login_fields, password_fields, request};
use net::{Pki, client_tls};

const WAIT: Duration = Duration::from_secs(10);

struct Serve {
    _tmp: tempfile::TempDir,
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Serve {
    /// `serve` with SSM_DATA_DIR in a temp dir, `env` on top; `tls`: write a test certificate
    /// and set SSM_TLS_CERT / SSM_TLS_KEY (IMAP on 127.0.0.1:0).
    fn start(tls: Option<&Pki>, env: &[(&str, &str)]) -> Serve {
        Serve::start_in(tempfile::tempdir().unwrap(), tls, env)
    }

    /// `start` in `tmp`, whose `data` dir may already hold accounts.
    fn start_in(tmp: tempfile::TempDir, tls: Option<&Pki>, env: &[(&str, &str)]) -> Serve {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"));
        cmd.arg("serve").env_clear().env("SSM_DATA_DIR", tmp.path().join("data"));
        if let Some(pki) = tls {
            let (cert, key) = (tmp.path().join("cert.pem"), tmp.path().join("key.pem"));
            std::fs::write(&cert, &pki.cert_pem).unwrap();
            std::fs::write(&key, &pki.key_pem).unwrap();
            cmd.env("SSM_TLS_CERT", cert).env("SSM_TLS_KEY", key).env("SSM_IMAP_LISTEN", "127.0.0.1:0");
        }
        cmd.envs(env.iter().copied());
        let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Serve { _tmp: tmp, child, lines, seen: Vec::new() }
    }

    /// The first log line containing `pat`, waiting up to WAIT.
    fn wait_for(&mut self, pat: &str) -> Option<String> {
        if let Some(l) = self.seen.iter().find(|l| l.contains(pat)) {
            return Some(l.clone());
        }
        let deadline = Instant::now() + WAIT;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.seen.push(l.clone());
                    if l.contains(pat) {
                        return Some(l);
                    }
                }
                Err(_) => return None,
            }
        }
        None
    }

    /// Collect log lines for `d`.
    fn settle(&mut self, d: Duration) {
        let deadline = Instant::now() + d;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(l) => self.seen.push(l),
                Err(_) => return,
            }
        }
    }

    fn log(&self) -> String {
        self.seen.join("\n")
    }

    fn running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The address in a "<name>: listening on <addr> ..." line.
fn listening_addr(line: &str) -> SocketAddr {
    let rest = line.split("listening on ").nth(1).unwrap_or_else(|| panic!("no address in {line:?}"));
    rest.split_whitespace().next().unwrap().parse().unwrap_or_else(|_| panic!("no address in {line:?}"))
}

#[test]
fn serve_without_tls_logs_web_off() {
    let mut s = Serve::start(None, &[]);
    let line = s.wait_for("web: off").unwrap_or_else(|| panic!("no \"web: off\" warning in:\n{}", s.log()));
    assert!(line.contains(" WARN "), "a warning: {line}");
    s.settle(Duration::from_millis(300));
    assert!(!s.log().contains("web: listening"), "{}", s.log());
    assert!(s.running(), "serve keeps running without the web UI");
}

#[test]
fn web_listen_off_starts_no_listener() {
    let pki = Pki::local();
    let mut s = Serve::start(Some(&pki), &[("SSM_WEB_LISTEN", "off")]);
    assert!(s.wait_for("imap: listening on").is_some(), "IMAP starts:\n{}", s.log());
    assert!(s.wait_for("web: off").is_some(), "the log says the web UI is off:\n{}", s.log());
    s.settle(Duration::from_millis(500));
    assert!(!s.log().contains("web: listening"), "SSM_WEB_LISTEN=off starts no web listener:\n{}", s.log());
    assert!(s.running(), "{}", s.log());
}

#[tokio::test]
async fn serve_starts_web_with_the_imap_certificate() {
    let pki = Pki::local();
    let mut s = Serve::start(Some(&pki), &[("SSM_WEB_LISTEN", "127.0.0.1:0")]);
    let imap = listening_addr(&s.wait_for("imap: listening on").unwrap_or_else(|| panic!("IMAP starts:\n{}", s.log())));
    let web = listening_addr(&s.wait_for("web: listening on").unwrap_or_else(|| panic!("web starts:\n{}", s.log())));

    let mut w = Web::open(web, client_tls(&pki)).await.expect("TLS to the web listener");
    let w_cert = w.peer_certificate().expect("web certificate");
    let i = Web::open(imap, client_tls(&pki)).await.expect("TLS to the IMAP listener");
    assert_eq!(w_cert, i.peer_certificate().expect("IMAP certificate"), "same certificate as IMAP");
    assert_eq!(w_cert, pki.cert_der);

    let host = format!("localhost:{}", web.port());
    w.write(&request("GET", &css_path(), &host, &[], b"")).await;
    let r = w.read_response(false).await.expect("response");
    assert_eq!(r.status, 200, "the stylesheet is served");
}

#[tokio::test]
async fn web_bind_failure_warns_and_imap_keeps_serving() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let pki = Pki::local();
    let mut s = Serve::start(Some(&pki), &[("SSM_WEB_LISTEN", &addr)]);
    let imap = listening_addr(&s.wait_for("imap: listening on").unwrap_or_else(|| panic!("IMAP starts:\n{}", s.log())));
    s.settle(Duration::from_millis(500));
    assert!(s.running(), "a web port that cannot be bound does not stop serve:\n{}", s.log());
    let log = s.log();
    let line = log.lines().find(|l| l.contains("SSM_WEB_LISTEN") && l.contains(&addr)).unwrap_or_else(|| panic!("a line names the setting and address:\n{log}"));
    assert!(line.contains(" WARN "), "a warning: {line}");
    assert!(!log.contains("web: listening"), "{log}");

    let mut c = harness::Client::open(imap, &pki).await.expect("TLS to the IMAP listener");
    let greeting = c.read_response().await.expect("IMAP greeting");
    assert!(greeting.starts_with(b"* OK"), "IMAP keeps serving: {}", String::from_utf8_lossy(&greeting));
    drop(taken);
}

/// Run the CLI on `data` with `stdin`; it must succeed.
fn cli(data: &Path, args: &[&str], stdin: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .args(args)
        .env_clear()
        .env("SSM_DATA_DIR", data)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A browser against the real binary: one cookie, one request per connection.
struct Live<'p> {
    addr: SocketAddr,
    pki: &'p Pki,
    cookie: Option<String>,
}

impl Live<'_> {
    async fn send(&mut self, method: &str, path: &str, form: Option<String>) -> Resp {
        let host = format!("localhost:{}", self.addr.port());
        let mut headers = vec!["Connection: close".to_string()];
        if let Some(c) = &self.cookie {
            headers.push(format!("Cookie: {COOKIE}={c}"));
        }
        if let Some(body) = &form {
            headers.push(format!("Origin: https://{host}"));
            headers.push(format!("Content-Type: {FORM}"));
            headers.push(format!("Content-Length: {}", body.len()));
        }
        let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let mut w = Web::open(self.addr, client_tls(self.pki)).await.expect("TLS to the web listener");
        w.write(&request(method, path, &host, &refs, form.unwrap_or_default().as_bytes())).await;
        let r = tokio::time::timeout(WAIT, w.read_response(false)).await.expect("an answer in time").expect("a response");
        for c in r.all("set-cookie").into_iter().map(SetCookie::parse) {
            if c.name == COOKIE {
                self.cookie = (!c.clears()).then(|| c.value.clone());
            }
        }
        r
    }

    async fn sign_in(&mut self, login: &str, password: &str) -> Resp {
        let page = self.send("GET", "/login", None).await;
        assert_eq!(page.status, 200, "GET /login: {}", page.text());
        let (u, p) = login_fields(&page.text());
        self.send("POST", "/login", Some(form_body(&[(&u, login), (&p, password)]))).await
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    suite.tls13().unwrap().common.hash_provider.hash(bytes).as_ref().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn changes_logged_without_password_token_hash_or_cookie() {
    const LOGIN: &str = "user@example.com";
    const OLD: &str = "old-secret-Passw0rd-1";
    const NEW: &str = "new-secret-Passw0rd-2";
    const WRONG: &str = "wrong-secret-Passw0rd-3";
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    cli(&data, &["account", "add", LOGIN], &format!("{OLD}\n"));
    cli(&data, &["address", "add", LOGIN, LOGIN], "");

    let pki = Pki::local();
    let mut s = Serve::start_in(tmp, Some(&pki), &[("SSM_WEB_LISTEN", "127.0.0.1:0"), ("SSM_LOG", "debug")]);
    let addr = listening_addr(&s.wait_for("web: listening on").unwrap_or_else(|| panic!("web starts:\n{}", s.log())));
    let mut b = Live { addr, pki: &pki, cookie: None };

    let r = b.sign_in(LOGIN, WRONG).await;
    assert_eq!(r.status, 422, "a failed sign-in: {}", r.text());
    let r = b.sign_in(LOGIN, OLD).await;
    assert_eq!(r.status, 303, "sign-in: {}", r.text());
    let cookie = b.cookie.clone().expect("a session cookie");
    let me = b.send("GET", "/me", None).await;
    assert_eq!(me.status, 200, "{}", me.text());
    let csrf = csrf_token(&me.text()).expect("a CSRF token on the own page");
    let (cur, new, again) = password_fields(&me.text());
    let form = form_body(&[(&cur, OLD), (&new, NEW), (&again, NEW), ("csrf", &csrf)]);
    let r = b.send("POST", "/me/password", Some(form)).await;
    assert_eq!(r.status, 303, "password change: {}", r.text());
    let r = b.send("POST", "/logout", Some(form_body(&[("csrf", &csrf)]))).await;
    assert_eq!(r.status, 303, "sign-out: {}", r.text());
    s.settle(Duration::from_millis(500));

    let log = s.log();
    let user_lines: Vec<&str> = log.lines().filter(|l| l.contains(&format!("web: {LOGIN:?}"))).collect();
    assert!(user_lines.len() >= 3, "sign-in, failure, password change and sign-out are logged as `web: {LOGIN:?} …`:\n{log}");
    assert!(user_lines.iter().any(|l| l.to_ascii_lowercase().contains("password")), "the password change is logged:\n{log}");

    let id_hash = sha256(cookie.as_bytes());
    let mut secrets = vec![OLD.to_string(), NEW.to_string(), WRONG.to_string(), cookie.clone(), csrf.clone(), hex(&id_hash), "$argon2".to_string()];
    if let Ok(raw) = (0..cookie.len()).step_by(2).map(|i| u8::from_str_radix(&cookie[i..i + 2], 16)).collect::<Result<Vec<u8>, _>>() {
        secrets.push(hex(&sha256(&raw)));
    }
    let log_lower = log.to_ascii_lowercase();
    for secret in secrets {
        assert!(!log_lower.contains(&secret.to_ascii_lowercase()), "the log holds {secret:?}:\n{log}");
    }
}

impl Live<'_> {
    /// Submit the one form to `action` on `page`: its hidden fields and button, then `fill`.
    async fn submit(&mut self, page: &str, action: &str, fill: &[(&str, &str)]) -> Resp {
        let form = browser::post_form(page, action);
        let mut body: Vec<(&str, &str)> = form.sent.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        body.extend_from_slice(fill);
        self.send("POST", &form.action, Some(form_body(&body))).await
    }
}

const SETUP_ADMIN: &str = "admin@example.com";
const SETUP_PW: &str = "setup-secret-Passw0rd-1";

/// `serve` on a fresh data dir with debug logging: the web address and the setup link's path.
fn fresh_serve(pki: &Pki) -> (Serve, SocketAddr, String) {
    let mut s = Serve::start(Some(pki), &[("SSM_WEB_LISTEN", "127.0.0.1:0"), ("SSM_LOG", "debug")]);
    let addr = listening_addr(&s.wait_for("web: listening on").unwrap_or_else(|| panic!("web starts:\n{}", s.log())));
    let line = s.wait_for("web: no admin yet").unwrap_or_else(|| panic!("the setup link is logged:\n{}", s.log()));
    let at = format!(":{}/setup?t=", addr.port());
    assert!(line.contains("open https://") && line.contains(&at), "an https link to this port: {line}");
    let token: String = line.split(&at).nth(1).unwrap().chars().take_while(char::is_ascii_hexdigit).collect();
    assert_eq!(token.len(), 32, "128 bits as hex: {line}");
    (s, addr, format!("/setup?t={token}"))
}

/// Create the first admin through the setup link; the browser is signed in as it.
async fn first_admin(b: &mut Live<'_>, path: &str) {
    let page = b.send("GET", path, None).await;
    assert_eq!(page.status, 200, "the logged link opens the setup page: {}", page.text());
    let forms = browser::post_forms(&page.text(), "/setup");
    let create = forms.iter().find(|f| f.password_fields().len() == 2).unwrap_or_else(|| panic!("a create-admin form:\n{}", page.text()));
    let (user, pw) = (create.text_field(), create.password_fields());
    let mut body: Vec<(&str, &str)> = create.sent.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    body.extend([(user.as_str(), SETUP_ADMIN), (pw[0].as_str(), SETUP_PW), (pw[1].as_str(), SETUP_PW)]);
    let r = b.send("POST", &create.action, Some(form_body(&body))).await;
    assert_eq!(r.status, 303, "the first admin is created: {}", r.text());
    assert_eq!(r.header("location").map(|l| l.split('?').next().unwrap_or_default()), Some("/accounts"));
}

#[tokio::test]
async fn serve_logs_setup_link_that_works() {
    let pki = Pki::local();
    let (mut s, addr, path) = fresh_serve(&pki);
    let mut b = Live { addr, pki: &pki, cookie: None };
    first_admin(&mut b, &path).await;
    let list = b.send("GET", "/accounts", None).await;
    assert_eq!(list.status, 200, "signed in as the new admin: {}", list.text());
    assert!(list.text().contains(SETUP_ADMIN));
    assert_eq!(b.send("GET", &path, None).await.status, 404, "the link is used up");
    s.settle(Duration::from_millis(500));

    let token = browser::setup_token(&path);
    let log = s.log();
    let with_token: Vec<&str> = log.lines().filter(|l| l.contains(token)).collect();
    assert_eq!(with_token.len(), 1, "the token is logged once, in the setup line, and never again (no query strings):\n{log}");
    assert!(with_token[0].contains("web: no admin yet"));
    assert!(!log.contains(SETUP_PW), "{log}");
}

#[tokio::test]
async fn admin_changes_logged_without_secrets() {
    const USER: &str = "user@example.com";
    const PW1: &str = "first-secret-Passw0rd-2";
    const PW2: &str = "second-secret-Passw0rd-3";
    let pki = Pki::local();
    let (mut s, addr, path) = fresh_serve(&pki);
    let mut b = Live { addr, pki: &pki, cookie: None };
    first_admin(&mut b, &path).await;
    let cookie = b.cookie.clone().expect("a session cookie");

    let list = b.send("GET", "/accounts", None).await.text();
    let csrf = csrf_token(&list).expect("a CSRF token on the list");
    let form = browser::post_form(&list, "/accounts");
    let (user, pw) = (form.text_field(), form.password_fields());
    let r = b.submit(&list, "/accounts", &[(&user, USER), (&pw[0], PW1), (&pw[1], PW1)]).await;
    assert_eq!(r.status, 303, "account added: {}", r.text());

    let rows = b.send("GET", "/accounts", None).await.text();
    let mut pages = Vec::new();
    for h in browser::tags(&rows, "a").into_iter().filter_map(|a| a.attr("href").map(str::to_string)).filter(|h| h.starts_with("/account?id=")) {
        let p = b.send("GET", &h, None).await.text();
        if browser::visible_text(&p).contains(USER) {
            pages.push(p);
        }
    }
    assert_eq!(pages.len(), 1, "one account page shows {USER}:\n{rows}");
    let page = pages.remove(0);
    let pw = browser::post_form(&page, "/account/password").password_fields();
    assert_eq!(b.submit(&page, "/account/password", &[(&pw[0], PW2), (&pw[1], PW2)]).await.status, 303, "password set");
    assert_eq!(b.submit(&page, "/account/disable", &[]).await.status, 303, "sign-in blocked");
    s.settle(Duration::from_millis(500));

    let log = s.log();
    let changes: Vec<&str> = log.lines().filter(|l| l.contains(&format!("web: {SETUP_ADMIN:?}")) && l.contains(&format!("{USER:?}"))).collect();
    assert!(changes.len() >= 3, "add, password and block are logged as `web: {SETUP_ADMIN:?} <action> {USER:?}`:\n{log}");
    let token = browser::setup_token(&path).to_string();
    let log_lower: String = log.lines().filter(|l| !l.contains("web: no admin yet")).collect::<Vec<_>>().join("\n").to_ascii_lowercase();
    for secret in [SETUP_PW, PW1, PW2, &cookie, &csrf, &hex(&sha256(cookie.as_bytes())), &token, "$argon2"] {
        assert!(!log_lower.contains(&secret.to_ascii_lowercase()), "the log holds {secret:?}:\n{log}");
    }
}
