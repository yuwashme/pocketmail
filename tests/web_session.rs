//! Settings web sessions: the session cookie, idle and absolute expiry on the injected clock,
//! sign out, the CSRF token and the Origin check on every POST, the sign-in rate limit, and
//! sessions ending when the account changes outside the web.

mod browser;
mod harness;
mod net;

use std::collections::HashSet;
use std::time::Duration;

use browser::*;
use harness::password;
use std::net::IpAddr;
use synology_mail_server::web::session::{LOGIN_FAILURES, Limiter, WINDOW};

const ADMIN: &str = "admin@example.com";
const USER: &str = "user@example.com";
const OTHER: &str = "other@example.com";
const NEW: &str = "a-new-password-for-user";
const SEC: Duration = Duration::from_secs(1);
const MIN: Duration = Duration::from_secs(60);

async fn signed_in<'h>(h: &'h WebHarness, login: &str) -> Browser<'h> {
    let mut b = h.browser();
    let r = b.sign_in(login, &password(login)).await;
    assert_eq!(r.status, 303, "sign-in as {login}: {}", r.text());
    assert!(b.cookie.is_some(), "sign-in sets the session cookie: {:?}", r.headers);
    let me = b.get("/me").await;
    assert_eq!(me.status, 200, "own page after sign-in: {:?}", me.header("location"));
    assert!(b.csrf.is_some(), "the own page carries a csrf field:\n{}", me.text());
    b
}

#[track_caller]
fn assert_page_of(r: &Resp, login: &str, what: &str) {
    assert_eq!(r.status, 200, "{what}: still signed in, got {} {:?}", r.status, r.header("location"));
    assert!(r.text().contains(login), "{what}: the page shows {login}");
}

/// Five failed sign-ins from this browser's IP, each for an unknown login (so no login is
/// counted twice); every one answered only after the 2 s delay.
async fn five_failures(b: &mut Browser<'_>) {
    for i in 1..=5 {
        let r = b.sign_in(&format!("nobody{i}@example.com"), "wrong-password").await;
        assert_eq!(r.status, 422, "failure {i}: {}", r.text());
        assert!(b.delayed, "failure {i} is answered after the 2 s delay");
    }
}

fn one_token_off(t: &str) -> String {
    let mut s = t.to_string();
    let last = s.pop().unwrap();
    s.push(if last == '0' { '1' } else { '0' });
    s
}

// ---------------------------------------------------------------------------------------------
// The cookie

#[tokio::test]
async fn login_sets_host_secure_httponly_strict_cookie() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = h.browser();
    let r = b.sign_in(USER, &password(USER)).await;
    assert_eq!(r.status, 303, "{}", r.text());
    let to = location(&r);
    assert!(to.starts_with('/') && !to.starts_with("//"), "a local redirect: {to}");

    let cookies: Vec<SetCookie> = r.all("set-cookie").into_iter().map(SetCookie::parse).collect();
    assert_eq!(cookies.len(), 1, "{:?}", r.headers);
    let c = &cookies[0];
    assert_eq!(c.name, COOKIE);
    assert!(is_hex64(&c.value), "a 256-bit id as 64 lowercase hex digits: {:?}", c.value);
    assert_eq!(c.attr("path"), Some("/"), "{c:?}");
    assert!(c.has("secure") && c.has("httponly"), "{c:?}");
    assert!(c.attr("samesite").is_some_and(|v| v.eq_ignore_ascii_case("strict")), "{c:?}");
    for absent in ["domain", "max-age", "expires"] {
        assert!(!c.has(absent), "a session cookie without {absent}: {c:?}");
    }
    assert!(!to.contains(&c.value) && !r.text().contains(&c.value), "the id is only in Set-Cookie");

    let me = b.follow(r).await;
    assert_page_of(&me, USER, "after sign-in");
}

#[tokio::test]
async fn new_256_bit_id_per_login() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = h.browser();
    let mut ids = Vec::new();
    for i in 0..16 {
        let r = b.sign_in(USER, &password(USER)).await;
        assert_eq!(r.status, 303, "login {i}");
        let id = b.cookie.clone().expect("a session cookie");
        assert!(is_hex64(&id), "login {i}: {id:?}");
        ids.push(id);
    }
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len(), "every login gets a new id: {ids:?}");
    for pos in 0..64 {
        let at: HashSet<u8> = ids.iter().map(|id| id.as_bytes()[pos]).collect();
        assert!(at.len() > 1, "hex digit {pos} is the same in 16 ids (not random): {ids:?}");
    }

    let mut other = signed_in(&h, USER).await;
    let mut this = signed_in(&h, USER).await;
    assert_ne!(other.csrf, this.csrf, "each session has its own token");
    assert_ne!(this.cookie, this.csrf, "the token is not the id");
    assert_page_of(&other.get("/me").await, USER, "first of two sessions");
    assert_page_of(&this.get("/me").await, USER, "second of two sessions");
}

// ---------------------------------------------------------------------------------------------
// Expiry

#[tokio::test]
async fn idle_30_min_ends() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    no_timers_left(&h.clock, "a signed-in session (expiry is checked on use)").await;

    h.clock.advance(IDLE_LIMIT - SEC);
    assert_page_of(&b.get("/me").await, USER, "29:59 idle");
    h.clock.advance(IDLE_LIMIT - SEC);
    assert_page_of(&b.get("/me").await, USER, "29:59 idle again (each request restarts the idle time)");

    h.clock.advance(IDLE_LIMIT + SEC);
    assert_to_login(&b.get("/me").await, "30:01 idle");
    assert_to_login(&b.get("/me").await, "the ended session stays ended");
    assert_to_login(&b.get("/").await, "the ended session stays ended (/)");
}

#[tokio::test]
async fn twelve_hours_ends_active() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    let step = 20 * MIN;
    for i in 1..=35 {
        h.clock.advance(step);
        assert_page_of(&b.get("/me").await, USER, &format!("active, {} min after sign-in", i * 20));
    }
    h.clock.advance(step + SEC);
    assert_to_login(&b.get("/me").await, "12 h 00 min 01 s after sign-in, though active");
}

#[tokio::test]
async fn logout_ends_and_clears_cookie() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    let id = b.cookie.clone().unwrap();

    let r = b.post("/logout", &[]).await;
    assert_to_login(&r, "sign out");
    let cleared: Vec<SetCookie> = r.all("set-cookie").into_iter().map(SetCookie::parse).filter(|c| c.name == COOKIE).collect();
    assert_eq!(cleared.len(), 1, "sign out clears the cookie: {:?}", r.headers);
    let c = &cleared[0];
    assert!(c.value.is_empty() && (c.attr("max-age") == Some("0") || c.has("expires")), "an empty, expired cookie: {c:?}");
    assert!(c.attr("path") == Some("/") && c.has("secure"), "__Host- cookies are only replaced with Path=/ and Secure: {c:?}");
    assert!(b.cookie.is_none());

    b.cookie = Some(id);
    assert_to_login(&b.get("/me").await, "the old id after sign out");
}

// ---------------------------------------------------------------------------------------------
// CSRF and Origin

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_logout() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    let other = signed_in(&h, USER).await;
    let token = b.csrf.clone().unwrap();
    let others = other.csrf.clone().unwrap();
    let off = one_token_off(&token);
    let cases: [(&str, Vec<(&str, &str)>); 5] = [
        ("no token", vec![]),
        ("empty token", vec![(CSRF_FIELD, "")]),
        ("token one digit off", vec![(CSRF_FIELD, &off)]),
        ("short token", vec![(CSRF_FIELD, "x")]),
        ("another session's token", vec![(CSRF_FIELD, &others)]),
    ];
    for (what, form) in cases {
        let r = b.post_exact("/logout", &form).await;
        assert_eq!(r.status, 403, "sign out with {what}");
        assert_page_of(&b.get("/me").await, USER, &format!("after sign out with {what}"));
    }
    assert_to_login(&b.post("/logout", &[]).await, "sign out with the token");
    assert_to_login(&b.get("/me").await, "after sign out");
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_me_password() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;
    let mut other = signed_in(&h, USER).await;
    let (c, n, a) = password_fields(&b.get("/me").await.text());
    let token = b.csrf.clone().unwrap();
    let others = other.csrf.clone().unwrap();
    let off = one_token_off(&token);
    for (what, t) in [("no token", None), ("empty token", Some("")), ("token one digit off", Some(off.as_str())), ("another session's token", Some(others.as_str()))] {
        let mut form = vec![(c.as_str(), pw.as_str()), (n.as_str(), NEW), (a.as_str(), NEW)];
        form.extend(t.map(|t| (CSRF_FIELD, t)));
        let r = b.post_exact("/me/password", &form).await;
        assert_eq!(r.status, 403, "password change with {what}");
    }
    assert!(b.imap_login(USER, &pw).await, "the old password still works");
    assert!(!b.imap_login(USER, NEW).await, "the new one was never set");
    assert_page_of(&other.get("/me").await, USER, "the other session (a change would have ended it)");
}

#[tokio::test]
async fn login_needs_same_origin() {
    let h = WebHarness::start().await;
    h.user(USER);
    let (u, p) = h.login_fields().await;
    let pw = password(USER);
    let mut b = h.browser();
    for origin in [None, Some("https://evil.example.com".to_string())] {
        b.origin = origin.clone();
        let r = b.post_exact("/login", &[(&u, USER), (&p, &pw)]).await;
        assert_eq!(r.status, 403, "sign-in with Origin {origin:?}");
        assert_no_session_cookie(&r, "a refused sign-in");
    }
    b.origin = Some(h.origin());
    let r = b.post_exact("/login", &[(&u, USER), (&p, &pw)]).await;
    assert_eq!(r.status, 303, "same-origin sign-in, no csrf field needed: {}", r.text());
    assert!(b.cookie.is_some());
}

#[tokio::test]
async fn foreign_or_missing_origin_403() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let host = h.host();
    let port = h.addr.port();
    let origins = [
        None,
        Some("null".to_string()),
        Some("https://evil.example.com".to_string()),
        Some(format!("http://{host}")),
        Some(format!("https://{host}.evil.example.com")),
        Some("https://localhost".to_string()),
        Some(format!("https://localhost:{}", port.wrapping_add(1))),
    ];
    let (u, p) = h.login_fields().await;
    let mut b = signed_in(&h, USER).await;
    let (c, n, a) = password_fields(&b.get("/me").await.text());
    for origin in origins {
        let mut anon = h.browser();
        anon.origin = origin.clone();
        let r = anon.post_exact("/login", &[(&u, USER), (&p, &pw)]).await;
        assert_eq!(r.status, 403, "/login with Origin {origin:?}");
        assert_no_session_cookie(&r, "/login from another origin");

        b.origin = origin.clone();
        let r = b.post("/logout", &[]).await;
        assert_eq!(r.status, 403, "/logout with Origin {origin:?}");
        let r = b.post("/me/password", &[(&c, &pw), (&n, NEW), (&a, NEW)]).await;
        assert_eq!(r.status, 403, "/me/password with Origin {origin:?}");
        assert_page_of(&b.get("/me").await, USER, &format!("still signed in after Origin {origin:?}"));
    }
    assert!(b.imap_login(USER, &pw).await, "the password never changed");
}

/// A page sent with `Referrer-Policy: no-referrer` makes Chrome send `Origin: null` on its form
/// posts; whatever the policy, such a post is refused.
#[tokio::test]
async fn origin_null_refused_nothing_changes() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let create = post_form(&b.get("/accounts").await.text(), "/accounts");
    let block = b.account_form(USER, "/account/disable").await;
    let address = b.account_form(USER, "/account/address/add").await;
    let before = h.snapshot();

    b.origin = Some("null".into());
    let (user, pw) = (create.text_field(), create.password_fields());
    let r = b.submit(&create, &[(&user, "new@example.com"), (&pw[0], NEW), (&pw[1], NEW)]).await;
    assert_eq!(r.status, 403, "add account with Origin: null");
    assert_eq!(b.submit(&block, &[]).await.status, 403, "block sign-in with Origin: null");
    let field = address.text_field();
    assert_eq!(b.submit(&address, &[(&field, "info@example.com")]).await.status, 403, "add address with Origin: null");
    assert_eq!(b.post("/logout", &[]).await.status, 403, "sign out with Origin: null");
    assert_eq!(h.snapshot(), before, "nothing changed");
    b.origin = Some(h.origin());
    assert_eq!(b.get("/accounts").await.status, 200, "still signed in");

    let mut anon = h.browser();
    anon.origin = Some("null".into());
    let r = anon.sign_in(USER, &password(USER)).await;
    assert_eq!(r.status, 403, "sign-in with Origin: null");
    assert_no_session_cookie(&r, "a sign-in with Origin: null");
}

#[tokio::test]
async fn session_checked_before_csrf() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;
    let (c, n, a) = password_fields(&b.get("/me").await.text());

    let mut anon = h.browser();
    for (what, cookie) in [("no cookie", None), ("a made-up id", Some("ab".repeat(32)))] {
        anon.cookie = cookie;
        assert_to_login(&anon.post_exact("/me/password", &[(&c, &pw), (&n, NEW), (&a, NEW)]).await, &format!("{what}, no token"));
        assert_to_login(&anon.post_exact("/me/password", &[(&c, &pw), (&n, NEW), (&a, NEW), (CSRF_FIELD, "x")]).await, &format!("{what}, a token"));
        assert_to_login(&anon.post_exact("/logout", &[]).await, &format!("sign out with {what}"));
    }

    h.clock.advance(IDLE_LIMIT + SEC);
    let r = b.post("/me/password", &[(&c, &pw), (&n, NEW), (&a, NEW)]).await;
    assert_to_login(&r, "an expired session with its old token");
    assert!(b.imap_login(USER, &pw).await, "nothing changed");
}

// ---------------------------------------------------------------------------------------------
// Sign-in rate limit

#[tokio::test]
async fn five_failures_lock_ip_15_min() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();
    five_failures(&mut b).await;

    let r = b.sign_in(USER, &pw).await;
    assert_eq!(r.status, 429, "the IP is locked, for a login that never failed too: {}", r.text());
    assert_no_session_cookie(&r, "a locked sign-in");
    assert!(b.imap_login(USER, &pw).await, "the web lock does not touch IMAP");

    h.clock.advance(14 * MIN + 30 * SEC);
    assert_eq!(b.sign_in(USER, &pw).await.status, 429, "still locked at 14:40");
    h.clock.advance(40 * SEC);
    let r = b.sign_in(USER, &pw).await;
    assert_eq!(r.status, 303, "the window is over at 15:20: {}", r.text());
}

#[tokio::test]
async fn success_keeps_the_ip_count() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();
    for i in 1..=4 {
        let r = b.sign_in(&format!("nobody{i}@example.com"), "wrong-password").await;
        assert_eq!(r.status, 422, "failure {i}");
    }
    let r = b.sign_in(USER, &pw).await;
    assert_eq!(r.status, 303, "four failures do not lock: {}", r.text());

    b.forget();
    let r = b.sign_in("nobody5@example.com", "wrong-password").await;
    assert_eq!(r.status, 422, "the fifth failure from this IP");
    let r = b.sign_in(USER, &pw).await;
    assert_eq!(r.status, 429, "one account's success does not clear the IP's count, so the fifth failure locks the IP: {}", r.text());
    assert_no_session_cookie(&r, "a locked sign-in");
}

#[tokio::test]
async fn password_change_keeps_the_ip_count() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;
    let mut other = h.browser();
    for i in 1..=4 {
        assert_eq!(other.sign_in(&format!("nobody{i}@example.com"), "wrong-password").await.status, 422, "failure {i}");
    }
    let r = b.change_password(&pw, NEW, NEW).await;
    assert_eq!(r.status, 303, "the password change: {}", r.text());

    assert_eq!(other.sign_in("nobody5@example.com", "wrong-password").await.status, 422, "the fifth failure from this IP");
    let r = other.sign_in(USER, NEW).await;
    assert_eq!(r.status, 429, "a password change does not clear the IP's count: {}", r.text());
}

#[test]
fn success_clears_only_that_logins_count() {
    let l = Limiter::default();
    let t0 = Duration::from_secs(1000);
    let ip = |s: String| -> IpAddr { s.parse().unwrap() };
    let client = ip("192.168.1.50".into());
    for i in 1..=4 {
        l.failed(client, &format!("nobody{i}@example.com"), t0);
    }
    for i in 1..LOGIN_FAILURES {
        l.failed(ip(format!("192.168.2.{i}")), USER, t0);
        l.failed(ip(format!("192.168.3.{i}")), OTHER, t0);
    }
    l.succeeded(client, USER);

    l.failed(ip("192.168.4.1".into()), USER, t0);
    assert_eq!(l.locked(ip("192.168.4.2".into()), USER, t0), None, "the success cleared the count of its login");
    l.failed(ip("192.168.4.3".into()), OTHER, t0);
    assert!(l.locked(ip("192.168.4.4".into()), OTHER, t0).is_some(), "another login's count is kept");
    l.failed(client, "nobody5@example.com", t0);
    assert!(l.locked(client, "nobody6@example.com", t0).is_some(), "the client's count is kept: its fifth failure locks it");
}

/// The web harness has one client address (127.0.0.1), so this is checked on the limiter, with
/// the time passed in.
#[test]
fn ten_failures_from_different_clients_lock_the_login() {
    let l = Limiter::default();
    let t0 = Duration::from_secs(1000);
    let ip = |s: String| -> IpAddr { s.parse().unwrap() };
    let clients: Vec<IpAddr> = (1..=5).map(|i| ip(format!("192.168.1.{i}"))).chain((1..=5).map(|i| ip(format!("fd00:0:0:{i}::1")))).collect();
    assert_eq!(clients.len() as u32, LOGIN_FAILURES);
    let fresh = ip("10.0.0.1".into());
    let mut now = t0;
    for (n, c) in clients.iter().enumerate() {
        assert_eq!(l.locked(fresh, USER, now), None, "{n} failures do not lock the login");
        l.failed(*c, USER, now);
        assert_eq!(l.locked(*c, OTHER, now), None, "one failure does not lock client {c}");
        now += SEC;
    }
    assert_eq!(l.locked(fresh, USER, now), Some(WINDOW - SEC), "ten failures from ten clients lock the login, from any client, for a whole window");
    assert_eq!(l.locked(fresh, OTHER, now), None, "only that login");
    assert!(l.locked(fresh, USER, now + WINDOW - 2 * SEC).is_some(), "locked until the window ends");
    assert_eq!(l.locked(fresh, USER, now + WINDOW - SEC), None, "and not after");
}

#[tokio::test]
async fn locked_skips_password_check_even_if_correct() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();
    for i in 1..=5 {
        assert_eq!(b.sign_in(USER, "wrong-password").await.status, 422, "failure {i}");
    }

    let right = b.sign_in(USER, &pw).await;
    assert_eq!(right.status, 429);
    assert!(!b.delayed, "no 2 s delay: the password is not checked");
    assert_no_session_cookie(&right, "the right password while locked");
    let wrong = b.sign_in(USER, "wrong-password").await;
    assert_eq!(wrong.status, 429);
    assert!(!b.delayed, "no 2 s delay for a wrong password while locked either");
    assert_eq!(right.text().replace(&pw, ""), wrong.text().replace("wrong-password", ""), "a locked answer says nothing about the password");

    // Five 2 s delays put the clock at 0:10; this moves it to 15:20.
    h.clock.advance(LOCK_WINDOW + 10 * SEC);
    let r = b.sign_in(USER, &pw).await;
    assert_eq!(r.status, 303, "attempts while locked do not extend the lock: {}", r.text());
}

#[tokio::test]
async fn same_message_after_2_s_for_wrong_login_or_password() {
    let h = WebHarness::start().await;
    h.user(USER);
    let (u, p) = h.login_fields().await;
    let plain = h.get("/login").await.text();
    let b = h.browser();
    let mut pages = Vec::new();
    for (login, pw) in [(USER, "wrong-password".to_string()), ("nobody@example.com", password(USER))] {
        let bytes = b.request("POST", "/login", Some(&form_body(&[(&u, login), (&p, &pw)])));
        let mark = h.clock.mark();
        let mut w = h.open().await;
        w.write(&bytes).await;
        h.clock.wait_sleep_since(mark, harness::AUTH_DELAY, "the failed sign-in delay").await;
        assert!(w.nothing_within(Duration::from_millis(200)).await, "{login}: no answer before the clock moves 2 s");
        h.clock.advance(harness::AUTH_DELAY);
        let r = w.read_response(false).await.expect("an answer after 2 s");
        assert_eq!(r.status, 422, "{login}: {}", r.text());
        assert_no_session_cookie(&r, login);
        pages.push(r.text().replace(login, "LOGIN"));
    }
    assert_eq!(pages[0], pages[1], "a wrong password and an unknown login get the same page");
    assert_ne!(pages[0], plain, "the page says the sign-in failed");
}

#[tokio::test]
async fn lock_message_gives_minutes() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();
    five_failures(&mut b).await;
    for (advance, minutes) in [(Duration::ZERO, "15 minutes"), (7 * MIN, "8 minutes"), (7 * MIN + 20 * SEC, "1 minute")] {
        h.clock.advance(advance);
        let r = b.sign_in(USER, &pw).await;
        assert_eq!(r.status, 429);
        let want = format!("Too many attempts, try again in {minutes}");
        assert!(r.text().contains(&want), "{want:?} in:\n{}", r.text());
    }
}

// ---------------------------------------------------------------------------------------------
// The account changes outside the web

#[tokio::test]
async fn password_changed_outside_web_ends_sessions() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    let (c, n, a) = password_fields(&b.get("/me").await.text());

    h.store.set_password(USER, NEW).unwrap();
    assert_to_login(&b.get("/me").await, "after a password change on the command line");
    assert_to_login(&b.post("/me/password", &[(&c, NEW), (&n, "yet-another-password"), (&a, "yet-another-password")]).await, "POST after it");

    let r = b.sign_in(USER, NEW).await;
    assert_eq!(r.status, 303, "the new password signs in");
    assert_page_of(&b.get("/me").await, USER, "signed in again");
    h.store.set_password(USER, NEW).unwrap();
    assert_to_login(&b.get("/me").await, "setting the same password again also ends sessions");
}

#[tokio::test]
async fn disabled_account_session_ends_and_login_blocked() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;

    h.store.set_disabled(USER, true).unwrap();
    assert_to_login(&b.get("/me").await, "after the account is disabled");

    let blocked = b.sign_in(USER, &pw).await;
    assert!((400..500).contains(&blocked.status), "{}", blocked.status);
    assert_no_session_cookie(&blocked, "a disabled account");
    let text = blocked.text().to_lowercase();
    assert!(text.contains("blocked") && text.contains("admin"), "says sign-in is blocked and to ask the admin:\n{}", blocked.text());

    let wrong = b.sign_in(USER, "wrong-password").await;
    let unknown = b.sign_in("nobody@example.com", "wrong-password").await;
    assert_eq!(wrong.status, unknown.status);
    assert_eq!(
        wrong.text().replace(USER, "LOGIN"),
        unknown.text().replace("nobody@example.com", "LOGIN"),
        "with a wrong password a disabled account looks like any failed sign-in"
    );

    h.store.set_disabled(USER, false).unwrap();
    assert_eq!(b.sign_in(USER, &pw).await.status, 303, "enabled again");
}
