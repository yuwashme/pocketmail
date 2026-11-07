//! The one-time setup link: made at start only when no active admin exists, 128 random bits,
//! valid for 1 h, used up by the first success, and dead as soon as any admin exists (also one
//! made on the command line). It makes an existing account admin (with that account's password,
//! through the sign-in limit) or creates a new admin, then signs that admin in.

mod browser;
mod harness;
mod net;

use std::process::{Command, Stdio};
use std::time::Duration;

use browser::*;
use harness::password;

const ADMIN: &str = "admin@example.com";
const USER: &str = "user@example.com";
const PW: &str = "a-password-for-the-admin";

fn path_of(h: &WebHarness) -> String {
    h.server.setup_path().expect("a setup link while no admin exists")
}

/// A setup link that was never valid.
fn bogus() -> String {
    format!("/setup?t={}", "0123456789abcdef".repeat(2))
}

#[tokio::test]
async fn link_only_without_admin() {
    let h = WebHarness::start_seeded(
        |s| {
            s.create_account(ADMIN, &password(ADMIN)).unwrap();
            s.set_admin(ADMIN, true).unwrap();
        },
        |_| {},
    )
    .await;
    assert_eq!(h.server.setup_path(), None, "no setup link with an admin");
    for path in ["/setup", &bogus()] {
        assert_eq!(h.get(path).await.status, 404, "{path}");
    }

    for (what, h) in [
        ("an empty database", WebHarness::start().await),
        ("only a plain account", WebHarness::start_seeded(|s| _ = s.create_account(USER, &password(USER)).unwrap(), |_| {}).await),
        (
            "only a blocked admin",
            WebHarness::start_seeded(
                |s| {
                    s.create_account(ADMIN, &password(ADMIN)).unwrap();
                    let db = rusqlite::Connection::open(s.data_dir().join("ssm.db")).unwrap();
                    db.execute("UPDATE accounts SET admin = 1, disabled = 1", []).unwrap();
                },
                |_| {},
            )
            .await,
        ),
    ] {
        let path = h.server.setup_path().unwrap_or_else(|| panic!("{what}: a setup link"));
        let token = setup_token(&path);
        assert!(token.len() == 32 && token.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{what}: 128 bits as 32 lowercase hex digits: {path}");
        assert_eq!(h.get(&path).await.status, 200, "{what}: the link opens the setup page");
    }
    let (a, b) = (WebHarness::start().await, WebHarness::start().await);
    assert_ne!(a.server.setup_path(), b.server.setup_path(), "a new random token per start");
}

#[tokio::test]
async fn creates_admin_on_empty_db() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let mut b = h.browser();
    let page = b.get(&path).await;
    assert_eq!(page.status, 200);
    assert_eq!(page.header("cache-control"), Some("no-store"), "the setup page is not cached");

    for (what, login, p, again) in [("passwords differ", ADMIN, PW, "a-password-for-the-admiN"), ("too short", ADMIN, "short", "short"), ("a bad login", "an admin@example.com", PW, PW)] {
        let r = b.setup_create(&path, login, p, again).await;
        assert_eq!(r.status, 422, "{what}: {}", r.text());
        assert_no_session_cookie(&r, what);
        assert!(h.store.accounts().unwrap().is_empty(), "{what}: nothing created");
    }

    let r = b.setup_create(&path, ADMIN, PW, PW).await;
    assert_eq!(r.status, 303, "{}", r.text());
    assert_eq!(location_path(&r), "/accounts");
    assert!(b.cookie.is_some(), "the new admin is signed in: {:?}", r.headers);
    let a = h.account(ADMIN);
    assert!(a.admin && !a.disabled, "{a:?}");
    let list = b.follow(r).await;
    assert_eq!(list.status, 200, "the admin sees the list");
    assert!(list.text().contains(ADMIN));
    assert!(b.imap_login(ADMIN, PW).await, "the new admin works for IMAP too");
    assert_eq!(h.get(&path).await.status, 404, "the link is used up");
}

#[tokio::test]
async fn promotes_existing_with_its_password() {
    let h = WebHarness::start().await;
    h.user(USER);
    let path = path_of(&h);
    let mut b = h.browser();

    let before = h.snapshot();
    for (what, login, p) in [("a wrong password", USER, "not-the-password"), ("an unknown login", "nobody@example.com", "not-the-password")] {
        let r = b.setup_promote(&path, login, p).await;
        assert_eq!(r.status, 422, "{what}: {}", r.text());
        assert!(b.delayed, "{what}: answered after the 2 s delay, like a failed sign-in");
        assert_no_session_cookie(&r, what);
        assert_eq!(h.snapshot(), before, "{what}: nothing changed");
    }

    let r = b.setup_promote(&path, USER, &password(USER)).await;
    assert_eq!(r.status, 303, "{}", r.text());
    assert_eq!(location_path(&r), "/accounts");
    assert!(h.account(USER).admin, "the account is admin now");
    assert_eq!(h.account(USER).auth_stamp, before.accounts[0].3, "its password is unchanged");
    let list = b.follow(r).await;
    assert_eq!(list.status, 200, "signed in as that account");
    assert_eq!(h.get(&path).await.status, 404, "the link is used up");
}

#[tokio::test]
async fn single_use() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let mut slow = h.browser();
    let (_, create) = slow.setup_forms(&path).await;

    let mut b = h.browser();
    assert_eq!(b.setup_create(&path, ADMIN, PW, PW).await.status, 303);

    let (user, pw) = (create.text_field(), create.password_fields());
    let r = slow.submit(&create, &[(&user, "second@example.com"), (&pw[0], PW), (&pw[1], PW)]).await;
    assert_eq!(r.status, 404, "a page opened before the link was used cannot use it again: {}", r.text());
    assert!(h.store.account_id("second@example.com").unwrap().is_none());

    // With no admin again (changed behind the store's back), the used link still stays dead.
    let db = rusqlite::Connection::open(h.tmp.path().join("data/ssm.db")).unwrap();
    db.execute("UPDATE accounts SET admin = 0", []).unwrap();
    assert!(!h.store.has_active_admin().unwrap());
    assert_eq!(h.get(&path).await.status, 404, "used once, dead for good");
    let r = slow.submit(&create, &[(&user, "second@example.com"), (&pw[0], PW), (&pw[1], PW)]).await;
    assert_eq!(r.status, 404, "{}", r.text());
    assert!(h.store.account_id("second@example.com").unwrap().is_none());
}

#[tokio::test]
async fn expires_after_1_h() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let mut b = h.browser();
    let (_, create) = b.setup_forms(&path).await;
    h.clock.advance(Duration::from_secs(3600 - 1));
    assert_eq!(h.get(&path).await.status, 200, "valid until 1 h is up");
    h.clock.advance(Duration::from_secs(2));
    assert_eq!(h.get(&path).await.status, 404, "expired after 1 h");
    let (user, pw) = (create.text_field(), create.password_fields());
    let r = b.submit(&create, &[(&user, ADMIN), (&pw[0], PW), (&pw[1], PW)]).await;
    assert_eq!(r.status, 404, "{}", r.text());
    assert!(h.store.accounts().unwrap().is_empty(), "nothing created");
}

#[tokio::test]
async fn dies_when_cli_makes_admin() {
    let h = WebHarness::start().await;
    h.user(USER);
    let path = path_of(&h);
    let mut b = h.browser();
    let (_, create) = b.setup_forms(&path).await;

    let out = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .args(["account", "admin", USER, "on"])
        .env_clear()
        .env("SSM_DATA_DIR", h.tmp.path().join("data"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "account admin on: {}", String::from_utf8_lossy(&out.stderr));
    assert!(h.store.has_active_admin().unwrap());

    assert_eq!(h.get(&path).await.status, 404, "an admin exists: the link is dead");
    let (user, pw) = (create.text_field(), create.password_fields());
    let r = b.submit(&create, &[(&user, ADMIN), (&pw[0], PW), (&pw[1], PW)]).await;
    assert_eq!(r.status, 404, "a page opened before cannot use it either: {}", r.text());
    assert!(h.store.account_id(ADMIN).unwrap().is_none(), "nothing created");
}

#[tokio::test]
async fn wrong_token_404() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let token = setup_token(&path).to_string();
    let mut b = h.browser();
    let (_, create) = b.setup_forms(&path).await;
    for wrong in [
        "/setup".to_string(),
        "/setup?t=".to_string(),
        bogus(),
        format!("/setup?t={}", one_off(&token)),
        format!("/setup?t={}", token.to_uppercase()),
        format!("/setup?t={token}0"),
        format!("/setup?t={}", &token[..31]),
        format!("/setup?x={token}"),
    ] {
        if wrong == path {
            continue;
        }
        let r = h.get(&wrong).await;
        assert_eq!(r.status, 404, "GET {wrong}");
        let mut f = create.clone();
        f.action = wrong.clone();
        if f.sent.iter().any(|(_, v)| *v == token) {
            f = f.with(&f.sent.iter().find(|(_, v)| *v == token).unwrap().0.clone(), &one_off(&token));
        }
        let (user, pw) = (f.text_field(), f.password_fields());
        let r = b.submit(&f, &[(&user, ADMIN), (&pw[0], PW), (&pw[1], PW)]).await;
        assert_eq!(r.status, 404, "POST {wrong}: {}", r.text());
        assert!(h.store.accounts().unwrap().is_empty(), "POST {wrong}: nothing created");
    }
    assert_eq!(h.get(&path).await.status, 200, "the right link still works");
}

#[tokio::test]
async fn wrong_password_counts_against_limiter() {
    let h = WebHarness::start().await;
    h.user(USER);
    let path = path_of(&h);
    let mut b = h.browser();
    for i in 1..=5 {
        let r = b.setup_promote(&path, USER, "not-the-password").await;
        assert_eq!(r.status, 422, "wrong password {i}");
        assert!(b.delayed, "wrong password {i}: after the 2 s delay");
    }
    let r = b.setup_promote(&path, USER, &password(USER)).await;
    assert_eq!(r.status, 429, "locked: the right password is not checked either: {}", r.text());
    assert!(!b.delayed);
    assert!(!h.account(USER).admin, "not promoted");
    assert_eq!(h.browser().sign_in(USER, &password(USER)).await.status, 429, "sign-in from the same IP is locked too");
    assert_eq!(h.get(&path).await.status, 200, "failures do not use up the link");
}

#[tokio::test]
async fn setup_pages_small_without_script_and_labelled() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let mut b = h.browser();
    let pages = [("setup", b.get(&path).await), ("setup error", b.setup_create(&path, ADMIN, PW, "a-password-for-the-admiN").await)];
    let css = css_source().len();
    for (what, r) in &pages {
        let text = r.text();
        assert!(r.body.len() + css < 20_000, "{what}: {} bytes of HTML + {css} of CSS", r.body.len());
        assert_eq!(r.header("content-security-policy"), Some(CSP), "{what}");
        assert!(!text.to_ascii_lowercase().contains("<script"), "{what}");
        let labels = tags(&text, "label");
        for t in all_tags(&text) {
            assert!(t.attrs.iter().all(|(n, _)| !n.starts_with("on") && n != "style"), "{what}: {t:?}");
            if t.name == "input" && !matches!(t.attr("type"), Some("hidden" | "submit" | "button")) {
                let id = t.attr("id").unwrap_or_else(|| panic!("{what}: input without an id: {t:?}"));
                assert!(labels.iter().any(|l| l.attr("for") == Some(id)), "{what}: no <label for={id:?}>");
            }
        }
    }
}

#[tokio::test]
async fn dead_link_page_says_expired_or_used() {
    let h = WebHarness::start().await;
    let path = path_of(&h);
    let unknown = h.get(&bogus()).await;
    assert_eq!(h.browser().setup_create(&path, ADMIN, PW, PW).await.status, 303);
    let used = h.get(&path).await;

    let later = WebHarness::start().await;
    let old = path_of(&later);
    later.clock.advance(Duration::from_secs(3600));
    let expired = later.get(&old).await;

    for (what, r) in [("unknown link", unknown), ("used link", used), ("expired link", expired)] {
        assert_eq!(r.status, 404, "{what}");
        let text = visible_text(&r.text()).to_lowercase();
        assert!(text.contains("expired") && text.contains("used"), "{what}: says the link has expired or was used: {text}");
        assert!(tags(&r.text(), "a").iter().any(|a| a.attr("href") == Some("/")), "{what}: a link to /:\n{}", r.text());
    }
}
