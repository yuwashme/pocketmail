//! Admin account pages: the list, adding an account, setting a password, blocking and allowing
//! sign-in, and granting or removing admin. Admins only; ids, never logins, in URLs. An admin
//! cannot block or demote themselves on the web, and the last active admin always remains.

mod browser;
mod harness;
mod net;

use browser::*;
use harness::password;
use synology_mail_server::store::{Delivery, DeliveryOutcome, check_login};

const ADMIN: &str = "admin@example.com";
const USER: &str = "user@example.com";
const PW: &str = "a-password-for-a-new-account";
const NEW: &str = "a-new-password-set-by-admin";
const LAST_ADMIN: &str = "At least one admin must remain";

/// Deliver a small message to `to` through the store.
fn deliver(h: &WebHarness, to: &str, n: u32) -> DeliveryOutcome {
    let body = format!("Subject: test {n}\r\n\r\nhello\r\n").into_bytes();
    let key = format!("msg:1767225600000:00000000-0000-4000-8000-{n:012}");
    let d = Delivery {
        key: &key,
        envelope_from: "sender@example.com",
        envelope_to: to,
        received_ms: 1_767_225_600_000,
        expected_size: body.len() as u64,
    };
    h.store.deliver(&d, &mut &body[..]).unwrap()
}

/// The column of the header row whose text contains `word` (case ignored).
fn column(rows: &[(Vec<String>, String)], word: &str) -> usize {
    let header = &rows.first().expect("a header row").0;
    header
        .iter()
        .position(|c| c.to_lowercase().contains(word))
        .unwrap_or_else(|| panic!("a {word:?} column in {header:?}"))
}

/// The row whose cells include `login` exactly.
fn row<'r>(rows: &'r [(Vec<String>, String)], login: &str) -> &'r (Vec<String>, String) {
    let found: Vec<_> = rows
        .iter()
        .filter(|(cells, _)| cells.iter().any(|c| c == login))
        .collect();
    assert_eq!(found.len(), 1, "one row for {login}: {rows:?}");
    found[0]
}

#[tokio::test]
async fn admin_sees_all_accounts_fields_addresses() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user("alice@example.com");
    h.store
        .add_address("info@example.com", "alice@example.com")
        .unwrap();
    h.user("bob@example.com");
    h.store.set_disabled("bob@example.com", true).unwrap();
    h.admin("carol@example.com");
    h.user("dave@example.com");
    h.store
        .add_address("@example.org", "dave@example.com")
        .unwrap();

    let mut b = h.signed_in(ADMIN).await;
    let r = b.get("/").await;
    assert_eq!(r.status, 303);
    assert_eq!(
        location_path(&r),
        "/accounts",
        "/ sends an admin to the account list"
    );

    let r = b.get("/accounts").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let text = r.text();
    let rows = table_rows(&text);
    let (created, admin, blocked, addresses) = (
        column(&rows, "created"),
        column(&rows, "admin"),
        column(&rows, "block"),
        column(&rows, "address"),
    );
    for (login, is_admin, is_blocked, own, others) in [
        (
            ADMIN,
            true,
            false,
            vec![ADMIN],
            vec!["alice@", "info@", "example.org"],
        ),
        (
            "alice@example.com",
            false,
            false,
            vec!["alice@example.com", "info@example.com"],
            vec!["admin@", "example.org"],
        ),
        (
            "bob@example.com",
            false,
            true,
            vec!["bob@example.com"],
            vec!["info@", "example.org"],
        ),
        (
            "carol@example.com",
            true,
            false,
            vec!["carol@example.com"],
            vec!["info@"],
        ),
        (
            "dave@example.com",
            false,
            false,
            vec!["dave@example.com", "@example.org"],
            vec!["info@"],
        ),
    ] {
        let (cells, markup) = row(&rows, login);
        let account = h.account(login);
        assert_eq!(
            cells[created],
            date(account.created_at),
            "{login}: the date created"
        );
        assert_eq!(
            cells[admin].to_lowercase(),
            if is_admin { "yes" } else { "no" },
            "{login}: admin"
        );
        assert_eq!(
            cells[blocked].to_lowercase(),
            if is_blocked { "yes" } else { "no" },
            "{login}: sign-in blocked"
        );
        for a in own {
            assert!(
                cells[addresses].contains(a),
                "{login}: address {a} in {:?}",
                cells[addresses]
            );
        }
        for a in others {
            assert!(
                !cells[addresses].contains(a),
                "{login}: {a} is not this account's: {:?}",
                cells[addresses]
            );
        }
        let href = account_href(account.id.0);
        assert!(
            tags(markup, "a")
                .iter()
                .any(|a| a.attr("href") == Some(href.as_str())),
            "{login}: a link to {href} in {markup}"
        );
    }
    let (cells, _) = row(&rows, "dave@example.com");
    assert!(
        cells[addresses].contains("all other mail for example.org"),
        "the catch-all in plain words: {:?}",
        cells[addresses]
    );
    for a in tags(&text, "a") {
        let href = a.attr("href").unwrap_or_default();
        assert!(
            !href.contains("example.com") && !href.contains("example.org"),
            "ids, not logins, in links: {href}"
        );
    }

    let page = b.account_page("alice@example.com").await;
    for shown in [
        "alice@example.com",
        "info@example.com",
        &date(h.account("alice@example.com").created_at),
    ] {
        assert!(page.contains(shown), "{shown} on the account page:\n{page}");
    }
    assert_eq!(
        b.get(&account_href(9999)).await.status,
        404,
        "no such account"
    );
}

#[tokio::test]
async fn added_account_logs_in_to_imap_at_once() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    let mut b = h.signed_in(ADMIN).await;
    let r = b.create_account(USER, PW, PW).await;
    assert_done(&r, "add an account");
    assert!(
        !location(&r).contains(USER) && !location(&r).contains(PW),
        "nothing typed in the redirect: {}",
        location(&r)
    );
    assert_eq!(b.follow(r).await.status, 200);

    let a = h.account(USER);
    assert!(
        !a.admin && !a.disabled,
        "a new account is a plain, enabled one: {a:?}"
    );
    assert!(
        b.imap_login(USER, PW).await,
        "IMAP takes the new account at once"
    );
    assert_eq!(
        h.browser().sign_in(USER, PW).await.status,
        303,
        "so does the web"
    );
    let list = b.get("/accounts").await.text();
    assert!(
        table_rows(&list)
            .iter()
            .any(|(cells, _)| cells.iter().any(|c| c == USER)),
        "listed:\n{list}"
    );
}

#[tokio::test]
async fn field_errors_keep_login_never_password() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    let mut b = h.signed_in(ADMIN).await;
    let form = post_form(&b.get("/accounts").await.text(), "/accounts");
    let (login_field, pw) = (form.text_field(), form.password_fields());
    for (what, login, p, again, bad) in [
        (
            "passwords differ",
            USER,
            PW,
            "another-secret-password",
            &pw[1],
        ),
        (
            "password too short",
            USER,
            "eleven-char",
            "eleven-char",
            &pw[0],
        ),
        (
            "login with a space",
            "user name@example.com",
            PW,
            PW,
            &login_field,
        ),
    ] {
        let r = b.create_account(login, p, again).await;
        assert_eq!(r.status, 422, "{what}: {}", r.text());
        let text = r.text();
        assert_field_error(&text, "/accounts", bad, what);
        assert_eq!(
            field_value(&text, "/accounts", &login_field).as_deref(),
            Some(login),
            "{what}: the login is kept"
        );
        for name in &pw {
            assert!(
                field_value(&text, "/accounts", name).is_none_or(|v| v.is_empty()),
                "{what}: password fields come back empty"
            );
        }
        for s in [PW, "another-secret-password", "eleven-char"] {
            assert!(!text.contains(s), "{what}: no password on the page");
        }
    }
    assert!(
        h.store.account_id(USER).unwrap().is_none(),
        "nothing was added"
    );
}

#[tokio::test]
async fn passwords_must_match() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;

    let before = h.snapshot();
    let r = b
        .create_account("new@example.com", PW, "a-password-for-a-new-accounT")
        .await;
    assert_eq!(r.status, 422, "{}", r.text());
    let pw = post_form(&r.text(), "/accounts").password_fields();
    assert!(
        pw.iter()
            .all(|n| field_value(&r.text(), "/accounts", n).is_none_or(|v| v.is_empty())),
        "password fields come back empty"
    );
    assert_field_error(
        &r.text(),
        "/accounts",
        &pw[1],
        "new account: passwords differ",
    );

    let r = b
        .set_password(USER, NEW, "a-new-password-set-by-admiN")
        .await;
    assert_eq!(r.status, 422, "{}", r.text());
    let pw = post_form(&r.text(), "/account/password").password_fields();
    assert_field_error(
        &r.text(),
        "/account/password",
        &pw[1],
        "set password: passwords differ",
    );
    assert_eq!(h.snapshot(), before, "nothing changed");
    assert!(
        b.imap_login(USER, &password(USER)).await,
        "the old password still works"
    );
}

#[tokio::test]
async fn login_rules_match_cli() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    let mut b = h.signed_in(ADMIN).await;
    let long = |n: usize| format!("{}@example.com", "a".repeat(n - "@example.com".len()));
    let cases = [
        ("empty", String::new()),
        ("a space", "user name@example.com".to_string()),
        ("a tab", "user\tname@example.com".to_string()),
        ("a line break", "user\nname@example.com".to_string()),
        ("a control character", "user\u{7}@example.com".to_string()),
        ("256 bytes", long(256)),
        ("255 bytes", long(255)),
        ("no @, as the CLI allows", "alice".to_string()),
        ("non-ASCII", "žiga@example.com".to_string()),
    ];
    let form = post_form(&b.get("/accounts").await.text(), "/accounts");
    let field = form.text_field();
    for (what, login) in cases {
        let r = b.create_account(&login, PW, PW).await;
        let exists = h.store.account_id(&login).unwrap().is_some();
        if check_login(&login).is_ok() {
            assert_done(&r, what);
            assert!(exists, "{what}: added");
        } else {
            assert_eq!(
                r.status,
                422,
                "{what}: refused as the CLI refuses it: {}",
                r.text()
            );
            assert_field_error(&r.text(), "/accounts", &field, what);
            assert!(!exists, "{what}: not added");
        }
    }
}

#[tokio::test]
async fn web_password_min_12_chars_max_1024_bytes() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let refused = [
        ("11 characters", "a".repeat(11)),
        ("11 two-byte characters (22 bytes)", "ž".repeat(11)),
        ("1,025 bytes", "a".repeat(1025)),
        ("1,026 bytes in 513 characters", "ž".repeat(513)),
        ("a line break", "first-line-of\nthe-password".to_string()),
    ];
    for (i, (what, p)) in refused.iter().enumerate() {
        let login = format!("refused{i}@example.com");
        let r = b.create_account(&login, p, p).await;
        assert_eq!(r.status, 422, "new account, {what}: {}", r.text());
        assert!(
            h.store.account_id(&login).unwrap().is_none(),
            "new account, {what}: not added"
        );
        let r = b.set_password(USER, p, p).await;
        assert_eq!(r.status, 422, "set password, {what}: {}", r.text());
    }
    assert!(
        b.imap_login(USER, &password(USER)).await,
        "the password was never changed"
    );

    let taken = [
        ("12 characters", "a".repeat(12)),
        ("12 two-byte characters", "ž".repeat(12)),
        ("1,024 bytes", "b".repeat(1024)),
        ("1,024 bytes in 512 characters", "ž".repeat(512)),
    ];
    for (i, (what, p)) in taken.iter().enumerate() {
        let login = format!("taken{i}@example.com");
        assert_done(
            &b.create_account(&login, p, p).await,
            &format!("new account, {what}"),
        );
        assert_eq!(
            h.browser().sign_in(&login, p).await.status,
            303,
            "new account, {what}: signs in"
        );
        assert_done(
            &b.set_password(USER, p, p).await,
            &format!("set password, {what}"),
        );
        assert_eq!(
            h.browser().sign_in(USER, p).await.status,
            303,
            "set password, {what}: signs in"
        );
    }
}

#[tokio::test]
async fn existing_login_already_exists_no_change() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let before = h.snapshot();
    let r = b.create_account(USER, PW, PW).await;
    assert_eq!(r.status, 409, "{}", r.text());
    assert!(
        r.text().contains("already exists"),
        "says so:\n{}",
        r.text()
    );
    assert_eq!(h.snapshot(), before, "nothing changed");
    assert!(
        b.imap_login(USER, &password(USER)).await,
        "the old password still works"
    );
    assert!(!b.imap_login(USER, PW).await, "the typed one was not set");
}

#[tokio::test]
async fn admin_sets_password_old_fails_imap_and_web_sessions_end() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let old = password(USER);
    let mut user = h.signed_in(USER).await;
    let mut other = h.signed_in(USER).await;
    assert_eq!(user.get("/me").await.status, 200);

    let mut b = h.signed_in(ADMIN).await;
    let r = b.set_password(USER, NEW, NEW).await;
    assert_done(&r, "set the password");
    assert_eq!(b.follow(r).await.status, 200);

    assert_to_login(&user.get("/me").await, "the user's session ended");
    assert_to_login(&other.get("/me").await, "every session of the user ended");
    assert_eq!(
        b.get("/accounts").await.status,
        200,
        "the admin's session stays"
    );
    assert!(
        !b.imap_login(USER, &old).await,
        "IMAP refuses the old password"
    );
    assert!(b.imap_login(USER, NEW).await, "IMAP takes the new one");
    assert_eq!(
        h.browser().sign_in(USER, &old).await.status,
        422,
        "the web refuses the old password"
    );
    assert_eq!(
        h.browser().sign_in(USER, NEW).await.status,
        303,
        "the web takes the new one"
    );
}

#[tokio::test]
async fn no_page_shows_password_or_argon2() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let secrets = [
        password(ADMIN),
        password(USER),
        PW.to_string(),
        NEW.to_string(),
        "another-secret-password".to_string(),
    ];
    let mut b = h.signed_in(ADMIN).await;
    let mut pages = vec![
        ("list", b.get("/accounts").await),
        ("account page", b.get(&account_href(h.id(USER))).await),
    ];
    pages.push((
        "create, passwords differ",
        b.create_account("new@example.com", PW, "another-secret-password")
            .await,
    ));
    let r = b.create_account("new@example.com", PW, PW).await;
    pages.push(("created", r.clone()));
    pages.push(("created, followed", b.follow(r).await));
    pages.push(("create, exists", b.create_account(USER, PW, PW).await));
    pages.push((
        "set, passwords differ",
        b.set_password(USER, NEW, "another-secret-password").await,
    ));
    let r = b.set_password(USER, NEW, NEW).await;
    pages.push(("set", r.clone()));
    pages.push(("set, followed", b.follow(r).await));
    pages.push((
        "new account's page",
        b.get(&account_href(h.id("new@example.com"))).await,
    ));
    pages.push(("list after", b.get("/accounts").await));
    for (what, r) in &pages {
        let all = format!("{:?}\n{}", r.headers, r.text());
        for s in &secrets {
            assert!(
                !all.contains(s.as_str()),
                "{what} shows a password ({s:?}):\n{all}"
            );
        }
        assert!(!all.contains("$argon2"), "{what} shows a hash:\n{all}");
    }
}

#[tokio::test]
async fn disable_blocks_imap_and_web_ends_sessions_mail_arrives() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let pw = password(USER);
    let mut user = h.signed_in(USER).await;
    let mut b = h.signed_in(ADMIN).await;

    let form = b.account_form(USER, "/account/disable").await;
    assert!(
        visible_text(&form.html).contains("Block sign-in"),
        "the button says Block sign-in: {}",
        form.html
    );
    let r = b.submit(&form, &[]).await;
    assert_done(&r, "block sign-in");
    assert!(h.account(USER).disabled);

    assert_to_login(&user.get("/me").await, "the user's session ended");
    assert!(
        !b.imap_login(USER, &pw).await,
        "IMAP refuses a blocked account"
    );
    let r = h.browser().sign_in(USER, &pw).await;
    assert_eq!(r.status, 403, "the web refuses it: {}", r.text());
    assert!(r.text().contains("blocked"), "and says why:\n{}", r.text());
    let id = h.store.account_id(USER).unwrap().unwrap();
    assert!(
        matches!(deliver(&h, USER, 1), DeliveryOutcome::Delivered { account, .. } if account == id),
        "its mail still arrives"
    );
}

#[tokio::test]
async fn disabled_page_says_mail_arrives() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let enabled = b.account_page(USER).await;
    assert!(
        !enabled.to_lowercase().contains("still arrives"),
        "only a blocked account's page says it:\n{enabled}"
    );
    assert!(
        post_forms(&enabled, "/account/enable").is_empty(),
        "nothing to allow yet"
    );

    h.store.set_disabled(USER, true).unwrap();
    let blocked = b.account_page(USER).await;
    assert!(
        visible_text(&blocked)
            .to_lowercase()
            .contains("still arrives"),
        "a blocked account's page says its mail still arrives:\n{blocked}"
    );
    assert!(
        post_forms(&blocked, "/account/disable").is_empty(),
        "nothing to block again"
    );
    let form = post_form(&blocked, "/account/enable");
    assert!(
        visible_text(&form.html).contains("Allow sign-in"),
        "the button says Allow sign-in: {}",
        form.html
    );
}

#[tokio::test]
async fn reenable_restores() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let pw = password(USER);
    let mut b = h.signed_in(ADMIN).await;
    assert_done(&b.press(USER, "/account/disable").await, "block sign-in");
    assert!(!b.imap_login(USER, &pw).await);

    let r = b.press(USER, "/account/enable").await;
    assert_done(&r, "allow sign-in");
    assert!(!h.account(USER).disabled);
    assert!(b.imap_login(USER, &pw).await, "IMAP takes it again");
    assert_eq!(
        h.browser().sign_in(USER, &pw).await.status,
        303,
        "the web takes it again"
    );
}

#[tokio::test]
async fn grant_and_remove_admin() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;

    let form = b.account_form(USER, "/account/admin").await;
    assert!(
        visible_text(&form.html).contains("Make admin"),
        "the button says Make admin: {}",
        form.html
    );
    assert_done(&b.submit(&form, &[]).await, "make admin");
    assert!(h.account(USER).admin);

    let mut user = h.signed_in(USER).await;
    let r = user.get("/").await;
    assert_eq!(
        location_path(&r),
        "/accounts",
        "a new admin starts at the list"
    );
    assert_eq!(user.get("/accounts").await.status, 200, "and may see it");

    let form = b.account_form(USER, "/account/admin").await;
    assert!(
        visible_text(&form.html).contains("Remove admin"),
        "the button says Remove admin: {}",
        form.html
    );
    assert_done(&b.submit(&form, &[]).await, "remove admin");
    assert!(!h.account(USER).admin);
    let r = user.get("/accounts").await;
    assert!(
        r.status == 403 || (r.status == 303 && location_path(&r) == "/login"),
        "a removed admin loses the list at once: {} {:?}",
        r.status,
        r.header("location")
    );
}

#[tokio::test]
async fn last_admin_cannot_disable_or_demote_self() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let block = b.account_form(USER, "/account/disable").await;
    h.store.set_admin(USER, true).unwrap();
    let demote = b.account_form(USER, "/account/admin").await;
    h.store.set_admin(USER, false).unwrap();

    let own = b.account_page(ADMIN).await;
    assert!(
        post_forms(&own, "/account/disable").is_empty()
            && post_forms(&own, "/account/admin").is_empty(),
        "no block or remove-admin control on the own page:\n{own}"
    );
    assert!(
        !own.contains("Block sign-in") && !own.contains("Remove admin"),
        "{own}"
    );

    let me = h.id(ADMIN).to_string();
    let before = h.snapshot();
    for (what, form) in [("block", &block), ("remove admin", &demote)] {
        let r = b.submit(&form.with("id", &me), &[]).await;
        assert_eq!(
            r.status,
            409,
            "the last admin's own {what} is refused: {}",
            r.text()
        );
        assert!(
            r.text().contains(LAST_ADMIN),
            "{what}: says {LAST_ADMIN:?}:\n{}",
            r.text()
        );
        assert_eq!(h.snapshot(), before, "{what}: nothing changed");
    }
    assert_eq!(
        b.get("/accounts").await.status,
        200,
        "still signed in as admin"
    );
}

#[tokio::test]
async fn forged_self_block_refused() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.admin("carol@example.com");
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let block = b.account_form(USER, "/account/disable").await;
    let demote = b.account_form("carol@example.com", "/account/admin").await;
    assert!(visible_text(&demote.html).contains("Remove admin"));

    let own = b.account_page(ADMIN).await;
    assert!(
        post_forms(&own, "/account/disable").is_empty()
            && post_forms(&own, "/account/admin").is_empty(),
        "with another admin, still no self-block or self-demote:\n{own}"
    );

    let me = h.id(ADMIN).to_string();
    let before = h.snapshot();
    for (what, form) in [("block", &block), ("remove admin", &demote)] {
        let r = b.submit(&form.with("id", &me), &[]).await;
        assert_eq!(
            r.status,
            409,
            "a forged own {what} is refused: {}",
            r.text()
        );
        assert_eq!(h.snapshot(), before, "{what}: nothing changed");
    }
    assert_done(
        &b.submit(&demote, &[]).await,
        "removing another admin's admin works",
    );
    assert!(!h.account("carol@example.com").admin);
}

// // CSRF: each form refuses a missing or wrong token with 403 and changes nothing; the form as
// rendered then works.

async fn csrf_refused(h: &WebHarness, b: &mut Browser<'_>, form: &PostForm, fill: &[(&str, &str)]) {
    let token = form
        .sent("csrf")
        .unwrap_or_else(|| panic!("the {} form carries a csrf field: {form:?}", form.action))
        .to_string();
    let others = h.signed_in(ADMIN).await.get("/accounts").await;
    let others = csrf_token(&others.text()).expect("another session's token");
    let off = one_off(&token);
    let before = h.snapshot();
    for (what, f) in [
        ("no token", form.without("csrf")),
        ("empty token", form.with("csrf", "")),
        ("token one digit off", form.with("csrf", &off)),
        ("another session's token", form.with("csrf", &others)),
    ] {
        let r = b.submit(&f, fill).await;
        assert_eq!(r.status, 403, "{} with {what}: {}", form.action, r.text());
        assert_eq!(
            h.snapshot(),
            before,
            "{} with {what}: nothing changed",
            form.action
        );
    }
    let r = b.submit(form, fill).await;
    assert_done(&r, &format!("{} with its token", form.action));
    assert_ne!(
        h.snapshot(),
        before,
        "{} with its token changes something",
        form.action
    );
}

async fn admin_and_user(h: &WebHarness) -> Browser<'_> {
    h.admin(ADMIN);
    h.user(USER);
    h.signed_in(ADMIN).await
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_create() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = post_form(&b.get("/accounts").await.text(), "/accounts");
    let (login, pw) = (form.text_field(), form.password_fields());
    csrf_refused(
        &h,
        &mut b,
        &form,
        &[(&login, "new@example.com"), (&pw[0], PW), (&pw[1], PW)],
    )
    .await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_password() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = b.account_form(USER, "/account/password").await;
    let pw = form.password_fields();
    csrf_refused(&h, &mut b, &form, &[(&pw[0], NEW), (&pw[1], NEW)]).await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_disable() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = b.account_form(USER, "/account/disable").await;
    csrf_refused(&h, &mut b, &form, &[]).await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_enable() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    h.store.set_disabled(USER, true).unwrap();
    let form = b.account_form(USER, "/account/enable").await;
    csrf_refused(&h, &mut b, &form, &[]).await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_admin() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = b.account_form(USER, "/account/admin").await;
    csrf_refused(&h, &mut b, &form, &[]).await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_address_add() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = b.account_form(USER, "/account/address/add").await;
    let field = form.text_field();
    csrf_refused(&h, &mut b, &form, &[(&field, "info@example.com")]).await;
}

#[tokio::test]
async fn csrf_missing_or_wrong_403_nothing_changes_address_remove() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let form = b.remove_form(USER, USER).await;
    csrf_refused(&h, &mut b, &form, &[]).await;
}

#[tokio::test]
async fn blocked_page_says_connected_mail_apps_stay() {
    let h = WebHarness::start().await;
    let mut b = admin_and_user(&h).await;
    let r = b.press(USER, "/account/disable").await;
    assert_done(&r, "block sign-in");
    let done = b.follow(r).await.text();
    let later = b.account_page(USER).await;
    for (what, html) in [
        ("after blocking", done),
        ("the blocked account's page", later),
    ] {
        let text = visible_text(&html).to_lowercase();
        assert!(
            text.contains("mail app") && text.contains("connected"),
            "{what}: says mail apps already connected stay connected: {text}"
        );
    }
}

#[tokio::test]
async fn admin_can_create_another_admin_in_the_account_form() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    let mut b = h.signed_in(ADMIN).await;
    assert_eq!(b.get("/accounts").await.status, 200);
    let result = b
        .post(
            "/accounts",
            &[
                ("login", USER),
                ("password", PW),
                ("again", PW),
                ("new_admin", "yes"),
            ],
        )
        .await;
    assert_done(&result, "create admin");
    assert!(h.account(USER).admin);
}
