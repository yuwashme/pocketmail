//! The own page: any user signs in with the IMAP login, sees only their own login and addresses,
//! and changes their own password (current password, new one twice, 12 characters to 1,024
//! bytes). Typed text is shown as text; passwords and hashes are never shown.

mod browser;
mod harness;
mod net;

use browser::*;
use harness::password;

const USER: &str = "user@example.com";
const NEW: &str = "a-new-password-for-user";

async fn signed_in<'h>(h: &'h WebHarness, login: &str) -> Browser<'h> {
    let mut b = h.browser();
    let r = b.sign_in(login, &password(login)).await;
    assert_eq!(r.status, 303, "sign-in as {login}: {}", r.text());
    b
}

/// Every password input of the form is empty.
#[track_caller]
fn assert_password_inputs_empty(html: &str, action: &str) {
    for i in form_inputs(html, action).iter().filter(|i| i.attr("type") == Some("password")) {
        assert!(i.attr("value").is_none_or(str::is_empty), "{action}: a password input is never filled in: {i:?}");
    }
}

#[tokio::test]
async fn non_admin_sees_only_own_page() {
    let h = WebHarness::start().await;
    h.user("alice@example.com");
    h.store.add_address("info@example.com", "alice@example.com").unwrap();
    h.user("bob@example.com");
    h.store.add_address("@example.org", "bob@example.com").unwrap();

    let mut a = signed_in(&h, "alice@example.com").await;
    let r = a.get("/").await;
    assert_eq!(r.status, 303, "/ for a user: {}", r.text());
    assert_eq!(location_path(&r), "/me");

    let r = a.get("/me").await;
    assert_eq!(r.status, 200);
    let text = r.text();
    for shown in ["alice@example.com", "info@example.com"] {
        assert!(text.contains(shown), "{shown} on the own page:\n{text}");
    }
    for hidden in ["bob@example.com", "example.org"] {
        assert!(!text.contains(hidden), "{hidden} is another user's:\n{text}");
    }
    let actions: Vec<String> = forms(&text).into_iter().filter_map(|(f, _)| f.attr("action").map(str::to_string)).collect();
    assert!(
        actions.iter().all(|a| a == "/me/password" || a == "/logout"),
        "addresses are read-only: the only forms change the password and sign out, got {actions:?}"
    );
    assert!(text.contains("Sign out"), "a Sign out button:\n{text}");
}

#[tokio::test]
async fn anonymous_sent_to_login() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut anon = h.browser();
    for path in ["/", "/me", "/me?done=password"] {
        assert_to_login(&anon.get(path).await, &format!("GET {path} without a session"));
    }
    assert_to_login(&anon.post_exact("/me/password", &[("x", "y")]).await, "POST /me/password without a session");

    let r = anon.get("/login").await;
    assert_eq!(r.status, 200);
    let text = r.text();
    login_fields(&text);
    for wording in ["User name", "Password", "Sign in"] {
        assert!(text.contains(wording), "{wording:?} on the sign-in page:\n{text}");
    }
    assert!(!text.contains("Sign out"), "nothing to sign out of:\n{text}");
}

#[tokio::test]
async fn own_change_needs_current_and_match() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;
    for (what, current, new, again) in [
        ("the new passwords differ", pw.as_str(), NEW, "a-new-password-for-usex"),
        ("no current password", "", NEW, NEW),
        ("a wrong current password", "not-my-password", NEW, NEW),
        ("no new password", pw.as_str(), "", ""),
    ] {
        let r = b.change_password(current, new, again).await;
        assert_eq!(r.status, 422, "{what}: {}", r.text());
        password_fields(&r.text());
    }
    assert!(b.imap_login(USER, &pw).await, "nothing changed");
    assert!(!b.imap_login(USER, NEW).await, "nothing changed");

    let r = b.change_password(&pw, NEW, NEW).await;
    assert_eq!(r.status, 303, "{}", r.text());
    assert_eq!(location(&r), "/me?done=password");
}

#[tokio::test]
async fn wrong_current_counts_as_failure() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = signed_in(&h, USER).await;
    for i in 1..=5 {
        let r = b.change_password("not-my-password", NEW, NEW).await;
        assert_eq!(r.status, 422, "wrong current password {i}");
        assert!(b.delayed, "wrong current password {i}: answered after 2 s, like a failed sign-in");
    }
    let r = b.change_password(&pw, NEW, NEW).await;
    assert_eq!(r.status, 429, "locked: the right current password is not checked either: {}", r.text());
    assert!(!b.delayed);
    let r = h.browser().sign_in(USER, &pw).await;
    assert_eq!(r.status, 429, "sign-in from the same IP is locked too");
    assert!(b.imap_login(USER, &pw).await, "nothing changed");
}

#[tokio::test]
async fn success_ends_others_keeps_this_imap_uses_new() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut this = signed_in(&h, USER).await;
    let mut other = signed_in(&h, USER).await;
    assert_eq!(other.get("/me").await.status, 200);

    let plain = this.get("/me").await.text();
    let r = this.change_password(&pw, NEW, NEW).await;
    assert_eq!(r.status, 303, "{}", r.text());
    assert_eq!(location(&r), "/me?done=password");
    let done = this.follow(r).await;
    assert_eq!(done.status, 200, "this session stays");
    assert!(done.text().contains(USER));
    assert_ne!(done.text(), plain, "the page confirms the change");

    assert_to_login(&other.get("/me").await, "the other session ended");
    assert_eq!(this.get("/me").await.status, 200, "this session still works");

    assert!(!this.imap_login(USER, &pw).await, "IMAP refuses the old password");
    assert!(this.imap_login(USER, NEW).await, "IMAP takes the new password");
    let mut again = h.browser();
    assert_eq!(again.sign_in(USER, &pw).await.status, 422, "the web refuses the old password");
    assert_eq!(again.sign_in(USER, NEW).await.status, 303, "the web takes the new password");
}

#[tokio::test]
async fn web_password_min_12_chars_max_1024_bytes() {
    let h = WebHarness::start().await;
    h.user(USER);
    let mut b = signed_in(&h, USER).await;
    let mut current = password(USER);
    for (what, p) in [
        ("11 characters", "a".repeat(11)),
        ("11 two-byte characters (22 bytes)", "ž".repeat(11)),
        ("1,025 bytes", "a".repeat(1025)),
        ("1,026 bytes in 513 characters", "ž".repeat(513)),
    ] {
        let r = b.change_password(&current, &p, &p).await;
        assert_eq!(r.status, 422, "{what} is refused");
        assert!(!b.delayed, "{what}: a rule, not a failed password check");
    }
    for (what, p) in [
        ("12 characters", "a".repeat(12)),
        ("12 two-byte characters", "ž".repeat(12)),
        ("1,024 bytes", "b".repeat(1024)),
        ("1,024 bytes in 512 characters", "ž".repeat(512)),
    ] {
        let r = b.change_password(&current, &p, &p).await;
        assert_eq!(r.status, 303, "{what} is taken: {}", r.text());
        current = p;
    }
    let mut again = h.browser();
    assert_eq!(again.sign_in(USER, &current).await.status, 303, "the last one signs in");
}

#[tokio::test]
async fn no_page_shows_password_or_argon2() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let secrets = [pw.as_str(), NEW, "wrong-secret-password", "other-secret-password"];
    let mut b = h.browser();
    let mut pages = vec![("sign-in page", b.get("/login").await)];
    pages.push(("failed sign-in", b.sign_in(USER, "wrong-secret-password").await));
    pages.push(("sign-in", b.sign_in(USER, &pw).await));
    pages.push(("own page", b.get("/me").await));
    pages.push(("mismatch", b.change_password(&pw, NEW, "other-secret-password").await));
    pages.push(("wrong current", b.change_password("wrong-secret-password", NEW, NEW).await));
    let r = b.change_password(&pw, NEW, NEW).await;
    pages.push(("changed", r.clone()));
    pages.push(("confirmation", b.follow(r).await));
    for (what, r) in &pages {
        let all = format!("{:?}\n{}", r.headers, r.text());
        for s in secrets {
            assert!(!all.contains(s), "{what} shows a password ({s:?}):\n{all}");
        }
        assert!(!all.contains("$argon2"), "{what} shows a hash:\n{all}");
    }
}

#[tokio::test]
async fn script_login_shown_as_text() {
    let h = WebHarness::start().await;
    let evil = r#"<script>alert("x&'y")</script>@example.com"#;
    h.user(evil);
    let mut b = h.browser();

    let failed = b.sign_in(evil, "wrong-password").await;
    assert_eq!(failed.status, 422);
    let (u, _) = login_fields(&failed.text());
    let typed = form_inputs(&failed.text(), "/login").into_iter().find(|i| i.attr("name") == Some(&u)).unwrap();
    assert_eq!(typed.attr("value"), Some(evil), "the typed login comes back intact in a double-quoted attribute");

    assert_eq!(b.sign_in(evil, &password(evil)).await.status, 303);
    let me = b.get("/me").await;
    assert_eq!(me.status, 200);
    assert!(me.text().contains("&lt;script&gt;alert("), "the login is shown as text:\n{}", me.text());
    let mismatch = b.change_password(&password(evil), NEW, "something-else-entirely").await;
    assert_eq!(mismatch.status, 422);

    for (what, r) in [("failed sign-in", &failed), ("own page", &me), ("password form error", &mismatch)] {
        let text = r.text();
        assert!(!text.contains("<script"), "{what}: no script element:\n{text}");
        assert!(!text.contains(evil), "{what}: the login only appears escaped:\n{text}");
    }
}

#[tokio::test]
async fn field_errors_keep_login_never_password() {
    let h = WebHarness::start().await;
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();

    let r = b.sign_in(USER, "wrong-secret-password").await;
    assert_eq!(r.status, 422);
    let text = r.text();
    let (u, p) = login_fields(&text);
    let inputs = form_inputs(&text, "/login");
    let value = |name: &str| inputs.iter().find(|i| i.attr("name") == Some(name)).and_then(|i| i.attr("value")).map(str::to_string);
    assert_eq!(value(&u).as_deref(), Some(USER), "the login is kept");
    assert!(value(&p).is_none_or(|v| v.is_empty()), "the password is not");
    assert!(!text.contains("wrong-secret-password"));

    assert_eq!(b.sign_in(USER, &pw).await.status, 303);
    for (what, current, new, again) in
        [("mismatch", pw.as_str(), NEW, "other-secret-password"), ("too short", pw.as_str(), "short", "short"), ("wrong current", "wrong-secret-password", NEW, NEW)]
    {
        let r = b.change_password(current, new, again).await;
        assert_eq!(r.status, 422, "{what}");
        assert_password_inputs_empty(&r.text(), "/me/password");
        for s in [pw.as_str(), NEW, "other-secret-password", "wrong-secret-password"] {
            assert!(!r.text().contains(s), "{what}: no password on the page");
        }
    }
}

/// Every admin form, as an admin's page renders it for `target` (who has the address `target`),
/// with what a person would type into it.
async fn admin_forms(admin: &mut Browser<'_>, target: &str) -> Vec<(PostForm, Vec<(String, String)>)> {
    let create = post_form(&admin.get("/accounts").await.text(), "/accounts");
    let (login, pw) = (create.text_field(), create.password_fields());
    let page = admin.account_page(target).await;
    let password = post_form(&page, "/account/password");
    let set = password.password_fields();
    let add = post_form(&page, "/account/address/add");
    let address = add.text_field();
    let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
    let mut out = vec![
        (create, vec![pair(&login, "new@example.com"), pair(&pw[0], NEW), pair(&pw[1], NEW)]),
        (password, vec![pair(&set[0], NEW), pair(&set[1], NEW)]),
        (add, vec![pair(&address, "info@example.com")]),
        (admin.remove_form(target, target).await, vec![]),
        (post_form(&page, "/account/disable"), vec![]),
        (post_form(&page, "/account/admin"), vec![]),
    ];
    admin.h.store.set_disabled(target, true).unwrap();
    out.push((admin.account_form(target, "/account/enable").await, vec![]));
    admin.h.store.set_disabled(target, false).unwrap();
    out
}

fn fill(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[tokio::test]
async fn non_admin_403_on_every_admin_page_and_form() {
    let h = WebHarness::start().await;
    h.admin("admin@example.com");
    h.user(USER);
    h.user("bob@example.com");
    let mut admin = h.signed_in("admin@example.com").await;
    let mut forms = admin_forms(&mut admin, "bob@example.com").await;
    let own_admin = admin.account_form(USER, "/account/admin").await;
    forms.push((own_admin, vec![]));

    let mut b = h.signed_in(USER).await;
    let token = csrf_token(&b.get("/me").await.text()).expect("the own page's token");
    for path in ["/accounts".to_string(), account_href(h.id("bob@example.com")), account_href(h.id(USER)), account_href(h.id("admin@example.com"))] {
        let r = b.get(&path).await;
        assert_eq!(r.status, 403, "GET {path} as a user: {}", r.text());
        assert!(!r.text().contains("bob@example.com"), "GET {path}: nothing of other accounts shown");
    }
    let before = h.snapshot();
    for (form, typed) in &forms {
        let r = b.submit(&form.with("csrf", &token), &fill(typed)).await;
        assert_eq!(r.status, 403, "POST {} as a user, with the user's own token: {}", form.action, r.text());
        assert_eq!(h.snapshot(), before, "POST {}: nothing changed", form.action);
    }
    assert_eq!(location_path(&b.get("/").await), "/me", "a user still starts at the own page");
    assert_eq!(b.get("/me").await.status, 200, "and stays signed in");
}

#[tokio::test]
async fn anonymous_sent_to_login_from_admin_pages() {
    let h = WebHarness::start().await;
    h.admin("admin@example.com");
    h.user(USER);
    let mut admin = h.signed_in("admin@example.com").await;
    let forms = admin_forms(&mut admin, USER).await;

    let mut anon = h.browser();
    for path in ["/accounts".to_string(), account_href(h.id(USER)), account_href(9999)] {
        assert_to_login(&anon.get(&path).await, &format!("GET {path} without a session"));
    }
    let before = h.snapshot();
    for (form, typed) in &forms {
        assert_to_login(&anon.submit(form, &fill(typed)).await, &format!("POST {} without a session", form.action));
        assert_eq!(h.snapshot(), before, "POST {}: nothing changed", form.action);
    }
}
