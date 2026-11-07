//! Addresses on the admin pages: added with the CLI's checks (lower-cased, no `+`, exactly one
//! `@`, no spaces), the catch-all `@domain` in plain words, an address in use names its owner,
//! and a removed address routes to the catch-all, else to quarantine.

mod browser;
mod harness;
mod net;

use browser::*;
use harness::password;
use synology_mail_server::store::normalize_address;

const ADMIN: &str = "admin@example.com";
const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";

async fn admin_with_users(h: &WebHarness) -> Browser<'_> {
    h.admin(ADMIN);
    h.user(ALICE);
    h.user(BOB);
    h.signed_in(ADMIN).await
}

fn routes_to(h: &WebHarness, to: &str) -> Option<i64> {
    h.store.route(to).unwrap().map(|id| id.0)
}

#[tokio::test]
async fn adds_lowercased() {
    let h = WebHarness::start().await;
    let mut b = admin_with_users(&h).await;
    let r = b.add_address(ALICE, "Info@Example.COM").await;
    assert_done(&r, "add an address");
    assert!(
        !location(&r).to_lowercase().contains("info@"),
        "nothing typed in the redirect: {}",
        location(&r)
    );
    assert!(
        h.store
            .addresses()
            .unwrap()
            .contains(&("info@example.com".to_string(), ALICE.to_string())),
        "{:?}",
        h.store.addresses()
    );
    assert_eq!(routes_to(&h, "info@example.com"), Some(h.id(ALICE)));
    let page = b.account_page(ALICE).await;
    assert!(
        page.contains("info@example.com") && !page.contains("Info@Example.COM"),
        "shown lower-cased:\n{page}"
    );

    assert_done(&b.add_address(BOB, "@Example.ORG").await, "add a catch-all");
    assert_eq!(routes_to(&h, "anyone@example.org"), Some(h.id(BOB)));
}

#[tokio::test]
async fn rejects_plus_no_at_two_ats_spaces_on_form() {
    let h = WebHarness::start().await;
    let mut b = admin_with_users(&h).await;
    let field = b
        .account_form(ALICE, "/account/address/add")
        .await
        .text_field();
    let before = h.snapshot();
    for (what, address) in [
        ("a + in the local part", "alice+news@example.com"),
        ("no @", "example.com"),
        ("two @", "alice@home@example.com"),
        ("a space", "alice smith@example.com"),
        ("no domain", "alice@"),
        ("empty", ""),
    ] {
        assert!(
            normalize_address(address).is_err(),
            "{what}: the CLI refuses it too"
        );
        let r = b.add_address(ALICE, address).await;
        assert_eq!(r.status, 422, "{what}: {}", r.text());
        assert_field_error(&r.text(), "/account/address/add", &field, what);
        assert_eq!(h.snapshot(), before, "{what}: nothing changed");
    }
}

#[tokio::test]
async fn in_use_names_owner_no_change() {
    let h = WebHarness::start().await;
    let mut b = admin_with_users(&h).await;
    h.store.add_address("info@example.com", ALICE).unwrap();
    let before = h.snapshot();
    for (what, to, address) in [
        ("another account's", BOB, "info@example.com"),
        ("in another case", BOB, "INFO@example.com"),
        ("its own", ALICE, "info@example.com"),
    ] {
        let r = b.add_address(to, address).await;
        assert_eq!(r.status, 409, "{what}: {}", r.text());
        assert!(
            visible_text(&r.text()).contains(ALICE),
            "{what}: names the account that has it:\n{}",
            r.text()
        );
        assert_eq!(h.snapshot(), before, "{what}: nothing changed");
    }
    assert_eq!(routes_to(&h, "info@example.com"), Some(h.id(ALICE)));
}

#[tokio::test]
async fn removed_routes_to_catch_all_else_quarantine() {
    let h = WebHarness::start().await;
    let mut b = admin_with_users(&h).await;
    h.store.add_address("info@example.com", ALICE).unwrap();
    h.store.add_address("@example.com", BOB).unwrap();
    assert_eq!(routes_to(&h, "info@example.com"), Some(h.id(ALICE)));

    let r = b.remove_address(ALICE, "info@example.com").await;
    assert_done(&r, "remove an address");
    assert!(
        !h.store
            .addresses()
            .unwrap()
            .iter()
            .any(|(a, _)| a == "info@example.com")
    );
    assert_eq!(
        routes_to(&h, "info@example.com"),
        Some(h.id(BOB)),
        "mail to it goes to the catch-all"
    );
    assert!(
        !b.account_page(ALICE).await.contains("info@example.com"),
        "gone from the page"
    );

    assert_done(
        &b.remove_address(BOB, "@example.com").await,
        "remove the catch-all",
    );
    assert_eq!(
        routes_to(&h, "info@example.com"),
        None,
        "with no catch-all, mail to it is quarantined"
    );
    assert_eq!(
        routes_to(&h, ALICE),
        Some(h.id(ALICE)),
        "other addresses still route"
    );
}

#[tokio::test]
async fn catch_all_labelled() {
    let h = WebHarness::start().await;
    let mut b = admin_with_users(&h).await;
    h.store.add_address("@example.org", BOB).unwrap();
    let list = visible_text(&b.get("/accounts").await.text());
    let page = visible_text(&b.account_page(BOB).await);
    for (what, text) in [("list", list), ("account page", page)] {
        assert!(
            text.contains("@example.org") && text.contains("all other mail for example.org"),
            "{what}: the catch-all in plain words:\n{text}"
        );
        assert!(
            !text.contains("all other mail for example.com"),
            "{what}: only catch-alls are labelled so:\n{text}"
        );
    }
}

#[tokio::test]
async fn script_login_shown_as_text() {
    let h = WebHarness::start().await;
    let evil = r#"<script>alert("x&'y")</script>@example.com"#;
    let mut b = admin_with_users(&h).await;
    h.user(evil);

    let list = b.get("/accounts").await;
    let page = b.get(&account_href(h.id(evil))).await;
    assert_eq!((list.status, page.status), (200, 200));
    let failed = b
        .create_account(
            &evil.replace("@", "2@"),
            "a-long-enough-password",
            "a-different-password",
        )
        .await;
    assert_eq!(failed.status, 422);
    let field = post_form(&failed.text(), "/accounts").text_field();
    assert_eq!(
        field_value(&failed.text(), "/accounts", &field).as_deref(),
        Some(evil.replace("@", "2@").as_str()),
        "the typed login comes back intact"
    );
    let in_use = b.add_address(ALICE, evil).await;
    assert_eq!(in_use.status, 409, "{}", in_use.text());

    for (what, r) in [
        ("list", &list),
        ("account page", &page),
        ("form error", &failed),
        ("address in use", &in_use),
    ] {
        let text = r.text();
        assert!(
            !text.contains("<script"),
            "{what}: no script element:\n{text}"
        );
        assert!(
            !text.contains(evil),
            "{what}: the login only appears escaped:\n{text}"
        );
    }
    assert!(
        list.text().contains("&lt;script&gt;alert("),
        "the list shows it as text:\n{}",
        list.text()
    );
    assert!(
        page.text().contains("&lt;script&gt;alert("),
        "the account page shows it as text:\n{}",
        page.text()
    );
    assert!(
        b.imap_login(evil, &password(evil)).await,
        "the account itself works"
    );
}
