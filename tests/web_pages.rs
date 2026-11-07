//! Every settings page: small (HTML + CSS under 20 KB), no script or inline style, every input
//! labelled, errors tied to their field, and a viewport that can be zoomed.

mod browser;
mod harness;
mod net;

use std::collections::HashSet;

use browser::*;
use harness::password;

const USER: &str = "user@example.com";
const NEW: &str = "a-new-password-for-user";
const PAGE_BUDGET: usize = 20_000;

/// Every kind of page this build serves, with a name for the messages.
async fn all_pages(h: &WebHarness) -> Vec<(&'static str, Resp)> {
    h.user(USER);
    let pw = password(USER);
    let mut b = h.browser();
    let mut pages = vec![("sign-in", b.get("/login").await)];
    pages.push(("failed sign-in", b.sign_in(USER, "wrong-password").await));
    assert_eq!(b.sign_in(USER, &pw).await.status, 303);
    pages.push(("own page", b.get("/me").await));
    pages.push(("new passwords differ", b.change_password(&pw, NEW, "a-new-password-for-usex").await));
    pages.push(("new password too short", b.change_password(&pw, "short", "short").await));
    pages.push(("wrong current password", b.change_password("wrong-password", NEW, NEW).await));
    let r = b.change_password(&pw, NEW, NEW).await;
    assert_eq!(r.status, 303);
    pages.push(("password changed", b.follow(r).await));
    b.origin = Some("https://evil.example.com".into());
    pages.push(("foreign origin", b.post("/logout", &[]).await));
    pages.push(("not found", b.get("/no-such-page").await));

    let mut locked = h.browser();
    for i in 1..=5 {
        locked.sign_in(&format!("nobody{i}@example.com"), "wrong-password").await;
    }
    pages.push(("locked", locked.sign_in(USER, NEW).await));

    let expect = [200, 422, 200, 422, 422, 422, 200, 403, 404, 429];
    for ((what, r), status) in pages.iter().zip(expect) {
        assert_eq!(r.status, status, "{what}: {}", r.text());
    }
    pages
}

/// The admin pages: a list of 20 accounts, account pages, and their errors.
async fn admin_pages(h: &WebHarness) -> Vec<(&'static str, Resp)> {
    const ADMIN: &str = "admin@example.com";
    const PW: &str = "a-password-for-an-account";
    h.admin(ADMIN);
    for i in 1..=20 {
        let login = format!("user{i:02}-with-a-longer-name@example.com");
        h.user(&login);
        h.store.add_address(&format!("info{i:02}-for-the-family@example.com"), &login).unwrap();
    }
    h.store.add_address("@example.org", "user01-with-a-longer-name@example.com").unwrap();
    h.store.set_disabled("user02-with-a-longer-name@example.com", true).unwrap();
    let mut b = h.signed_in(ADMIN).await;
    let mut pages = vec![("account list", b.get("/accounts").await)];
    pages.push(("new account, passwords differ", b.create_account("new@example.com", PW, "a-password-for-an-accounT").await));
    pages.push(("new account, bad login", b.create_account("a new@example.com", PW, PW).await));
    pages.push(("new account exists", b.create_account(ADMIN, PW, PW).await));
    let user = "user01-with-a-longer-name@example.com";
    pages.push(("account page", b.get(&account_href(h.id(user))).await));
    pages.push(("blocked account page", b.get(&account_href(h.id("user02-with-a-longer-name@example.com"))).await));
    pages.push(("own account page", b.get(&account_href(h.id(ADMIN))).await));
    pages.push(("set password, too short", b.set_password(user, "short", "short").await));
    pages.push(("address refused", b.add_address(user, "a+b@example.com").await));
    pages.push(("address in use", b.add_address(user, ADMIN).await));
    let r = b.add_address(user, "new@example.com").await;
    assert_eq!(r.status, 303);
    pages.push(("address added", b.follow(r).await));
    let block = b.account_form(user, "/account/disable").await;
    pages.push(("own block refused", b.submit(&block.with("id", &h.id(ADMIN).to_string()), &[]).await));

    let expect = [200, 422, 422, 409, 200, 200, 200, 422, 422, 409, 200, 409];
    assert_eq!(pages.len(), expect.len());
    for ((what, r), status) in pages.iter().zip(expect) {
        assert_eq!(r.status, status, "{what}: {}", r.text());
    }
    pages
}

async fn every_page(h: &WebHarness) -> Vec<(&'static str, Resp)> {
    let mut pages = admin_pages(h).await;
    pages.extend(all_pages(h).await);
    pages
}

/// The page's inputs that a person fills in or ticks.
fn fields(html: &str) -> Vec<Tag> {
    tags(html, "input").into_iter().filter(|i| !matches!(i.attr("type"), Some("hidden" | "submit" | "button"))).collect()
}

#[tokio::test]
async fn every_page_plus_css_under_20_kb() {
    let h = WebHarness::start().await;
    let css = css_source().len();
    for (what, r) in every_page(&h).await {
        assert!(r.body.len() + css < PAGE_BUDGET, "{what}: {} bytes of HTML + {css} of CSS", r.body.len());
    }
}

#[tokio::test]
async fn no_script_anywhere() {
    let h = WebHarness::start().await;
    for (what, r) in every_page(&h).await {
        let text = r.text();
        let lower = text.to_ascii_lowercase();
        for bad in ["<script", "javascript:", "<style", "<iframe", "<object", "<embed"] {
            assert!(!lower.contains(bad), "{what}: {bad}\n{text}");
        }
        for t in all_tags(&text) {
            for (name, _) in &t.attrs {
                assert!(!name.starts_with("on") && name != "style", "{what}: <{} {name}=…>", t.name);
            }
            if t.name == "link" {
                assert_eq!(t.attr("rel"), Some("stylesheet"), "{what}: {t:?}");
                assert_eq!(t.attr("href"), Some(css_path().as_str()), "{what}: only the stylesheet is linked");
            }
        }
        assert_eq!(r.header("content-security-policy"), Some(CSP), "{what}");
    }
}

#[tokio::test]
async fn every_input_labelled() {
    let h = WebHarness::start().await;
    for (what, r) in every_page(&h).await {
        let text = r.text();
        let ids: Vec<String> = all_tags(&text).iter().filter_map(|t| t.attr("id").map(str::to_string)).collect();
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len(), "{what}: ids are unique: {ids:?}");
        let labels: Vec<Tag> = tags(&text, "label");
        for input in fields(&text) {
            let id = input.attr("id").unwrap_or_else(|| panic!("{what}: input without an id: {input:?}"));
            let label = labels.iter().find(|l| l.attr("for") == Some(id)).unwrap_or_else(|| panic!("{what}: no <label for={id:?}>"));
            let label_text = text[label.end..].split("</label>").next().unwrap_or("").trim();
            assert!(!label_text.is_empty(), "{what}: label for {id:?} has text");
            assert!(input.has("name"), "{what}: {input:?}");
        }
        for (form, _) in forms(&text) {
            assert!(form.attr("method").is_some_and(|m| m.eq_ignore_ascii_case("post")), "{what}: {form:?}");
            assert!(form.attr("action").is_some_and(|a| a.starts_with('/') && !a.starts_with("//")), "{what}: {form:?}");
        }
        for button in tags(&text, "button") {
            let label = text[button.end..].split("</button>").next().unwrap_or("").trim();
            assert!(!label.is_empty(), "{what}: a button with text: {button:?}");
        }
    }
}

#[tokio::test]
async fn errors_described_by_field() {
    let h = WebHarness::start().await;
    let pages = all_pages(&h).await;
    for (what, r) in &pages {
        let text = r.text();
        for input in fields(&text) {
            match input.attr("aria-invalid") {
                None | Some("false") => continue,
                Some(v) => assert_eq!(v, "true", "{what}: {input:?}"),
            }
            let by = input.attr("aria-describedby").unwrap_or_else(|| panic!("{what}: invalid input without aria-describedby: {input:?}"));
            for id in by.split_whitespace() {
                let msg = text_of_id(&text, id).unwrap_or_else(|| panic!("{what}: aria-describedby={id:?} names no element"));
                assert!(!msg.is_empty(), "{what}: the error {id:?} has text");
            }
        }
    }

    let invalid = |page: &str| -> Vec<String> {
        let r = &pages.iter().find(|(w, _)| *w == page).unwrap().1;
        fields(&r.text())
            .into_iter()
            .filter(|i| i.attr("aria-invalid") == Some("true"))
            .filter_map(|i| i.attr("autocomplete").map(str::to_string))
            .collect()
    };
    assert_eq!(invalid("wrong current password"), ["current-password"], "the current password field is in error");
    assert_eq!(invalid("new password too short"), ["new-password"], "the (first) new password field is in error");
    assert_eq!(invalid("new passwords differ"), ["new-password"], "one new password field is in error");
    assert!(invalid("own page").is_empty() && invalid("sign-in").is_empty(), "no errors before a submit");
}

#[tokio::test]
async fn viewport_meta() {
    let h = WebHarness::start().await;
    for (what, r) in all_pages(&h).await {
        let text = r.text();
        let html = tags(&text, "html");
        assert!(html.len() == 1 && html[0].attr("lang") == Some("en"), "{what}: <html lang=\"en\">");
        let metas = tags(&text, "meta");
        assert!(metas.iter().any(|m| m.attr("charset").is_some_and(|c| c.eq_ignore_ascii_case("utf-8"))), "{what}: charset");
        let viewport: Vec<&Tag> = metas.iter().filter(|m| m.attr("name") == Some("viewport")).collect();
        assert_eq!(viewport.len(), 1, "{what}: one viewport meta");
        let content = viewport[0].attr("content").unwrap_or_default().replace(' ', "");
        assert!(content.contains("width=device-width"), "{what}: {content}");
        assert!(!content.contains("user-scalable=no") && !content.contains("maximum-scale"), "{what}: zoom is not blocked: {content}");
        assert!(text_of_id_or_tag(&text, "title").is_some_and(|t| !t.is_empty()), "{what}: a title");
        if matches!(r.status, 200 | 422) {
            assert!(text_of_id_or_tag(&text, "title").is_some_and(|t| t.contains("Pocketmail")), "{what}: the site name in the title");
        }
    }
}

fn text_of_id_or_tag(html: &str, tag: &str) -> Option<String> {
    let t = tags(html, tag).into_iter().next()?;
    Some(unescape(html[t.end..].split(&format!("</{tag}>")).next()?.trim()))
}

// ---------------------------------------------------------------------------------------------
// Navigation, error pages and wording

const ADMIN: &str = "admin@example.com";

/// The markup between `<tag ...>` and its `</tag>` for the first such element.
fn inner<'a>(html: &'a str, tag: &str) -> Option<&'a str> {
    let t = tags(html, tag).into_iter().next()?;
    let close = html[t.end..].find(&format!("</{tag}>"))?;
    Some(&html[t.end..t.end + close])
}

/// The links of the page's `<nav>`: (href, text, aria-current).
fn nav_links(html: &str, what: &str) -> Vec<(String, String, Option<String>)> {
    assert_eq!(tags(html, "nav").len(), 1, "{what}: one <nav>:\n{html}");
    let nav = inner(html, "nav").unwrap_or_else(|| panic!("{what}: a closed <nav>"));
    tags(nav, "a")
        .into_iter()
        .map(|a| {
            let text = visible_text(nav[a.end..].split("</a>").next().unwrap_or_default());
            (a.attr("href").unwrap_or_default().to_string(), text, a.attr("aria-current").map(str::to_string))
        })
        .collect()
}

#[tokio::test]
async fn admin_pages_have_nav_with_current_page() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let user_page = account_href(h.id(USER));
    for (what, path, current) in [("account list", "/accounts", Some("/accounts")), ("own page", "/me", Some("/me")), ("account page", user_page.as_str(), None)] {
        let r = b.get(path).await;
        assert_eq!(r.status, 200, "{what}: {}", r.text());
        let links = nav_links(&r.text(), what);
        for (href, text) in [("/accounts", "Accounts"), ("/me", "Your account")] {
            let found: Vec<_> = links.iter().filter(|(h, _, _)| h == href).collect();
            assert_eq!(found.len(), 1, "{what}: one nav link to {href}: {links:?}");
            assert_eq!(found[0].1, text, "{what}: the {href} link says {text:?}");
        }
        for (href, _, aria) in &links {
            let want = (Some(href.as_str()) == current).then_some("page");
            assert_eq!(aria.as_deref().filter(|v| *v == "page"), want, "{what}: aria-current=\"page\" only on the link to this page ({href}): {links:?}");
        }
    }

    let mut user = h.signed_in(USER).await;
    let me = user.get("/me").await.text();
    assert!(!tags(&me, "a").iter().any(|a| a.attr("href") == Some("/accounts")), "a non-admin sees no Accounts link:\n{me}");
}

/// A `<main>` that says why, in a sentence besides its heading, and a link to `/`. Returns the
/// sentence(s).
#[track_caller]
fn assert_explained(r: &Resp, what: &str) -> String {
    let text = r.text();
    let main = inner(&text, "main").unwrap_or_else(|| panic!("{what}: a <main>:\n{text}"));
    let heading = inner(main, "h1").map(visible_text).unwrap_or_default();
    let said = visible_text(main).replacen(&heading, "", 1).trim().to_string();
    assert!(said.contains('.') && said.split_whitespace().count() >= 3, "{what}: a one-sentence reason besides the heading {heading:?}, got {said:?}:\n{text}");
    assert!(tags(&text, "a").iter().any(|a| a.attr("href") == Some("/")), "{what}: a link to /:\n{text}");
    said
}

#[tokio::test]
async fn error_pages_say_why_and_link_home() {
    let h = WebHarness::start().await;
    h.user(USER);
    let not_found = h.get("/no-such-page").await;
    assert_eq!(not_found.status, 404);
    let not_found = assert_explained(&not_found, "404");

    let mut b = h.signed_in(USER).await;
    let r = b.get("/accounts").await;
    assert_eq!(r.status, 403, "a non-admin on the account list");
    let forbidden = assert_explained(&r, "403 not an admin");
    assert_ne!(forbidden, not_found, "403 and 404 give their own reasons");

    assert_eq!(b.get("/me").await.status, 200);
    let token = b.csrf.clone().expect("a csrf token on the own page");
    let r = b.post_exact("/logout", &[(CSRF_FIELD, &one_off(&token))]).await;
    assert_eq!(r.status, 403, "a wrong CSRF token");
    assert_explained(&r, "403 CSRF failure");
}

#[tokio::test]
async fn login_and_address_inputs_not_capitalized_or_spellchecked() {
    let h = WebHarness::start().await;
    let setup = h.server.setup_path().expect("a setup link while no admin exists");
    let setup_page = h.get(&setup).await;
    assert_eq!(setup_page.status, 200);
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;

    let mut found = vec![("sign-in", post_form(&h.get("/login").await.text(), "/login"))];
    found.push(("add account", post_form(&b.get("/accounts").await.text(), "/accounts")));
    found.push(("add address", b.account_form(USER, "/account/address/add").await));
    found.extend(post_forms(&setup_page.text(), "/setup").into_iter().map(|f| ("setup", f)));
    assert_eq!(found.len(), 5, "sign-in, add account, add address and the two setup forms");
    for (what, form) in found {
        let text: Vec<&Tag> = form.fields.iter().filter(|f| matches!(f.attr("type"),None|Some("text")|Some("email"))).collect();
        assert_eq!(text.len(), 1, "{what}: one user name or address input: {:?}", form.fields);
        let input = text[0];
        assert_eq!(input.attr("autocapitalize"), Some("none"), "{what}: phones must not capitalize a user name or address: {input:?}");
        assert_eq!(input.attr("spellcheck"), Some("false"), "{what}: no spellcheck on a user name or address: {input:?}");
    }
}

#[tokio::test]
async fn user_name_wording_is_consistent() {
    let h = WebHarness::start().await;
    h.admin(ADMIN);
    h.user(USER);
    let mut b = h.signed_in(ADMIN).await;
    let list = b.get("/accounts").await.text();
    let rows = table_rows(&list);
    let header = &rows.first().expect("the account table").0;
    let form = post_form(&list, "/accounts");
    let field = form.text_field();
    let label = tags(&list, "label").into_iter().find(|l| l.attr("for") == Some(field.as_str())).expect("a label for the user name");
    let label = visible_text(list[label.end..].split("</label>").next().unwrap_or_default());
    assert_eq!(label, "User name", "the new-account form's label");
    assert_eq!(header[0], label, "the table's first column is headed as the form labels it: {header:?}");

    let pages = [
        ("account list", list.clone()),
        ("account page", b.account_page(USER).await),
        ("own page", b.get("/me").await.text()),
        ("sign-in", h.get("/login").await.text()),
    ];
    for (what, html) in pages {
        let text = visible_text(&html);
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower.split(|c: char| !c.is_alphanumeric()).collect();
        assert!(!words.iter().any(|w| *w == "login" || *w == "logins"), "{what}: says \"user name\", never \"login\": {text}");
    }
}
