//! Group E, mailbox level: SELECT / EXAMINE responses, \Recent ownership, LIST / LSUB, SUBSCRIBE,
//! STATUS, NOOP after a delivery, the NO [CANNOT] set, EXPUNGE / CLOSE / CHECK
//! (RFC 3501 6.3 and 7).

mod harness;
mod net;

use harness::*;
use synology_mail_server::store::Flags;

const USER: &str = "test@example.com";

fn assert_permanentflags(d: &Done, expected: &[&str]) {
    let pf = d.code("PERMANENTFLAGS").unwrap_or_else(|| panic!("no [PERMANENTFLAGS ...]:\n{}", d.transcript()));
    let toks = tokenize(pf.as_bytes());
    assert_eq!(toks.len(), 1, "PERMANENTFLAGS is one list: {pf}");
    assert_eq!(flag_set(&toks[0]), flags(expected), "PERMANENTFLAGS:\n{}", d.transcript());
}

fn assert_flags_response(d: &Done) {
    let f = d.data("FLAGS");
    assert_eq!(f.len(), 1, "one * FLAGS line:\n{}", d.transcript());
    let set = flag_set(&f[0][2]);
    let required = flags(&["\\Seen", "\\Answered", "\\Flagged", "\\Draft"]);
    assert!(required.is_subset(&set), "FLAGS must list the four system flags, got {set:?}");
    let allowed = flags(&["\\Seen", "\\Answered", "\\Flagged", "\\Draft", "\\Deleted"]);
    assert!(set.is_subset(&allowed), "FLAGS lists only system flags (no keywords, no \\Recent), got {set:?}");
}

#[tokio::test]
async fn select_inbox_sends_every_required_response() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    h.set_flags(mb, 1, Flags::SEEN);
    let mut c = h.login(USER).await;
    let d = c.cmd("S1", "SELECT INBOX").await;
    d.assert_ok();
    assert_flags_response(&d);
    assert_eq!(d.number("EXISTS"), Some(3), "{}", d.transcript());
    assert_eq!(d.number("RECENT"), Some(3), "first SELECT claims all three as \\Recent");
    assert_eq!(d.code("UIDVALIDITY"), Some(h.uidvalidity(mb).to_string()));
    assert_eq!(d.code("UIDNEXT").as_deref(), Some("4"));
    assert_eq!(d.code("UNSEEN").as_deref(), Some("2"), "first unseen sequence number");
    assert_permanentflags(&d, &["\\Seen", "\\Answered", "\\Flagged", "\\Draft", "\\Deleted"]);
    assert!(d.tagged_text().to_ascii_uppercase().starts_with("[READ-WRITE]"), "{}", d.transcript());

    // Mailbox names: INBOX is case-insensitive, quoted or not.
    c.cmd("S2", "select inbox").await.assert_ok();
    c.cmd("S3", "SELECT \"InBoX\"").await.assert_ok();
}

#[tokio::test]
async fn recent_belongs_to_the_first_session_that_selects() {
    let h = Harness::start().await;
    h.simple_account(USER, 3);
    let mut a = h.login(USER).await;
    let d = a.cmd("A1", "SELECT INBOX").await;
    assert_eq!(d.number("RECENT"), Some(3));
    let f = a.cmd("A2", "FETCH 1:* FLAGS").await;
    f.assert_ok();
    for (seq, items) in f.fetch_map() {
        assert!(items.flags().contains("\\recent"), "message {seq} is \\Recent in the claiming session");
    }

    let mut b = h.login(USER).await;
    let d = b.cmd("B1", "SELECT INBOX").await;
    assert_eq!(d.number("RECENT"), Some(0), "already claimed:\n{}", d.transcript());
    let f = b.cmd("B2", "FETCH 1:* FLAGS").await;
    for (seq, items) in f.fetch_map() {
        assert!(!items.flags().contains("\\recent"), "message {seq} is not \\Recent for a later session");
    }
}

#[tokio::test]
async fn examine_is_read_only_and_claims_nothing() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    let mut c = h.login(USER).await;
    let d = c.cmd("E1", "EXAMINE INBOX").await;
    d.assert_ok();
    assert_flags_response(&d);
    assert_eq!(d.number("EXISTS"), Some(3));
    assert!(d.tagged_text().to_ascii_uppercase().starts_with("[READ-ONLY]"), "{}", d.transcript());
    assert_permanentflags(&d, &[]);

    // No writes: STORE refused, a non-PEEK body fetch does not set \Seen.
    c.cmd("E2", "STORE 1 +FLAGS (\\Flagged)").await.assert_no();
    c.cmd("E3", "FETCH 1 BODY[]").await.assert_ok();
    assert_eq!(h.stored_flags(mb, 1), Flags::empty(), "EXAMINE must not change flags");

    // \Recent is still unclaimed for the next SELECT.
    let mut s = h.login(USER).await;
    assert_eq!(s.cmd("S1", "SELECT INBOX").await.number("RECENT"), Some(3));
}

#[tokio::test]
async fn selecting_a_missing_mailbox_fails_and_leaves_the_selected_state() {
    let h = Harness::start().await;
    h.simple_account(USER, 2);
    let mut c = h.select(USER).await;
    c.cmd("M1", "SELECT Archive").await.assert_no();
    c.cmd("M2", "FETCH 1 FLAGS").await.assert_refused();
    c.cmd("M3", "EXAMINE \"Sent Items\"").await.assert_no();
    c.cmd("M4", "SELECT INBOX").await.assert_ok();
}

#[tokio::test]
async fn list_patterns() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.login(USER).await;

    // The "" probe: hierarchy delimiter "/" and the root.
    let d = c.cmd("L1", "LIST \"\" \"\"").await;
    d.assert_ok();
    let l = d.data("LIST");
    assert_eq!(l.len(), 1, "{}", d.transcript());
    assert!(flag_set(&l[0][2]).contains("\\noselect"), "{}", d.transcript());
    assert_eq!(l[0][3], Tok::Str(b"/".to_vec()), "delimiter");
    assert_eq!(name_of(&l[0][4]), "");

    for (i, pattern) in ["*", "%", "INBOX", "inbox", "\"IN*\"", "I%", "\"*\""].iter().enumerate() {
        let d = c.cmd(&format!("L{}", i + 2), &format!("LIST \"\" {pattern}")).await;
        d.assert_ok();
        let l = d.data("LIST");
        assert_eq!(l.len(), 1, "LIST \"\" {pattern}:\n{}", d.transcript());
        assert_eq!(l[0][3], Tok::Str(b"/".to_vec()));
        assert_eq!(name_of(&l[0][4]), "INBOX", "INBOX is always reported upper-case");
        assert!(!flag_set(&l[0][2]).contains("\\noselect"));
    }
    for (i, pattern) in ["Sent", "\"INBOX/*\"", "x*", "\"%/%\""].iter().enumerate() {
        let d = c.cmd(&format!("N{i}"), &format!("LIST \"\" {pattern}")).await;
        d.assert_ok();
        assert!(d.data("LIST").is_empty(), "LIST \"\" {pattern} matches nothing:\n{}", d.transcript());
    }
}

#[tokio::test]
async fn lsub_follows_subscribe_and_unsubscribe() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.login(USER).await;
    let names = |d: &Done| d.data("LSUB").iter().map(|l| name_of(&l[4])).collect::<Vec<_>>();

    // INBOX starts subscribed (store default).
    let d = c.cmd("U1", "LSUB \"\" \"*\"").await;
    d.assert_ok();
    assert_eq!(names(&d), vec!["INBOX"], "{}", d.transcript());

    c.cmd("U2", "UNSUBSCRIBE INBOX").await.assert_ok();
    let d = c.cmd("U3", "LSUB \"\" \"*\"").await;
    assert!(names(&d).is_empty(), "{}", d.transcript());
    // Still listed by LIST.
    assert_eq!(c.cmd("U4", "LIST \"\" *").await.data("LIST").len(), 1);

    c.cmd("U5", "SUBSCRIBE inbox").await.assert_ok();
    let d = c.cmd("U6", "LSUB \"\" %").await;
    assert_eq!(names(&d), vec!["INBOX"]);
    c.cmd("U7", "SUBSCRIBE Archive").await.assert_no();
}

#[tokio::test]
async fn status_items() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    h.set_flags(mb, 2, Flags::SEEN);
    let mut c = h.login(USER).await;
    let d = c.cmd("T1", "STATUS INBOX (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)").await;
    d.assert_ok();
    let s = d.data("STATUS");
    assert_eq!(s.len(), 1, "{}", d.transcript());
    assert_eq!(name_of(&s[0][2]), "INBOX");
    let m = pairs(&s[0][3]);
    assert_eq!(m.get("MESSAGES").map(String::as_str), Some("3"));
    assert_eq!(m.get("RECENT").map(String::as_str), Some("3"));
    assert_eq!(m.get("UIDNEXT").map(String::as_str), Some("4"));
    assert_eq!(m.get("UIDVALIDITY"), Some(&h.uidvalidity(mb).to_string()));
    assert_eq!(m.get("UNSEEN").map(String::as_str), Some("2"));
    assert_eq!(m.len(), 5);

    // Only what was asked; STATUS does not claim \Recent.
    let d = c.cmd("T2", "status inbox (UIDNEXT)").await;
    assert_eq!(pairs(&d.data("STATUS")[0][3]).keys().collect::<Vec<_>>(), vec!["UIDNEXT"]);
    assert_eq!(c.cmd("T3", "SELECT INBOX").await.number("RECENT"), Some(3));

    // Allowed while selected; missing mailbox and unknown item refused.
    c.cmd("T4", "STATUS INBOX (MESSAGES)").await.assert_ok();
    c.cmd("T5", "STATUS Archive (MESSAGES)").await.assert_no();
    c.cmd("T6", "STATUS INBOX (FOO)").await.assert_bad();
}

#[tokio::test]
async fn noop_reports_a_new_delivery_as_exists_and_recent() {
    let h = Harness::start().await;
    h.simple_account(USER, 3);
    let mut c = h.select(USER).await;
    let d = c.cmd("N1", "NOOP").await;
    d.assert_ok();
    assert_eq!(d.number("EXISTS"), None, "nothing new yet:\n{}", d.transcript());

    h.deliver(USER, b"From: late@example.test\r\nSubject: late\r\n\r\nnew\r\n", ms("02-Mar-2026 10:00:00 +0000"));
    let d = c.cmd("N2", "NOOP").await;
    d.assert_ok();
    assert_eq!(d.number("EXISTS"), Some(4), "{}", d.transcript());
    assert_eq!(d.number("RECENT"), Some(4), "3 claimed at SELECT + the new one");
    let f = c.cmd("N3", "FETCH 4 (UID FLAGS)").await;
    let m = f.fetch_map();
    assert_eq!(m[&4].num("UID"), 4);
    assert!(m[&4].flags().contains("\\recent"));

    let d = c.cmd("N4", "NOOP").await;
    assert_eq!(d.number("EXISTS"), None, "reported once:\n{}", d.transcript());

    // CHECK also succeeds in the selected state.
    c.cmd("N5", "CHECK").await.assert_ok();
}

#[tokio::test]
async fn new_delivery_is_seen_by_other_commands_too() {
    let h = Harness::start().await;
    h.simple_account(USER, 1);
    let mut c = h.select(USER).await;
    h.deliver(USER, b"Subject: two\r\n\r\nx\r\n", ms("02-Mar-2026 10:00:00 +0000"));
    // Whatever command comes next, the client must learn about message 2 before using it.
    let d = c.cmd("F1", "FETCH 1 FLAGS").await;
    d.assert_ok();
    let d2 = c.cmd("F2", "NOOP").await;
    let exists = d.number("EXISTS").or(d2.number("EXISTS"));
    assert_eq!(exists, Some(2), "EXISTS 2 after FETCH or NOOP:\n{}\n{}", d.transcript(), d2.transcript());
    c.cmd("F3", "FETCH 2 UID").await.assert_ok();
}

#[tokio::test]
async fn unsupported_mailbox_operations_get_no_cannot() {
    let h = Harness::start().await;
    h.simple_account(USER, 2);
    let mut c = h.login(USER).await;
    for (i, cmd) in ["CREATE Archive", "CREATE INBOX/Sub", "DELETE Archive", "DELETE INBOX", "RENAME INBOX Old", "RENAME Archive Old"]
        .iter()
        .enumerate()
    {
        c.cmd(&format!("C{i}"), cmd).await.assert_no().assert_code("CANNOT");
    }
    let msg = b"From: me@example.com\r\nSubject: append\r\n\r\nhello\r\n";
    let d = c.cmd_parts("A1", &[Part::Text("APPEND INBOX (\\Seen) "), Part::Lit(msg)]).await;
    d.assert_ok();
    c.cmd("A2","SELECT INBOX").await.assert_ok();
    c.cmd("C10","COPY 1 INBOX").await.assert_ok();
    c.cmd("C11","UID COPY 1:2 INBOX").await.assert_ok();
    assert_eq!(c.cmd("C11a","FETCH 1:* UID").await.fetches().len(),6);
    c.cmd("C12", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn expunge_and_close_succeed_and_remove_nothing() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    let mut c = h.select(USER).await;
    c.cmd("X1", "STORE 1:2 +FLAGS (\\Deleted)").await.assert_ok();
    let d = c.cmd("X2", "EXPUNGE").await;
    d.assert_ok();
    assert_eq!(d.data("EXPUNGE").len(),2);
    assert_eq!(h.store.messages(mb).unwrap().len(), 1);
    assert_eq!(c.cmd("X3", "FETCH 1:* UID").await.fetches().len(), 1);

    let d = c.cmd("X4", "CLOSE").await;
    d.assert_ok();
    assert!(d.data("EXPUNGE").is_empty());
    assert_eq!(h.store.messages(mb).unwrap().len(), 1);
    // CLOSE returns to the authenticated state.
    c.cmd("X5", "FETCH 1 FLAGS").await.assert_refused();
    assert_eq!(c.cmd("X6", "SELECT INBOX").await.number("EXISTS"), Some(1));
}
