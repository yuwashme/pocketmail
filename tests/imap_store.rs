//! Group E, STORE / UID STORE: FLAGS, +FLAGS, -FLAGS, .SILENT, \Deleted accepted but ignored,
//! read-only refusal, changes visible to other sessions .

mod harness;
mod net;

use harness::*;
use synology_mail_server::store::Flags;

const USER: &str = "test@example.com";

#[tokio::test]
async fn add_replace_remove() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    let mut c = h.select(USER).await;

    let d = c.cmd("S1", "STORE 1 +FLAGS (\\Flagged)").await;
    d.assert_ok();
    let m = d.fetch_map();
    assert_eq!(
        m[&1].flags(),
        flags(&["\\Flagged", "\\Recent"]),
        "{}",
        d.transcript()
    );
    assert_eq!(h.stored_flags(mb, 1), Flags::FLAGGED);

    let d = c.cmd("S2", "STORE 2 FLAGS (\\Seen \\Draft)").await;
    assert_eq!(
        d.fetch_map()[&2].flags(),
        flags(&["\\Seen", "\\Draft", "\\Recent"])
    );
    assert_eq!(h.stored_flags(mb, 2), Flags::SEEN | Flags::DRAFT);

    let d = c.cmd("S3", "STORE 2 -FLAGS (\\Draft)").await;
    assert_eq!(d.fetch_map()[&2].flags(), flags(&["\\Seen", "\\Recent"]));
    assert_eq!(h.stored_flags(mb, 2), Flags::SEEN);

    let d = c.cmd("S4", "store 2 flags ()").await;
    d.assert_ok();
    assert_eq!(d.fetch_map()[&2].flags(), flags(&["\\Recent"]));
    assert_eq!(h.stored_flags(mb, 2), Flags::empty());

    // A single flag without parentheses is valid too (RFC 3501 flag-list or flag).
    c.cmd("S5", "STORE 3 +FLAGS \\Answered").await.assert_ok();
    assert_eq!(h.stored_flags(mb, 3), Flags::ANSWERED);
    // Only the targeted messages changed.
    assert_eq!(h.stored_flags(mb, 1), Flags::FLAGGED);
}

#[tokio::test]
async fn silent_variants_send_no_fetch() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    let mut c = h.select(USER).await;
    for (cmd, uid, want) in [
        ("STORE 1 +FLAGS.SILENT (\\Answered)", 1, Flags::ANSWERED),
        (
            "STORE 2 FLAGS.SILENT (\\Seen \\Flagged)",
            2,
            Flags::SEEN | Flags::FLAGGED,
        ),
        ("STORE 2 -FLAGS.SILENT (\\Seen)", 2, Flags::FLAGGED),
        ("UID STORE 3 +FLAGS.SILENT (\\Draft)", 3, Flags::DRAFT),
    ] {
        let d = c.cmd("Q1", cmd).await;
        d.assert_ok();
        assert!(
            d.data("FETCH").is_empty(),
            "{cmd}: no FETCH response:\n{}",
            d.transcript()
        );
        assert_eq!(h.stored_flags(mb, uid), want, "{cmd}");
    }
}

#[tokio::test]
async fn deleted_search_and_expunge_follow_the_session_sequence_numbers() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 3);
    let mut c = h.select(USER).await;
    c.cmd("D1", "STORE 1:2 +FLAGS (\\Deleted)")
        .await
        .assert_ok();
    assert_eq!(c.cmd("D2", "SEARCH DELETED").await.search(), vec![1, 2]);
    let result = c.cmd("D3", "EXPUNGE").await;
    result.assert_ok();
    assert_eq!(result.data("EXPUNGE").len(), 2);
    assert_eq!(h.store.messages(mb).unwrap()[0].uid, 3);
}

#[tokio::test]
async fn uid_store_and_ranges() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 4);
    let mut c = h.select(USER).await;

    let d = c.cmd("U1", "UID STORE 2 +FLAGS (\\Flagged)").await;
    d.assert_ok();
    let m = d.fetch_map();
    assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![2]);
    assert_eq!(m[&2].num("UID"), 2, "UID STORE responses carry UID");
    assert!(m[&2].flags().contains("\\flagged"));

    let d = c.cmd("U2", "STORE 1:* +FLAGS (\\Seen)").await;
    assert_eq!(d.fetch_map().len(), 4);
    for uid in 1..=4 {
        assert!(h.stored_flags(mb, uid).contains(Flags::SEEN));
    }
    let d = c.cmd("U3", "UID STORE 3:100 -FLAGS (\\Seen)").await;
    assert_eq!(
        d.fetch_map().keys().copied().collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_eq!(h.stored_flags(mb, 3), Flags::empty());
    assert_eq!(h.stored_flags(mb, 2), Flags::SEEN | Flags::FLAGGED);

    c.cmd("U4", "UID STORE 100:200 +FLAGS (\\Seen)")
        .await
        .assert_ok();
    c.cmd("U5", "STORE 5 +FLAGS (\\Seen)").await.assert_bad();
    c.cmd("U6", "STORE 1 +FLAGS (\\Seen").await.assert_bad();
    c.cmd("U7", "STORE 1 TOGGLE (\\Seen)").await.assert_bad();
}

#[tokio::test]
async fn store_is_refused_after_examine() {
    let h = Harness::start().await;
    let mb = h.simple_account(USER, 2);
    let mut c = h.login(USER).await;
    c.cmd("E1", "EXAMINE INBOX").await.assert_ok();
    c.cmd("E2", "STORE 1 +FLAGS (\\Seen)").await.assert_no();
    c.cmd("E3", "UID STORE 2 FLAGS (\\Flagged)")
        .await
        .assert_no();
    assert_eq!(h.stored_flags(mb, 1), Flags::empty());
    assert_eq!(h.stored_flags(mb, 2), Flags::empty());
}

#[tokio::test]
async fn changes_are_visible_to_another_session() {
    let h = Harness::start().await;
    h.simple_account(USER, 2);
    let mut a = h.select(USER).await;
    let mut b = h.select(USER).await;
    a.cmd("A1", "STORE 1 +FLAGS (\\Flagged \\Answered)")
        .await
        .assert_ok();
    let d = b.cmd("B1", "FETCH 1 FLAGS").await;
    let f = d.fetch_map()[&1].flags();
    assert!(
        f.contains("\\flagged") && f.contains("\\answered"),
        "{}",
        d.transcript()
    );
    assert!(!f.contains("\\recent"), "B did not claim \\Recent");
}
