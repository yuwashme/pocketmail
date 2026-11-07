//! Group E, SEARCH / UID SEARCH: every RFC 3501 6.4.4 key, OR / NOT nesting, UTF-8 literals,
//! BADCHARSET, decoding of RFC 2047 headers and QP bodies .
//! The mailbox is `Harness::search_account` (six messages, see `search_messages`).

mod harness;
mod net;

use harness::*;

async fn searching() -> (Harness, Client) {
    let h = Harness::start().await;
    h.search_account();
    let c = h.select(SEARCH_LOGIN).await;
    (h, c)
}

/// Run each `SEARCH <criteria>` and collect every mismatch, so one run shows all failing keys.
async fn check(c: &mut Client, cases: &[(&str, &[u32])]) {
    let mut bad = Vec::new();
    for (i, (criteria, want)) in cases.iter().enumerate() {
        let d = c.cmd(&format!("S{i}"), &format!("SEARCH {criteria}")).await;
        if d.status() != "OK" {
            bad.push(format!("SEARCH {criteria}: {}", d.transcript().trim_end()));
            continue;
        }
        let got = d.search();
        if got != *want {
            bad.push(format!("SEARCH {criteria}: want {want:?}, got {got:?}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[tokio::test]
async fn select_claims_only_messages_5_and_6_as_recent() {
    // Sanity of the setup itself: an earlier session claimed 1-4, so SELECT reports RECENT 2.
    let h = Harness::start().await;
    h.search_account();
    let mut c = h.login(SEARCH_LOGIN).await;
    let d = c.cmd("R1", "SELECT INBOX").await;
    d.assert_ok();
    assert_eq!(d.number("EXISTS"), Some(6));
    assert_eq!(d.number("RECENT"), Some(2));
    assert_eq!(d.code("UNSEEN").as_deref(), Some("3"));
}

#[tokio::test]
async fn flag_keys() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("ALL", &[1, 2, 3, 4, 5, 6]),
            ("SEEN", &[1, 2, 6]),
            ("UNSEEN", &[3, 4, 5]),
            ("ANSWERED", &[2]),
            ("UNANSWERED", &[1, 3, 4, 5, 6]),
            ("FLAGGED", &[3]),
            ("UNFLAGGED", &[1, 2, 4, 5, 6]),
            ("DRAFT", &[4]),
            ("UNDRAFT", &[1, 2, 3, 5, 6]),
            ("DELETED", &[]),
            ("UNDELETED", &[1, 2, 3, 4, 5, 6]),
            ("RECENT", &[5, 6]),
            ("NEW", &[5]),
            ("OLD", &[1, 2, 3, 4]),
            ("KEYWORD foo", &[]),
            ("UNKEYWORD foo", &[1, 2, 3, 4, 5, 6]),
            ("seen", &[1, 2, 6]),
        ],
    )
    .await;
}

#[tokio::test]
async fn address_keys_decode_rfc2047() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("FROM alice", &[1, 3]),
            ("FROM example.org", &[2, 5]),
            ("FROM \"Alice Example\"", &[1]),
            ("FROM BOB", &[2, 5]),
            ("TO example.com", &[1, 2, 4, 5, 6]),
            ("TO dave", &[3]),
            ("CC carol", &[1]),
            ("CC bob", &[]),
            ("BCC hidden", &[2]),
        ],
    )
    .await;
    // "Štefan" exists only as =?ISO-8859-2?Q?=A9tefan?=.
    let d = c.cmd_parts("U1", &[Part::Text("SEARCH CHARSET UTF-8 FROM "), Part::Lit("Štefan".as_bytes())]).await;
    d.assert_ok();
    assert_eq!(d.search(), vec![4]);
}

#[tokio::test]
async fn subject_with_ascii_and_utf8_literal() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("SUBJECT quarterly", &[1, 3, 6]),
            ("SUBJECT \"Re: Quarterly\"", &[3]),
            ("SUBJECT lunch?", &[2]),
            ("SUBJECT nothing-like-this", &[]),
        ],
    )
    .await;
    let d = c.cmd_parts("U1", &[Part::Text("SEARCH CHARSET UTF-8 SUBJECT "), Part::Lit("čćž".as_bytes())]).await;
    d.assert_ok();
    assert_eq!(d.search(), vec![4], "encoded-word subject decoded before matching");
    // Case-insensitive beyond ASCII is not required; the exact decoded text must match.
    let d = c.cmd_parts("U2", &[Part::Text("SEARCH CHARSET utf-8 SUBJECT "), Part::Lit("Šumniki".as_bytes())]).await;
    assert_eq!(d.search(), vec![4]);
}

#[tokio::test]
async fn body_and_text_keys_decode_the_body() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("BODY report", &[2]),
            ("BODY \"tomorrow at nine\"", &[6]),
            ("BODY xxxxxxxxxx", &[5]),
            ("BODY Quarterly", &[]),
            ("TEXT report", &[1, 2, 3]),
            ("TEXT \"Looks good\"", &[3]),
        ],
    )
    .await;
    let d = c.cmd_parts("U1", &[Part::Text("SEARCH CHARSET UTF-8 BODY "), Part::Lit("skače".as_bytes())]).await;
    assert_eq!(d.search(), vec![4], "8-bit UTF-8 body");
    let d = c.cmd_parts("U2", &[Part::Text("SEARCH CHARSET UTF-8 BODY "), Part::Lit("Café".as_bytes())]).await;
    assert_eq!(d.search(), vec![6], "quoted-printable body decoded");
}

#[tokio::test]
async fn header_key() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("HEADER X-Priority 1", &[3]),
            ("HEADER x-priority \"\"", &[3]),
            ("HEADER Message-ID s2@", &[2]),
            ("HEADER X-Missing \"\"", &[]),
        ],
    )
    .await;
}

#[tokio::test]
async fn internal_date_keys_compare_days_in_utc() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("BEFORE 3-Mar-2026", &[1, 2]),
            ("ON 3-Mar-2026", &[3, 4]),
            ("ON 03-mar-2026", &[3, 4]),
            ("SINCE 4-Mar-2026", &[5, 6]),
            ("SINCE 3-Mar-2026", &[3, 4, 5, 6]),
            ("BEFORE 1-Mar-2026", &[]),
            ("SINCE \"5-Mar-2026\"", &[6]),
        ],
    )
    .await;
}

#[tokio::test]
async fn sent_date_keys_use_the_date_header_ignoring_time_and_zone() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("SENTBEFORE 4-Feb-2026", &[1, 2]),
            ("SENTON 3-Feb-2026", &[2]),
            ("SENTON 4-Feb-2026", &[3]),
            ("SENTSINCE 6-Feb-2026", &[5, 6]),
            ("SENTBEFORE 1-Jan-2026", &[]),
        ],
    )
    .await;
}

#[tokio::test]
async fn size_uid_and_sequence_set_keys() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("LARGER 1000", &[5]),
            ("SMALLER 1000", &[1, 2, 3, 4, 6]),
            ("LARGER 100000", &[]),
            ("UID 2:3", &[2, 3]),
            ("UID 100:*", &[6]),
            ("UID 100:200", &[]),
            ("UID 1,5:*", &[1, 5, 6]),
            ("2:4", &[2, 3, 4]),
            ("*", &[6]),
            ("1,6", &[1, 6]),
        ],
    )
    .await;
}

#[tokio::test]
async fn boolean_combinations() {
    let (_h, mut c) = searching().await;
    check(
        &mut c,
        &[
            ("FROM alice SEEN", &[1]),
            ("NOT SEEN", &[3, 4, 5]),
            ("OR FROM bob FLAGGED", &[2, 3, 5]),
            ("NOT OR SEEN FLAGGED", &[4, 5]),
            ("OR OR ANSWERED DRAFT FLAGGED", &[2, 3, 4]),
            ("OR ANSWERED OR DRAFT FLAGGED", &[2, 3, 4]),
            ("(FROM bob SUBJECT lunch)", &[2]),
            ("NOT (FROM bob)", &[1, 3, 4, 6]),
            ("NOT NOT SEEN", &[1, 2, 6]),
            ("OR (FROM alice FLAGGED) (SUBJECT big)", &[3, 5]),
            ("UNSEEN NOT RECENT", &[3, 4]),
            ("ALL NOT ALL", &[]),
        ],
    )
    .await;
}

#[tokio::test]
async fn charsets_and_errors() {
    let (_h, mut c) = searching().await;
    let d = c.cmd("C1", "SEARCH CHARSET US-ASCII SUBJECT lunch").await;
    d.assert_ok();
    assert_eq!(d.search(), vec![2]);
    let d = c.cmd("C2", "SEARCH CHARSET utf-8 SUBJECT lunch").await;
    assert_eq!(d.search(), vec![2]);

    let d = c.cmd("C3", "SEARCH CHARSET ISO-8859-2 SUBJECT lunch").await;
    d.assert_no().assert_code("BADCHARSET");
    assert!(d.data("SEARCH").is_empty());
    c.cmd("C4", "SEARCH CHARSET KOI8-R ALL").await.assert_no().assert_code("BADCHARSET");

    for (i, bad) in ["FOO", "BEFORE 31-Feb-2026", "BEFORE yesterday", "LARGER x", "OR SEEN", "(SEEN", "UID", "HEADER X-Priority"].iter().enumerate() {
        c.cmd(&format!("B{i}"), &format!("SEARCH {bad}")).await.assert_bad();
    }
    c.cmd("Z", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn empty_result_is_a_bare_search_line() {
    let (_h, mut c) = searching().await;
    let d = c.cmd("E1", "SEARCH DELETED").await;
    d.assert_ok();
    let lines: Vec<_> = d.untagged.iter().filter(|l| l.to_ascii_uppercase().starts_with(b"* SEARCH")).collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].as_slice(), b"* SEARCH\r\n", "no trailing space");
}

#[tokio::test]
async fn uid_search_returns_uids() {
    let (_h, mut c) = searching().await;
    let d = c.cmd("U1", "UID SEARCH FLAGGED").await;
    d.assert_ok();
    assert_eq!(d.search(), vec![3]);
    let d = c.cmd("U2", "UID SEARCH UID 4:*").await;
    assert_eq!(d.search(), vec![4, 5, 6]);
    let d = c.cmd("U3", "UID SEARCH 1:2").await;
    assert_eq!(d.search(), vec![1, 2], "a bare sequence set is still sequence numbers");
}

#[tokio::test]
async fn search_sees_flag_changes_and_new_mail() {
    let (h, mut c) = searching().await;
    c.cmd("F1", "STORE 5 +FLAGS (\\Seen)").await.assert_ok();
    let d = c.cmd("F2", "SEARCH UNSEEN").await;
    assert_eq!(d.search(), vec![3, 4]);
    h.deliver(SEARCH_LOGIN, b"From: new@example.test\r\nSubject: fresh\r\n\r\nhi\r\n", ms("06-Mar-2026 10:00:00 +0000"));
    c.cmd("F3", "NOOP").await.assert_ok();
    let d = c.cmd("F4", "SEARCH SUBJECT fresh").await;
    assert_eq!(d.search(), vec![7]);
}
