//! Group E, FETCH: ENVELOPE / BODY / BODYSTRUCTURE against the hand-written goldens in
//! tests/fixtures/mail, every data item and macro, sections and partials, PEEK vs \Seen,
//! sequence sets, the 25 MiB message (RFC 3501 6.4.5 and 7.4.2).

mod harness;
mod net;

use harness::*;
use synology_mail_server::store::Flags;
use synology_mail_server::time::format_imap_datetime;

/// FETCH `item` for every fixture and compare with `<fixture>.<kind>`; reports every mismatch.
async fn compare_goldens(item: &str, kind: &str, names: &[&str], ci_strings: bool) {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let d = c.cmd("G1", &format!("FETCH 1:11 {item}")).await;
    d.assert_ok();
    let got = d.fetch_map();
    let mut bad = Vec::new();
    for name in names {
        let seq = fixture_seq(name);
        let want = golden(name, kind);
        match got.get(&seq) {
            None => bad.push(format!("{name}: no FETCH response")),
            Some(items) if !items.has(item) => {
                bad.push(format!("{name}: no {item} item ({:?})", items.keys()))
            }
            Some(items) => {
                let v = items.get(item);
                if !tok_eq(v, &want, ci_strings) {
                    bad.push(format!(
                        "{name}:\n  want {}\n  got  {}",
                        render(&want),
                        render(v)
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{item} differs from the goldens:\n{}",
        bad.join("\n")
    );
}

#[tokio::test]
async fn envelope_matches_goldens() {
    compare_goldens("ENVELOPE", "envelope", &FIXTURES, false).await;
}

#[tokio::test]
async fn bodystructure_matches_goldens() {
    compare_goldens("BODYSTRUCTURE", "bodystructure", &FIXTURES, true).await;
}

#[tokio::test]
async fn body_matches_non_extensible_goldens() {
    compare_goldens("BODY", "body", &["01-plain", "03-mixed", "04-rfc822"], true).await;
}

#[tokio::test]
async fn flags_internaldate_size_and_uid() {
    let h = Harness::start().await;
    let mb = h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let d = c
        .cmd("F1", "FETCH 1:* (FLAGS INTERNALDATE RFC822.SIZE UID)")
        .await;
    d.assert_ok();
    let m = d.fetch_map();
    assert_eq!(m.len(), 11);
    for (i, name) in FIXTURES.iter().enumerate() {
        let seq = i as u32 + 1;
        let it = &m[&seq];
        assert_eq!(it.flags(), flags(&["\\Recent"]), "{name}: only \\Recent");
        let date = format_imap_datetime(fixture_received_ms(i) / 1000);
        assert_eq!(
            it.get("INTERNALDATE"),
            &Tok::Str(date.clone().into_bytes()),
            "{name}: INTERNALDATE \"{date}\""
        );
        let blob = h.blob(mb, seq);
        assert_eq!(
            blob.len(),
            fixture(name).len() + "Return-Path: <sender@example.test>\r\n".len()
        );
        assert_eq!(
            it.num("RFC822.SIZE"),
            blob.len() as u64,
            "{name}: RFC822.SIZE = stored length"
        );
        assert_eq!(it.num("UID"), u64::from(seq));
    }
}

#[tokio::test]
async fn uid_fetch_always_includes_uid() {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let d = c.cmd("U1", "UID FETCH 1:* FLAGS").await;
    d.assert_ok();
    let f = d.fetches();
    assert_eq!(f.len(), 11);
    for (seq, items) in f {
        assert_eq!(
            items.num("UID"),
            u64::from(seq),
            "UID FETCH responses carry UID"
        );
    }
}

#[tokio::test]
async fn macros_all_fast_full() {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let set = |l: &[&str]| {
        l.iter()
            .map(|s| s.to_string())
            .collect::<std::collections::BTreeSet<_>>()
    };
    for (mac, want) in [
        (
            "ALL",
            set(&["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"]),
        ),
        ("FAST", set(&["FLAGS", "INTERNALDATE", "RFC822.SIZE"])),
        (
            "FULL",
            set(&["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"]),
        ),
    ] {
        let d = c.cmd("M1", &format!("FETCH 3 {mac}")).await;
        d.assert_ok();
        let m = d.fetch_map();
        assert_eq!(m[&3].keys(), want, "FETCH {mac}");
    }
    // FULL's BODY is the non-extensible form.
    let d = c.cmd("M2", "FETCH 3 FULL").await;
    assert!(tok_eq(
        d.fetch_map()[&3].get("BODY"),
        &golden("03-mixed", "body"),
        true
    ));
}

#[tokio::test]
async fn whole_message_header_and_text_sections() {
    let h = Harness::start().await;
    let mb = h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let blob = h.blob(mb, 1);
    let (head, text) = split_message(&blob);
    for (item, key, want) in [
        ("BODY.PEEK[]", "BODY[]", &blob),
        ("BODY.PEEK[HEADER]", "BODY[HEADER]", &head),
        ("BODY.PEEK[TEXT]", "BODY[TEXT]", &text),
        ("BODY.PEEK[1]", "BODY[1]", &text),
        ("RFC822.HEADER", "RFC822.HEADER", &head),
    ] {
        let d = c.cmd("B1", &format!("FETCH 1 {item}")).await;
        d.assert_ok();
        let got = d.fetch_map()[&1].bytes(key);
        assert_eq!(show(&got), show(want), "FETCH 1 {item}");
    }
    assert_eq!(
        h.stored_flags(mb, 1),
        Flags::empty(),
        "PEEK and RFC822.HEADER leave \\Seen alone"
    );

    let d = c.cmd("B2", "FETCH 2 RFC822").await;
    assert_eq!(d.fetch_map()[&2].bytes("RFC822"), h.blob(mb, 2));
    let d = c.cmd("B3", "FETCH 3 RFC822.TEXT").await;
    assert_eq!(
        d.fetch_map()[&3].bytes("RFC822.TEXT"),
        split_message(&h.blob(mb, 3)).1
    );
}

#[tokio::test]
async fn header_fields_and_header_fields_not() {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let cases: [(u32, &str, &str, &[u8]); 5] = [
        (1, "HEADER.FIELDS (Subject From)", "HEADER.FIELDS (SUBJECT FROM)", b"From: Alice Example <alice@example.test>\r\nSubject: Plain hello\r\n\r\n"),
        (1, "HEADER.FIELDS (subject)", "HEADER.FIELDS (SUBJECT)", b"Subject: Plain hello\r\n\r\n"),
        (
            1,
            "HEADER.FIELDS.NOT (Return-Path To Reply-To Date Message-ID MIME-Version Content-Type Content-Transfer-Encoding)",
            "HEADER.FIELDS.NOT (RETURN-PATH TO REPLY-TO DATE MESSAGE-ID MIME-VERSION CONTENT-TYPE CONTENT-TRANSFER-ENCODING)",
            b"From: Alice Example <alice@example.test>\r\nSubject: Plain hello\r\n\r\n",
        ),
        (1, "HEADER.FIELDS (X-Nothing)", "HEADER.FIELDS (X-NOTHING)", b"\r\n"),
        (
            8,
            "HEADER.FIELDS (X-Long-Header)",
            "HEADER.FIELDS (X-LONG-HEADER)",
            b"X-Long-Header: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\r\n\r\n",
        ),
    ];
    for (seq, section, key, want) in cases {
        let d = c
            .cmd("H1", &format!("FETCH {seq} BODY.PEEK[{section}]"))
            .await;
        d.assert_ok();
        let got = d.fetch_map()[&seq].bytes(&format!("BODY[{key}]"));
        assert_eq!(show(&got), show(want), "BODY[{section}] of {seq}");
    }
}

#[tokio::test]
async fn mime_part_sections() {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let alt = fixture("02-alternative");
    let mixed = fixture("03-mixed");
    let fwd = fixture("04-rfc822");
    let nested = between(
        &fwd,
        b"Content-Type: message/rfc822\r\n\r\n",
        b"\r\n--outer--",
    )
    .to_vec();
    assert_eq!(
        nested.len(),
        376,
        "fixture and golden agree on the nested message size"
    );
    let (nested_head, nested_text) = split_message(&nested);
    let b64 = between(
        &mixed,
        b"Content-ID: <part2@example.test>\r\n\r\n",
        b"\r\n--mixed-b--",
    )
    .to_vec();
    assert_eq!(b64.len(), 108);

    let cases: Vec<(u32, &str, Vec<u8>)> = vec![
        (2, "1", b"Plain version.\r\n".to_vec()),
        (2, "2", b"<p>HTML version.</p>\r\n".to_vec()),
        (2, "1.MIME", b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n".to_vec()),
        (2, "TEXT", split_message(&alt).1),
        (3, "1", b"See the attachment.\r\n".to_vec()),
        (3, "2", b64),
        (
            3,
            "2.MIME",
            b"Content-Type: application/pdf; name=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\
              Content-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Description: Quarterly numbers\r\n\
              Content-ID: <part2@example.test>\r\n\r\n"
                .to_vec(),
        ),
        (4, "1", b"Forwarding this.\r\n".to_vec()),
        (4, "2", nested.clone()),
        (4, "2.HEADER", nested_head),
        (4, "2.TEXT", nested_text),
        (4, "2.1", b"Inner plain.\r\n".to_vec()),
        (4, "2.2", b"<b>Inner html.</b>\r\n".to_vec()),
        (4, "2.2.MIME", b"Content-Type: text/html; charset=us-ascii\r\n\r\n".to_vec()),
        (4, "2.HEADER.FIELDS (SUBJECT)", b"Subject: Original\r\n\r\n".to_vec()),
        (9, "1", split_message(&fixture("09-8bit")).1),
        (10, "TEXT", b"line one\nline two\n".to_vec()),
        (11, "TEXT", Vec::new()),
    ];
    let mut bad = Vec::new();
    for (seq, section, want) in cases {
        let d = c
            .cmd("P1", &format!("FETCH {seq} BODY.PEEK[{section}]"))
            .await;
        d.assert_ok();
        let got = d.fetch_map()[&seq].get(&format!("BODY[{section}]")).clone();
        if got.bytes() != Some(&want[..]) {
            bad.push(format!(
                "{seq} BODY[{section}]:\n  want {:?}\n  got  {}",
                show(&want),
                render(&got)
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[tokio::test]
async fn missing_part_is_empty_not_an_error() {
    let h = Harness::start().await;
    h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    for (seq, section) in [(1, "9"), (2, "3"), (4, "2.5"), (4, "3")] {
        let d = c
            .cmd("E1", &format!("FETCH {seq} BODY.PEEK[{section}]"))
            .await;
        d.assert_ok();
        let v = d.fetch_map()[&seq].get(&format!("BODY[{section}]")).clone();
        assert!(
            v.is_nil() || v == Tok::Str(Vec::new()),
            "BODY[{section}] of {seq}: NIL or \"\", got {}",
            render(&v)
        );
    }
}

#[tokio::test]
async fn partial_fetches() {
    let h = Harness::start().await;
    let mb = h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;
    let blob = h.blob(mb, 1);
    let text = split_message(&blob).1;
    let n = blob.len();
    let cases: Vec<(String, String, Vec<u8>)> = vec![
        (
            "BODY.PEEK[]<0.10>".into(),
            "BODY[]<0>".into(),
            blob[..10].to_vec(),
        ),
        (
            "BODY.PEEK[TEXT]<5.10>".into(),
            "BODY[TEXT]<5>".into(),
            text[5..15].to_vec(),
        ),
        (
            format!("BODY.PEEK[]<{}.100>", n - 5),
            format!("BODY[]<{}>", n - 5),
            blob[n - 5..].to_vec(),
        ),
        (
            "BODY.PEEK[]<100000.10>".into(),
            "BODY[]<100000>".into(),
            Vec::new(),
        ),
        (
            format!("BODY.PEEK[]<{n}.1>"),
            format!("BODY[]<{n}>"),
            Vec::new(),
        ),
        (
            "BODY.PEEK[HEADER]<0.4>".into(),
            "BODY[HEADER]<0>".into(),
            b"Retu".to_vec(),
        ),
    ];
    for (item, key, want) in cases {
        let d = c.cmd("R1", &format!("FETCH 1 {item}")).await;
        d.assert_ok();
        assert_eq!(
            show(&d.fetch_map()[&1].bytes(&key)),
            show(&want),
            "FETCH 1 {item}"
        );
    }
    let d = c.cmd("R2", "FETCH 2 BODY.PEEK[1]<0.4>").await;
    assert_eq!(d.fetch_map()[&2].bytes("BODY[1]<0>"), b"Plai");
    // Non-PEEK partial still sets \Seen.
    c.cmd("R3", "FETCH 2 BODY[1]<0.4>").await.assert_ok();
    assert!(h.stored_flags(mb, 2).contains(Flags::SEEN));
}

#[tokio::test]
async fn peek_leaves_seen_alone_and_body_sets_it() {
    let h = Harness::start().await;
    let mb = h.fixtures_account();
    let mut c = h.select(FIXTURE_LOGIN).await;

    let d = c.cmd("K1", "FETCH 5 (BODY.PEEK[] BODY.PEEK[TEXT] RFC822.HEADER RFC822.SIZE ENVELOPE BODYSTRUCTURE)").await;
    d.assert_ok();
    let m = d.fetch_map();
    if m[&5].has("FLAGS") {
        assert!(!m[&5].flags().contains("\\seen"));
    }
    assert_eq!(
        h.stored_flags(mb, 5),
        Flags::empty(),
        "no \\Seen from PEEK / RFC822.HEADER / metadata"
    );

    // Each of these sets \Seen and reports the new FLAGS in the same command's untagged FETCH data.
    for (seq, item) in [
        (6, "BODY[TEXT]"),
        (7, "RFC822"),
        (8, "RFC822.TEXT"),
        (9, "BODY[HEADER]"),
        (10, "BODY[1]"),
    ] {
        let d = c.cmd("K2", &format!("FETCH {seq} {item}")).await;
        d.assert_ok();
        let m = d.fetch_map();
        assert!(
            m[&seq].has("FLAGS") && m[&seq].flags().contains("\\seen"),
            "FETCH {seq} {item} reports \\Seen:\n{}",
            d.transcript()
        );
        assert!(
            h.stored_flags(mb, seq).contains(Flags::SEEN),
            "FETCH {seq} {item} stores \\Seen"
        );
    }
    // Already \Seen: no change, still fine.
    c.cmd("K3", "FETCH 6 BODY[TEXT]").await.assert_ok();
    assert_eq!(h.stored_flags(mb, 6), Flags::SEEN);
    // UID FETCH behaves the same.
    let d = c.cmd("K4", "UID FETCH 11 BODY[]").await;
    assert!(d.fetch_map()[&11].flags().contains("\\seen"));
}

#[tokio::test]
async fn sequence_sets() {
    let h = Harness::start().await;
    h.simple_account("seq@example.com", 6);
    let mut c = h.select("seq@example.com").await;
    let seqs = |d: &Done| {
        d.fetches()
            .into_iter()
            .map(|(s, _)| s)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    for (set, want) in [
        ("1:*", vec![1, 2, 3, 4, 5, 6]),
        ("*", vec![6]),
        ("5:2", vec![2, 3, 4, 5]),
        ("*:4", vec![4, 5, 6]),
        ("1,3,5:6", vec![1, 3, 5, 6]),
        ("2,2,2", vec![2]),
        ("6:*", vec![6]),
    ] {
        let d = c.cmd("Q1", &format!("FETCH {set} UID")).await;
        d.assert_ok();
        assert_eq!(seqs(&d), want, "FETCH {set}");
        for (s, items) in d.fetches() {
            assert_eq!(items.num("UID"), u64::from(s), "UID of {s}");
        }
    }
    for set in ["7", "0", "1:7", "0:2", "a"] {
        c.cmd("Q2", &format!("FETCH {set} UID")).await.assert_bad();
    }
    for (set, want) in [
        ("1:*", vec![1, 2, 3, 4, 5, 6]),
        ("100:*", vec![6]),
        ("3:4", vec![3, 4]),
        ("5:100", vec![5, 6]),
        ("100:200", vec![]),
        ("100", vec![]),
    ] {
        let d = c.cmd("Q3", &format!("UID FETCH {set} FLAGS")).await;
        d.assert_ok();
        assert_eq!(seqs(&d), want, "UID FETCH {set}");
    }
}

#[tokio::test]
async fn bad_fetch_syntax() {
    let h = Harness::start().await;
    h.simple_account("seq@example.com", 2);
    let mut c = h.select("seq@example.com").await;
    for cmd in [
        "FETCH 1 (FOO)",
        "FETCH 1",
        "FETCH 1 BODY[1.]",
        "FETCH 1 BODY[]<1.0",
        "FETCH 1 (FLAGS",
    ] {
        c.cmd("Y1", cmd).await.assert_bad();
    }
    c.cmd("Y2", "NOOP").await.assert_ok();
}

#[tokio::test]
async fn nul_bytes_are_replaced_on_output_with_a_consistent_size() {
    let h = Harness::start().await;
    h.account("nul@example.com");
    h.deliver(
        "nul@example.com",
        b"Subject: nul\r\n\r\nbefore\0after\r\n",
        ms("01-Mar-2026 10:00:00 +0000"),
    );
    let mut c = h.select("nul@example.com").await;
    let d = c.cmd("Z1", "FETCH 1 (RFC822.SIZE BODY.PEEK[])").await;
    d.assert_ok();
    let m = d.fetch_map();
    let body = m[&1].bytes("BODY[]");
    assert!(!body.contains(&0), "NUL must not reach the client");
    assert_eq!(
        body.len() as u64,
        m[&1].num("RFC822.SIZE"),
        "size and literal agree"
    );
}

#[tokio::test]
async fn message_of_25_mib() {
    let h = Harness::start().await;
    let mb = h.account("big@example.com");
    let mut msg = b"From: big@example.test\r\nSubject: 25 MiB\r\n\r\n".to_vec();
    let line = [b"A".repeat(76), b"\r\n".to_vec()].concat();
    while msg.len() + line.len() <= 25 * 1024 * 1024 - 64 {
        msg.extend_from_slice(&line);
    }
    h.deliver("big@example.com", &msg, ms("01-Mar-2026 10:00:00 +0000"));
    let blob = h.blob(mb, 1);
    let mut c = h.select("big@example.com").await;

    let d = c.cmd("H1", "FETCH 1 RFC822.SIZE").await;
    assert_eq!(d.fetch_map()[&1].num("RFC822.SIZE"), blob.len() as u64);

    let d = c.cmd("H2", "FETCH 1 BODY.PEEK[]").await;
    d.assert_ok();
    let got = d.fetch_map()[&1].bytes("BODY[]");
    assert_eq!(got.len(), blob.len());
    assert!(got == blob, "25 MiB body differs from the stored blob");

    let n = blob.len();
    let d = c
        .cmd("H3", &format!("FETCH 1 BODY.PEEK[]<{}.200>", n - 100))
        .await;
    assert_eq!(
        d.fetch_map()[&1].bytes(&format!("BODY[]<{}>", n - 100)),
        blob[n - 100..]
    );
    let d = c.cmd("H4", "FETCH 1 BODYSTRUCTURE").await;
    let bs = d.fetch_map()[&1].get("BODYSTRUCTURE").clone();
    let text_len = blob.len() - split_message(&blob).0.len();
    assert_eq!(
        bs.list()[6],
        Tok::Atom(text_len.to_string()),
        "BODYSTRUCTURE size of the 25 MiB text"
    );
}
