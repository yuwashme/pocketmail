//! Store: delivery, UIDs, uidvalidity, Return-Path, size check, dedupe, quarantine (tests D).

mod common;
use common::*;
use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn first_delivery_gets_uid_1_and_bumps_uidnext_and_modseq() {
    let (_tmp, store) = setup();
    let (id, mb) = account(&store, "test@example.com");
    let out = deliver(&store, 1, "test@example.com", BODY).unwrap();
    assert_eq!(out, DeliveryOutcome::Delivered { account: id, mailbox: mb, uid: 1 });
    let info = store.mailbox(mb).unwrap();
    assert_eq!(info.uidnext, 2);
    assert_eq!(info.highest_modseq, 2);
    let msgs = store.messages(mb).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].uid, 1);
    assert_eq!(msgs[0].modseq, info.highest_modseq, "new message modseq = new highest_modseq");
    assert_eq!(msgs[0].flags, Flags::empty());
    assert!(store.is_delivered(&key(1)).unwrap());
}

#[test]
fn uids_are_monotonic_and_survive_reopen() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let uids: Vec<u32> = (1..=3).map(|n| uid_of(deliver(&store, n, "test@example.com", BODY).unwrap())).collect();
    assert_eq!(uids, vec![1, 2, 3]);
    // A failed delivery in between must not lead to a reused or lower UID.
    let k = key(4);
    assert!(store.deliver(&delivery(&k, FROM, "test@example.com", MS + 4, BODY.len() + 1), &mut &BODY[..]).is_err());
    drop(store);
    let store = reopen(&tmp);
    let next = uid_of(deliver(&store, 5, "test@example.com", BODY).unwrap());
    assert!(next > 3, "uid after reopen {next} must be above 3");
    let all: Vec<u32> = store.messages(mb).unwrap().iter().map(|m| m.uid).collect();
    assert_eq!(all, vec![1, 2, 3, next]);
    assert_eq!(store.mailbox(mb).unwrap().uidnext, next + 1);
}

#[test]
fn uidvalidity_is_stable_across_deliveries_and_reopen() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let v = store.mailbox(mb).unwrap().uidvalidity;
    deliver(&store, 1, "test@example.com", BODY).unwrap();
    assert_eq!(store.mailbox(mb).unwrap().uidvalidity, v);
    drop(store);
    let store = reopen(&tmp);
    deliver(&store, 2, "test@example.com", BODY).unwrap();
    assert_eq!(store.mailbox(mb).unwrap().uidvalidity, v);
}

#[test]
fn each_account_has_its_own_uid_sequence() {
    let (_tmp, store) = setup();
    let (_, a) = account(&store, "alice@example.com");
    let (_, b) = account(&store, "bob@example.com");
    assert_eq!(uid_of(deliver(&store, 1, "alice@example.com", BODY).unwrap()), 1);
    assert_eq!(uid_of(deliver(&store, 2, "bob@example.com", BODY).unwrap()), 1);
    assert_eq!(uid_of(deliver(&store, 3, "alice@example.com", BODY).unwrap()), 2);
    assert_eq!(store.messages(a).unwrap().len(), 2);
    assert_eq!(store.messages(b).unwrap().len(), 1);
}

#[test]
fn routing_cases_reach_the_right_inbox() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    store.add_address("šef@example.com", "test@example.com").unwrap();
    for (n, rcpt) in [(1, "test+news@example.com"), (2, "TEST@EXAMPLE.COM"), (3, "Šef@example.com")].into_iter() {
        assert!(matches!(deliver(&store, n, rcpt, BODY).unwrap(), DeliveryOutcome::Delivered { mailbox, .. } if mailbox == mb), "{rcpt}");
    }
    assert_eq!(store.messages(mb).unwrap().len(), 3);
}

#[test]
fn blob_layout_internal_date_and_size() {
    let (tmp, store) = setup();
    let (id, mb) = account(&store, "test@example.com");
    deliver(&store, 0, "test@example.com", BODY).unwrap();
    let m = &store.messages(mb).unwrap()[0];
    // blobs/<account_id>/<yyyymm of received_ms, UTC>/<received_ms>-<16hex>.eml
    let parts: Vec<&str> = m.blob.split('/').collect();
    assert_eq!(parts.len(), 4, "blob path {}", m.blob);
    assert_eq!(parts[0], "blobs");
    assert_eq!(parts[1], id.0.to_string());
    assert_eq!(parts[2], "202603");
    assert!(is_blob_name(parts[3], MS), "blob name {}", parts[3]);
    let path = data_dir(&tmp).join(&m.blob);
    assert!(path.is_file());
    assert_eq!(m.internal_date, MS / 1000, "INTERNALDATE comes from the key's ms");
    assert_eq!(m.size, std::fs::metadata(&path).unwrap().len(), "RFC822.SIZE = file length");
    assert_eq!(read_message(&store, mb, 1), std::fs::read(&path).unwrap());
    assert!(files_in(&data_dir(&tmp).join("tmp")).is_empty());
}

#[test]
fn return_path_is_prepended_byte_exact() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    deliver(&store, 1, "test@example.com", BODY).unwrap();
    let mut want = b"Return-Path: <sender@example.test>\r\n".to_vec();
    want.extend_from_slice(BODY);
    assert_eq!(read_message(&store, mb, 1), want);
    assert_eq!(store.messages(mb).unwrap()[0].size, want.len() as u64);
}

#[test]
fn null_sender_gets_an_empty_return_path() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    store.deliver(&delivery(&k, "", "test@example.com", MS, BODY.len()), &mut &BODY[..]).unwrap();
    let mut want = b"Return-Path: <>\r\n".to_vec();
    want.extend_from_slice(BODY);
    assert_eq!(read_message(&store, mb, 1), want);
}

#[test]
fn utf8_envelope_sender_is_kept_in_return_path() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    store.deliver(&delivery(&k, "šef@primer.si", "test@example.com", MS, BODY.len()), &mut &BODY[..]).unwrap();
    let mut want = "Return-Path: <šef@primer.si>\r\n".as_bytes().to_vec();
    want.extend_from_slice(BODY);
    assert_eq!(read_message(&store, mb, 1), want);
}

#[test]
fn existing_return_path_is_not_duplicated() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let bodies: [&[u8]; 2] = [
        b"Return-Path: <orig@example.test>\r\nSubject: a\r\n\r\nx\r\n",
        b"return-path:<orig@example.test>\r\nSubject: b\r\n\r\ny\r\n",
    ];
    for (n, body) in bodies.iter().enumerate() {
        deliver(&store, n as i64, "test@example.com", body).unwrap();
        assert_eq!(read_message(&store, mb, n as u32 + 1), body.to_vec());
    }
}

#[test]
fn crlf_in_envelope_sender_never_injects_a_header() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    let evil = "a@b.test>\r\nX-Injected: yes\r\nX-More: <c";
    store.deliver(&delivery(&k, evil, "test@example.com", MS, BODY.len()), &mut &BODY[..]).unwrap();
    let got = read_message(&store, mb, 1);
    assert!(got.ends_with(BODY), "body stays byte-exact");
    let prefix = &got[..got.len() - BODY.len()];
    let lf = prefix.iter().filter(|&&b| b == b'\n').count();
    let cr = prefix.iter().filter(|&&b| b == b'\r').count();
    assert!(prefix.is_empty() || (prefix.ends_with(b"\r\n") && lf == 1 && cr == 1), "prefix must be at most one line: {:?}", String::from_utf8_lossy(prefix));
}

#[test]
fn bare_lf_and_8bit_bodies_are_stored_verbatim() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let body: Vec<u8> = [b"Subject: lf\n\nline one\n".as_slice(), "šđčćž ".as_bytes(), b"\xff\x00 end\n"].concat();
    deliver(&store, 1, "test@example.com", &body).unwrap();
    assert!(read_message(&store, mb, 1).ends_with(&body));
}

#[test]
fn size_mismatch_leaves_nothing_behind() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    let r = store.deliver(&delivery(&k, FROM, "test@example.com", MS, BODY.len() + 1), &mut &BODY[..]);
    match r {
        Err(StoreError::SizeMismatch { expected, actual }) => {
            assert_eq!(expected, BODY.len() as u64 + 1);
            assert_eq!(actual, BODY.len() as u64, "size is the body as read, Return-Path excluded");
        }
        other => panic!("expected SizeMismatch, got {other:?}"),
    }
    let d = data_dir(&tmp);
    assert!(files_in(&d.join("tmp")).is_empty(), "no tmp file kept");
    assert!(files_in(&d.join("blobs")).is_empty(), "no blob written");
    assert!(!store.is_delivered(&k).unwrap());
    assert_eq!(store.mailbox(mb).unwrap().uidnext, 1);
    assert!(store.messages(mb).unwrap().is_empty());
}

struct BrokenReader(usize);
impl Read for BrokenReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "pull connection dropped"));
        }
        let n = self.0.min(buf.len()).min(5);
        buf[..n].fill(b'x');
        self.0 -= n;
        Ok(n)
    }
}

#[test]
fn body_read_error_leaves_nothing_behind() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    assert!(store.deliver(&delivery(&k, FROM, "test@example.com", MS, 100), &mut BrokenReader(20)).is_err());
    let d = data_dir(&tmp);
    assert!(files_in(&d.join("tmp")).is_empty());
    assert!(files_in(&d.join("blobs")).is_empty());
    assert!(!store.is_delivered(&k).unwrap());
    assert_eq!(store.mailbox(mb).unwrap().uidnext, 1);
}

#[test]
fn same_handoff_key_is_delivered_once() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let k = key(1);
    let d = delivery(&k, FROM, "test@example.com", MS, BODY.len());
    assert!(matches!(store.deliver(&d, &mut &BODY[..]).unwrap(), DeliveryOutcome::Delivered { uid: 1, .. }));
    assert_eq!(store.deliver(&d, &mut &BODY[..]).unwrap(), DeliveryOutcome::AlreadyDelivered);
    drop(store);
    let store = reopen(&tmp);
    assert_eq!(store.deliver(&d, &mut &BODY[..]).unwrap(), DeliveryOutcome::AlreadyDelivered);
    assert_eq!(store.messages(mb).unwrap().len(), 1);
    assert_eq!(store.mailbox(mb).unwrap().uidnext, 2);
    assert_eq!(files_in(&data_dir(&tmp).join("blobs")).len(), 1);
}

#[test]
fn unknown_recipient_is_quarantined_recorded_and_not_redelivered() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let path = match deliver(&store, 0, "stranger@other.test", BODY).unwrap() {
        DeliveryOutcome::Quarantined { path } => path,
        other => panic!("expected Quarantined, got {other:?}"),
    };
    let unrouted = data_dir(&tmp).join("unrouted");
    assert_eq!(path.parent().unwrap().canonicalize().unwrap(), unrouted.canonicalize().unwrap());
    assert!(is_blob_name(path.file_name().unwrap().to_str().unwrap(), MS), "{path:?}");
    assert!(std::fs::read(&path).unwrap().ends_with(BODY));
    assert!(store.is_delivered(&key(0)).unwrap(), "quarantine is recorded in handoff (then acked)");
    assert_eq!(deliver(&store, 0, "stranger@other.test", BODY).unwrap(), DeliveryOutcome::AlreadyDelivered);
    assert_eq!(files_in(&unrouted).len(), 1);
    assert_eq!(store.mailbox(mb).unwrap().uidnext, 1, "no mailbox touched");
    assert!(files_in(&data_dir(&tmp).join("blobs")).is_empty());
    let nulls: i64 = raw_db(&tmp)
        .query_row("SELECT COUNT(*) FROM handoff WHERE mailbox_id IS NULL AND uid IS NULL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(nulls, 1);
}

#[test]
fn prune_handoff_drops_only_old_rows() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    deliver(&store, 1, "test@example.com", BODY).unwrap();
    assert_eq!(store.prune_handoff(now() - 40 * 86_400).unwrap(), 0);
    assert!(store.is_delivered(&key(1)).unwrap());
    assert_eq!(store.prune_handoff(now() + 10).unwrap(), 1);
    assert!(!store.is_delivered(&key(1)).unwrap());
    assert_eq!(store.messages(mb).unwrap().len(), 1, "pruning never touches mail");
}

#[test]
fn open_message_of_unknown_uid_is_not_found() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    assert!(matches!(store.open_message(mb, 1), Err(StoreError::NotFound(_))));
}

#[test]
fn a_reader_never_sees_a_row_without_its_blob() {
    let (_tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    let store = Arc::new(store);
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let (store, done) = (store.clone(), done.clone());
        std::thread::spawn(move || {
            let mut checks = 0usize;
            while !done.load(Ordering::SeqCst) {
                for m in store.messages(mb).unwrap() {
                    let f = store.open_message(mb, m.uid).unwrap_or_else(|e| panic!("uid {} listed without blob: {e:?}", m.uid));
                    assert_eq!(f.metadata().unwrap().len(), m.size);
                    checks += 1;
                }
            }
            checks
        })
    };
    for n in 0..40 {
        deliver(&store, n, "test@example.com", BODY).unwrap();
    }
    done.store(true, Ordering::SeqCst);
    reader.join().expect("reader saw a row without a blob");
    assert_eq!(store.messages(mb).unwrap().len(), 40);
}
