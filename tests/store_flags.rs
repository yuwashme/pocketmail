//! Store: flags with modseq, and the \Recent claim (tests D).

mod common;
use common::*;
use std::sync::Arc;
use synology_mail_server::store::{FlagUpdate, RecentClaim};

fn with_messages(n: i64) -> (TempDir, Store, MailboxId) {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    for i in 1..=n {
        deliver(&store, i, "test@example.com", BODY).unwrap();
    }
    (tmp, store, mb)
}

fn flags_of(store: &Store, mb: MailboxId) -> Vec<u8> {
    store
        .messages(mb)
        .unwrap()
        .iter()
        .map(|m| m.flags.bits())
        .collect()
}

#[test]
fn flag_bits_match_the_schema() {
    assert_eq!(Flags::SEEN.bits(), 1);
    assert_eq!(Flags::ANSWERED.bits(), 2);
    assert_eq!(Flags::FLAGGED.bits(), 4);
    assert_eq!(Flags::DELETED.bits(), 8);
    assert_eq!(Flags::DRAFT.bits(), 16);
    assert_eq!((Flags::SEEN | Flags::FLAGGED).bits(), 5);
    assert!((Flags::SEEN | Flags::FLAGGED).contains(Flags::FLAGGED));
    assert!(!Flags::SEEN.contains(Flags::FLAGGED));
    assert_eq!(Flags::empty().bits(), 0);
}

#[test]
fn add_remove_replace_bump_modseq() {
    let (tmp, store, mb) = with_messages(1);
    let m0 = store.mailbox(mb).unwrap().highest_modseq;

    let r = store
        .store_flags(mb, &[1], FlagOp::Add, Flags::SEEN | Flags::FLAGGED)
        .unwrap();
    assert_eq!(
        r,
        vec![FlagUpdate {
            uid: 1,
            flags: Flags::SEEN | Flags::FLAGGED,
            modseq: m0 + 1
        }]
    );
    assert_eq!(store.mailbox(mb).unwrap().highest_modseq, m0 + 1);
    let raw: i64 = raw_db(&tmp)
        .query_row("SELECT flags FROM messages WHERE uid = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(raw, 5, "on-disk bits: Seen 1 | Flagged 4");

    let r = store
        .store_flags(mb, &[1], FlagOp::Remove, Flags::SEEN)
        .unwrap();
    assert_eq!(
        r,
        vec![FlagUpdate {
            uid: 1,
            flags: Flags::FLAGGED,
            modseq: m0 + 2
        }]
    );

    let r = store
        .store_flags(mb, &[1], FlagOp::Replace, Flags::ANSWERED | Flags::DRAFT)
        .unwrap();
    assert_eq!(
        r,
        vec![FlagUpdate {
            uid: 1,
            flags: Flags::ANSWERED | Flags::DRAFT,
            modseq: m0 + 3
        }]
    );

    let m = &store.messages(mb).unwrap()[0];
    assert_eq!(m.flags.bits(), 18);
    assert_eq!(m.modseq, m0 + 3);
    assert_eq!(store.mailbox(mb).unwrap().highest_modseq, m0 + 3);
}

#[test]
fn a_store_that_changes_nothing_keeps_modseq() {
    let (_tmp, store, mb) = with_messages(1);
    store
        .store_flags(mb, &[1], FlagOp::Add, Flags::FLAGGED)
        .unwrap();
    let before = store.mailbox(mb).unwrap().highest_modseq;
    let r = store
        .store_flags(mb, &[1], FlagOp::Add, Flags::FLAGGED)
        .unwrap();
    assert_eq!(
        r,
        vec![FlagUpdate {
            uid: 1,
            flags: Flags::FLAGGED,
            modseq: before
        }],
        "unchanged message keeps its modseq"
    );
    let r = store
        .store_flags(mb, &[1], FlagOp::Remove, Flags::SEEN)
        .unwrap();
    assert_eq!(r[0].modseq, before);
    assert_eq!(store.mailbox(mb).unwrap().highest_modseq, before);
}

#[test]
fn multi_uid_store_skips_unknown_uids_and_keeps_highest_modseq_consistent() {
    let (_tmp, store, mb) = with_messages(3);
    let before = store.mailbox(mb).unwrap().highest_modseq;
    let r = store
        .store_flags(mb, &[3, 1, 99], FlagOp::Add, Flags::SEEN)
        .unwrap();
    assert_eq!(
        r.iter().map(|u| u.uid).collect::<Vec<_>>(),
        vec![1, 3],
        "uid order, unknown uid 99 skipped"
    );
    assert!(
        r.iter()
            .all(|u| u.modseq > before && u.flags == Flags::SEEN)
    );
    assert_eq!(flags_of(&store, mb), vec![1, 0, 1]);
    let highest = store.mailbox(mb).unwrap().highest_modseq;
    let msgs = store.messages(mb).unwrap();
    assert_eq!(highest, msgs.iter().map(|m| m.modseq).max().unwrap());
    assert!(msgs.iter().all(|m| m.modseq <= highest));
    assert!(
        store
            .store_flags(mb, &[], FlagOp::Add, Flags::SEEN)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn flags_only_touch_the_given_mailbox() {
    let (_tmp, store) = setup();
    let (_, a) = account(&store, "alice@example.com");
    let (_, b) = account(&store, "bob@example.com");
    deliver(&store, 1, "alice@example.com", BODY).unwrap();
    deliver(&store, 2, "bob@example.com", BODY).unwrap();
    let b_modseq = store.mailbox(b).unwrap().highest_modseq;
    store
        .store_flags(a, &[1], FlagOp::Add, Flags::SEEN)
        .unwrap();
    assert_eq!(flags_of(&store, b), vec![0]);
    assert_eq!(store.mailbox(b).unwrap().highest_modseq, b_modseq);
}

#[test]
fn flags_survive_reopen() {
    let (tmp, store, mb) = with_messages(1);
    store
        .store_flags(mb, &[1], FlagOp::Add, Flags::ANSWERED)
        .unwrap();
    drop(store);
    let store = reopen(&tmp);
    assert_eq!(flags_of(&store, mb), vec![2]);
}

#[test]
fn claim_recent_hands_each_new_uid_to_one_session() {
    let (_tmp, store, mb) = with_messages(2);
    assert_eq!(
        store.claim_recent(mb).unwrap(),
        RecentClaim { floor: 0, upto: 2 }
    );
    assert_eq!(store.mailbox(mb).unwrap().recent_uid, 2);
    assert_eq!(
        store.claim_recent(mb).unwrap(),
        RecentClaim { floor: 2, upto: 2 },
        "nothing new"
    );
    deliver(&store, 3, "test@example.com", BODY).unwrap();
    assert_eq!(
        store.claim_recent(mb).unwrap(),
        RecentClaim { floor: 2, upto: 3 }
    );
}

#[test]
fn claim_recent_on_an_empty_mailbox() {
    let (_tmp, store, mb) = with_messages(0);
    assert_eq!(
        store.claim_recent(mb).unwrap(),
        RecentClaim { floor: 0, upto: 0 }
    );
}

#[test]
fn concurrent_claims_never_share_a_recent_uid() {
    let (_tmp, store, mb) = with_messages(3);
    let store = Arc::new(store);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || s.claim_recent(mb).unwrap())
        })
        .collect();
    let mut claims: Vec<RecentClaim> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    claims.sort_by_key(|c| (c.floor, c.upto));
    let winners: Vec<_> = claims.iter().filter(|c| c.upto > c.floor).collect();
    assert_eq!(
        winners,
        vec![&RecentClaim { floor: 0, upto: 3 }],
        "exactly one session sees uids 1..=3 as \\Recent: {claims:?}"
    );
    assert!(claims.iter().all(|c| c.upto == 3));
}

#[test]
fn claim_recent_survives_reopen() {
    let (tmp, store, mb) = with_messages(2);
    store.claim_recent(mb).unwrap();
    drop(store);
    let store = reopen(&tmp);
    assert_eq!(
        store.claim_recent(mb).unwrap(),
        RecentClaim { floor: 2, upto: 2 }
    );
}
