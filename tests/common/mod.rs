//! Shared helpers for the store integration tests (tempdir per test, never the real data dir).
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(unused_imports)]
pub use synology_mail_server::store::{
    AccountId, Delivery, DeliveryOutcome, FlagOp, Flags, MailboxId, Store, StoreError,
};
pub use tempfile::TempDir;

/// 2026-03-15 12:00:00.123 UTC: a fixed arrival time in a month that is not "now".
pub const MS: i64 = 1_773_576_000_123;
pub const FROM: &str = "sender@example.test";

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A fresh temp dir; the store lives in `<tmp>/data`, which does not exist yet.
pub fn setup() -> (TempDir, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(&data_dir(&tmp)).unwrap();
    (tmp, store)
}

pub fn data_dir(tmp: &TempDir) -> PathBuf {
    tmp.path().join("data")
}

pub fn reopen(tmp: &TempDir) -> Store {
    Store::open(&data_dir(tmp)).unwrap()
}

/// Creates an account (password "pw-<login>") with address `<login>`; returns it and its INBOX.
pub fn account(store: &Store, login: &str) -> (AccountId, MailboxId) {
    let id = store.create_account(login, &format!("pw-{login}")).unwrap();
    store.add_address(login, login).unwrap();
    (id, inbox(store, id))
}

pub fn inbox(store: &Store, id: AccountId) -> MailboxId {
    store.find_mailbox(id, "INBOX").unwrap().expect("INBOX exists").id
}

/// A hand-off key in the Worker's contract format, ordered by `n`.
pub fn key(n: i64) -> String {
    format!("msg:{:013}:00000000-0000-4000-8000-{:012}", MS + n, n)
}

pub fn delivery<'a>(key: &'a str, from: &'a str, to: &'a str, received_ms: i64, size: usize) -> Delivery<'a> {
    Delivery { key, envelope_from: from, envelope_to: to, received_ms, expected_size: size as u64 }
}

/// Delivers `body` for key(n) from FROM to `to` with the right expected size.
pub fn deliver(store: &Store, n: i64, to: &str, body: &[u8]) -> Result<DeliveryOutcome, StoreError> {
    let k = key(n);
    store.deliver(&delivery(&k, FROM, to, MS + n, body.len()), &mut &body[..])
}

pub fn uid_of(outcome: DeliveryOutcome) -> u32 {
    match outcome {
        DeliveryOutcome::Delivered { uid, .. } => uid,
        other => panic!("expected Delivered, got {other:?}"),
    }
}

pub fn read_message(store: &Store, mailbox: MailboxId, uid: u32) -> Vec<u8> {
    let mut v = Vec::new();
    store.open_message(mailbox, uid).unwrap().read_to_end(&mut v).unwrap();
    v
}

/// Every regular file under `dir`, recursively (empty if `dir` is missing).
pub fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_in(&p));
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// "<ms>-<16 lowercase hex>.eml"
pub fn is_blob_name(name: &str, ms: i64) -> bool {
    let Some(rest) = name.strip_prefix(&format!("{ms}-")) else { return false };
    let Some(hex) = rest.strip_suffix(".eml") else { return false };
    hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn raw_db(tmp: &TempDir) -> rusqlite::Connection {
    rusqlite::Connection::open(data_dir(tmp).join("ssm.db")).unwrap()
}

pub const BODY: &[u8] = b"From: a@example.test\r\nTo: test@example.com\r\nSubject: hi\r\n\r\nhello\r\n";
