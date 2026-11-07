//! Store: schema v2 (admin flag, auth stamp), the v1 upgrade and its backup, admin and disabled
//! accounts, the last-admin rule.

mod common;
use common::*;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use rusqlite::types::Value;
use synology_mail_server::store::{Account, check_login, check_password, normalize_address};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const PW: &str = "correct horse";
const LAST_ADMIN: &str = "At least one admin must remain";

const BLOB: &str = "blobs/1/202603/1773576000123-0123456789abcdef.eml";
const BACKUP: &str = "ssm.db.v1.bak";

/// The v1 schema exactly as the first release created it.
const V1_DDL: &str = "
CREATE TABLE accounts(
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INT,
    disabled INT DEFAULT 0
);
CREATE TABLE addresses(
    address TEXT PRIMARY KEY,
    account_id INT NOT NULL REFERENCES accounts
) WITHOUT ROWID;
CREATE TABLE mailboxes(
    id INTEGER PRIMARY KEY,
    account_id INT NOT NULL REFERENCES accounts,
    name TEXT NOT NULL,
    uidvalidity INT NOT NULL,
    uidnext INT NOT NULL DEFAULT 1,
    highest_modseq INT NOT NULL DEFAULT 1,
    recent_uid INT NOT NULL DEFAULT 0,
    subscribed INT NOT NULL DEFAULT 1,
    UNIQUE(account_id, name)
);
CREATE TABLE messages(
    mailbox_id INT NOT NULL REFERENCES mailboxes,
    uid INT NOT NULL,
    blob TEXT NOT NULL,
    size INT NOT NULL,
    internal_date INT NOT NULL,
    flags INT NOT NULL DEFAULT 0,
    modseq INT NOT NULL,
    PRIMARY KEY(mailbox_id, uid)
) WITHOUT ROWID;
CREATE TABLE handoff(
    key TEXT PRIMARY KEY,
    delivered_at INT NOT NULL,
    mailbox_id INT,
    uid INT
) WITHOUT ROWID;
";

const V1_ACCOUNT_COLS: [&str; 5] = ["created_at", "disabled", "id", "login", "password_hash"];
const V2_ACCOUNT_COLS: [&str; 7] = ["admin", "auth_stamp", "created_at", "disabled", "id", "login", "password_hash"];

/// Every v1 row, in a fixed order, for before/after comparisons.
const V1_ROWS: [&str; 5] = [
    "SELECT id, login, password_hash, created_at, disabled FROM accounts ORDER BY id",
    "SELECT address, account_id FROM addresses ORDER BY address",
    "SELECT id,account_id,name,uidvalidity,uidnext,highest_modseq,recent_uid,subscribed FROM mailboxes ORDER BY id",
    "SELECT mailbox_id,uid,blob,size,internal_date,flags,modseq FROM messages ORDER BY mailbox_id, uid",
    "SELECT * FROM handoff ORDER BY key",
];

/// A real argon2id PHC string for `password`, made by the store itself.
fn phc(password: &str) -> String {
    let (tmp, store) = setup();
    store.create_account("scratch@example.com", password).unwrap();
    drop(store);
    raw_db(&tmp).query_row("SELECT password_hash FROM accounts", [], |r| r.get(0)).unwrap()
}

/// A v1 data dir: alice with one message and her address, bob disabled with the catch-all, one
/// delivered and one quarantined hand-off.
fn v1_data_dir(tmp: &TempDir) {
    let d = data_dir(tmp);
    std::fs::create_dir_all(d.join("blobs/1/202603")).unwrap();
    std::fs::write(d.join(BLOB), BODY).unwrap();
    let hash = phc(PW);
    let c = Connection::open(d.join("ssm.db")).unwrap();
    let _: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap();
    c.execute_batch(V1_DDL).unwrap();
    c.execute(
        "INSERT INTO accounts(id, login, password_hash, created_at, disabled) VALUES (1, ?1, ?3, 1773576000, 0), (2, ?2, ?3, 1773576001, 1)",
        rusqlite::params![ALICE, BOB, hash],
    )
    .unwrap();
    c.execute("INSERT INTO addresses VALUES (?1, 1), ('@example.com', 2)", [ALICE]).unwrap();
    c.execute_batch(
        "INSERT INTO mailboxes VALUES (1, 1, 'INBOX', 1773576000, 2, 3, 1, 1), (2, 2, 'INBOX', 1773576001, 1, 1, 0, 0);",
    )
    .unwrap();
    c.execute(
        "INSERT INTO messages VALUES (1, 1, ?1, ?2, 1773576000, 1, 2)",
        rusqlite::params![BLOB, BODY.len() as i64],
    )
    .unwrap();
    c.execute_batch(
        "INSERT INTO handoff VALUES ('msg:1773576000123:00000000-0000-4000-8000-000000000001', 1773576000, 1, 1),
                                    ('msg:1773576000124:00000000-0000-4000-8000-000000000002', 1773576000, NULL, NULL);",
    )
    .unwrap();
    c.pragma_update(None, "user_version", 1).unwrap();
}

fn rows(c: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut st = c.prepare(sql).unwrap();
    let n = st.column_count();
    st.query_map([], |r| (0..n).map(|i| r.get::<_, Value>(i)).collect()).unwrap().map(|r| r.unwrap()).collect()
}

fn snapshot(c: &Connection) -> Vec<Vec<Vec<Value>>> {
    V1_ROWS.iter().map(|sql| rows(c, sql)).collect()
}

fn user_version(c: &Connection) -> i64 {
    c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
}

fn columns(c: &Connection, table: &str) -> Vec<String> {
    let mut st = c.prepare(&format!("PRAGMA table_info({table})")).unwrap();
    let mut got: Vec<String> = st.query_map([], |r| r.get::<_, String>(1)).unwrap().map(|x| x.unwrap()).collect();
    got.sort();
    got
}

/// (notnull, default) of a column, from PRAGMA table_info.
fn column_rule(c: &Connection, table: &str, col: &str) -> (bool, Option<String>) {
    let mut st = c.prepare(&format!("PRAGMA table_info({table})")).unwrap();
    st.query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, bool>(3)?, r.get::<_, Option<String>>(4)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .find(|(name, ..)| name == col)
        .map(|(_, nn, def)| (nn, def))
        .unwrap_or_else(|| panic!("{table}.{col} missing"))
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn get(store: &Store, id: AccountId) -> Account {
    store.account_by_id(id).unwrap().expect("account exists")
}

fn by_login(store: &Store, login: &str) -> Account {
    store.accounts().unwrap().into_iter().find(|a| a.login == login).expect("account listed")
}

fn assert_last_admin(r: Result<(), StoreError>, what: &str) {
    match r {
        Err(e @ StoreError::LastAdmin) => assert_eq!(e.to_string(), LAST_ADMIN),
        Err(e) => panic!("{what}: expected LastAdmin, got {e:?}"),
        Ok(()) => panic!("{what}: expected LastAdmin, got Ok"),
    }
}

// ---- schema v2 and the v1 upgrade -----------------------------------------------------------

#[test]
fn v1_db_upgrades_to_v2_no_admins_data_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    v1_data_dir(&tmp);
    let before = snapshot(&raw_db(&tmp));

    let store = Store::open(&data_dir(&tmp)).unwrap();
    let c = raw_db(&tmp);
    assert_eq!(user_version(&c), 6);
    assert_eq!(columns(&c, "accounts"), V2_ACCOUNT_COLS);
    assert_eq!(snapshot(&c), before, "accounts, addresses, mailboxes, messages and handoff rows unchanged");

    let accounts = store.accounts().unwrap();
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().all(|a| !a.admin), "the upgrade makes no one admin");
    assert!(!store.has_active_admin().unwrap());
    let (alice, bob) = (AccountId(1), AccountId(2));
    assert!(!get(&store, alice).disabled);
    assert!(get(&store, bob).disabled);

    assert_eq!(store.authenticate(ALICE, PW).unwrap(), Some(alice), "old password hashes still work");
    assert_eq!(store.authenticate(BOB, PW).unwrap(), None, "bob stays disabled");
    assert_eq!(store.route(ALICE).unwrap(), Some(alice));
    assert_eq!(store.route("anyone@example.com").unwrap(), Some(bob));
    assert_eq!(read_message(&store, MailboxId(1), 1), BODY);
    assert!(store.is_delivered("msg:1773576000124:00000000-0000-4000-8000-000000000002").unwrap());
}

#[test]
fn upgrade_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    v1_data_dir(&tmp);
    let store = Store::open(&data_dir(&tmp)).unwrap();
    store.set_admin(ALICE, true).unwrap();
    let stamp = by_login(&store, ALICE).auth_stamp;
    drop(store);
    let backup = std::fs::read(data_dir(&tmp).join(BACKUP)).unwrap();

    drop(reopen(&tmp));
    let store = reopen(&tmp);
    let c = raw_db(&tmp);
    assert_eq!(user_version(&c), 6);
    assert_eq!(columns(&c, "accounts"), V2_ACCOUNT_COLS);
    assert_eq!(store.accounts().unwrap().len(), 2);
    let alice = by_login(&store, ALICE);
    assert!(alice.admin, "a reopen must not run the upgrade again");
    assert_eq!(alice.auth_stamp, stamp);
    assert_eq!(std::fs::read(data_dir(&tmp).join(BACKUP)).unwrap(), backup, "the backup is written once");
}

#[test]
fn fresh_db_is_v2() {
    let (tmp, store) = setup();
    let c = raw_db(&tmp);
    assert_eq!(user_version(&c), 6);
    assert_eq!(columns(&c, "accounts"), V2_ACCOUNT_COLS);
    assert_eq!(column_rule(&c, "accounts", "admin"), (true, Some("0".into())));
    assert_eq!(column_rule(&c, "accounts", "auth_stamp"), (true, Some("0".into())));
    assert!(!data_dir(&tmp).join(BACKUP).exists(), "nothing to back up on a fresh install");
    let id = store.create_account(ALICE, PW).unwrap();
    assert!(!get(&store, id).admin);
    assert!(!store.has_active_admin().unwrap());
}

#[test]
fn upgrade_writes_v1_backup() {
    let tmp = tempfile::tempdir().unwrap();
    v1_data_dir(&tmp);
    let before = snapshot(&raw_db(&tmp));
    let _store = Store::open(&data_dir(&tmp)).unwrap();

    let path = data_dir(&tmp).join(BACKUP);
    assert!(path.is_file(), "{BACKUP} missing after the upgrade");
    assert_eq!(mode(&path), 0o600, "the backup holds password hashes");
    let bak = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(user_version(&bak), 1, "the backup is the database before the upgrade");
    assert_eq!(columns(&bak, "accounts"), V1_ACCOUNT_COLS);
    assert_eq!(snapshot(&bak), before);
    assert!(dated_backups(&tmp).is_empty(), "the first backup keeps the plain name {BACKUP}");
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// `ssm.db.v1.<unix-seconds>.bak` files in the data dir, with their seconds.
fn dated_backups(tmp: &TempDir) -> Vec<(i64, std::path::PathBuf)> {
    std::fs::read_dir(data_dir(tmp))
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            let name = e.file_name().into_string().ok()?;
            let secs = name.strip_prefix("ssm.db.v1.")?.strip_suffix(".bak")?;
            (!secs.is_empty() && secs.bytes().all(|b| b.is_ascii_digit())).then(|| (secs.parse().unwrap(), e.path()))
        })
        .collect()
}

#[test]
fn upgrade_with_backup_taken_writes_dated_backup() {
    let tmp = tempfile::tempdir().unwrap();
    v1_data_dir(&tmp);
    let before = snapshot(&raw_db(&tmp));
    let old = data_dir(&tmp).join(BACKUP);
    std::fs::write(&old, b"an older backup").unwrap();
    let start = unix_now();
    let store = Store::open_admin(&data_dir(&tmp)).unwrap();
    let end = unix_now();
    assert_eq!(std::fs::read(&old).unwrap(), b"an older backup", "an existing backup is never overwritten");
    assert_eq!(user_version(&raw_db(&tmp)), 6, "the upgrade still runs");
    assert_eq!(store.accounts().unwrap().len(), 2);

    let names: Vec<String> = std::fs::read_dir(data_dir(&tmp)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    let dated = dated_backups(&tmp);
    assert_eq!(dated.len(), 1, "every upgrade from v1 leaves a current backup: ssm.db.v1.<unix-seconds>.bak when {BACKUP} is taken, in {names:?}");
    let (secs, path) = &dated[0];
    assert!((start..=end).contains(secs), "named for the time of the upgrade: {secs} not in {start}..={end}");
    assert_eq!(mode(path), 0o600, "the backup holds password hashes");
    let bak = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(user_version(&bak), 1, "the backup is the database before the upgrade");
    assert_eq!(columns(&bak, "accounts"), V1_ACCOUNT_COLS);
    assert_eq!(snapshot(&bak), before);
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "no temp file left: {names:?}");
}

// ---- admin flag and the last-admin rule ------------------------------------------------------

#[test]
fn set_admin_on_off() {
    let (_tmp, store) = setup();
    let alice = store.create_account(ALICE, PW).unwrap();
    let bob = store.create_account(BOB, PW).unwrap();
    assert!(!get(&store, alice).admin, "new accounts are not admins");
    assert!(!store.has_active_admin().unwrap());

    store.set_admin(ALICE, true).unwrap();
    store.set_admin(ALICE, true).unwrap();
    assert!(get(&store, alice).admin);
    assert!(!get(&store, bob).admin);
    assert!(store.has_active_admin().unwrap());
    let admins: Vec<String> = store.accounts().unwrap().into_iter().filter(|a| a.admin).map(|a| a.login).collect();
    assert_eq!(admins, [ALICE]);

    store.set_admin(BOB, true).unwrap();
    store.set_admin(ALICE, false).unwrap();
    assert!(!get(&store, alice).admin);
    assert!(get(&store, bob).admin);

    let a = get(&store, alice);
    assert_eq!((a.id, a.login.as_str(), a.disabled), (alice, ALICE, false));
    assert!(store.account_by_id(AccountId(9999)).unwrap().is_none());
    assert!(matches!(store.set_admin("nobody@example.com", true), Err(StoreError::NotFound(_))));
    assert!(matches!(store.set_disabled("nobody@example.com", true), Err(StoreError::NotFound(_))));
}

#[test]
fn last_active_admin_cannot_be_demoted_or_disabled() {
    let (_tmp, store) = setup();
    let alice = store.create_account(ALICE, PW).unwrap();
    store.create_account(BOB, PW).unwrap();
    store.set_disabled(BOB, true).unwrap();
    store.set_disabled(BOB, false).unwrap();
    store.set_admin(ALICE, true).unwrap();

    assert_last_admin(store.set_admin(ALICE, false), "demote the only admin");
    assert_last_admin(store.set_disabled(ALICE, true), "disable the only admin");
    let a = get(&store, alice);
    assert!(a.admin && !a.disabled, "nothing changed");

    store.set_admin(BOB, false).unwrap();
    store.set_disabled(BOB, true).unwrap();
    store.set_disabled(ALICE, false).unwrap();
    assert!(store.has_active_admin().unwrap());
}

#[test]
fn disabled_admin_is_not_active() {
    let (tmp, store) = setup();
    store.create_account(ALICE, PW).unwrap();
    store.create_account(BOB, PW).unwrap();
    store.set_admin(ALICE, true).unwrap();
    store.set_admin(BOB, true).unwrap();
    store.set_disabled(BOB, true).unwrap();
    assert!(store.has_active_admin().unwrap());

    assert_last_admin(store.set_admin(ALICE, false), "bob is disabled, so alice is the last active admin");
    assert_last_admin(store.set_disabled(ALICE, true), "bob is disabled, so alice is the last active admin");
    store.set_admin(BOB, false).unwrap();

    store.set_admin(BOB, true).unwrap();
    store.set_disabled(BOB, false).unwrap();
    store.set_admin(ALICE, false).unwrap();
    assert!(by_login(&store, BOB).admin);

    raw_db(&tmp).execute("UPDATE accounts SET disabled = 1 WHERE login = ?", [BOB]).unwrap();
    assert!(!store.has_active_admin().unwrap(), "a disabled admin does not count");
}

#[test]
fn concurrent_demotions_keep_one_admin() {
    let (_tmp, store) = setup();
    store.create_account(ALICE, PW).unwrap();
    store.create_account(BOB, PW).unwrap();
    for round in 0..50 {
        store.set_admin(ALICE, true).unwrap();
        store.set_admin(BOB, true).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let results: Vec<bool> = std::thread::scope(|s| {
            let hs: Vec<_> = [ALICE, BOB]
                .into_iter()
                .map(|login| {
                    let (store, barrier) = (&store, &barrier);
                    s.spawn(move || {
                        barrier.wait();
                        store.set_admin(login, false).is_ok()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|ok| **ok).count(), 1, "round {round}: exactly one demotion may succeed");
        assert!(store.has_active_admin().unwrap(), "round {round}");
    }
}

// ---- disabled accounts -------------------------------------------------------------------------

#[test]
fn disabled_cannot_authenticate_but_mail_routes() {
    let (_tmp, store) = setup();
    let (id, inbox) = account(&store, ALICE);
    let pw = format!("pw-{ALICE}");
    store.set_disabled(ALICE, true).unwrap();
    assert!(get(&store, id).disabled);
    assert!(by_login(&store, ALICE).disabled);
    assert_eq!(store.authenticate(ALICE, &pw).unwrap(), None);
    assert_eq!(store.route(ALICE).unwrap(), Some(id), "mail to a disabled account still arrives");
    uid_of(deliver(&store, 1, ALICE, BODY).unwrap());
    assert_eq!(store.messages(inbox).unwrap().len(), 1);
}

#[test]
fn reenabled_authenticates() {
    let (_tmp, store) = setup();
    let (id, _) = account(&store, ALICE);
    let pw = format!("pw-{ALICE}");
    store.set_disabled(ALICE, true).unwrap();
    assert_eq!(store.authenticate(ALICE, &pw).unwrap(), None);
    store.set_disabled(ALICE, false).unwrap();
    store.set_disabled(ALICE, false).unwrap();
    assert!(!get(&store, id).disabled);
    assert_eq!(store.authenticate(ALICE, &pw).unwrap(), Some(id));
}

// ---- auth stamp and password hashing -----------------------------------------------------------

#[test]
fn set_password_changes_stamp() {
    let (_tmp, store) = setup();
    let alice = store.create_account(ALICE, "pw one").unwrap();
    let bob = store.create_account(BOB, "pw one").unwrap();
    let s0 = get(&store, alice).auth_stamp;
    let b0 = get(&store, bob).auth_stamp;
    assert_ne!(s0, 0, "a random stamp at create");
    assert_ne!(s0, b0, "a random stamp per account");

    store.set_password(ALICE, "pw two").unwrap();
    let s1 = get(&store, alice).auth_stamp;
    assert_ne!(s1, s0);
    store.set_password(ALICE, "pw two").unwrap();
    let s2 = get(&store, alice).auth_stamp;
    assert_ne!(s2, s1, "the same password again still ends old sessions");
    assert_eq!(get(&store, bob).auth_stamp, b0, "other accounts keep theirs");
}

/// Hashing (create, set_password) shares the two-at-once argon2 gate with verify: eight hashes
/// at once take at least four hash times.
#[test]
fn password_hashing_takes_the_verify_gate() {
    let (_tmp, store) = setup();
    store.create_account("warm@example.com", PW).unwrap();
    let one = (0..5)
        .map(|_| {
            let t = Instant::now();
            store.set_password("warm@example.com", PW).unwrap();
            t.elapsed()
        })
        .min()
        .unwrap();
    assert!(one > Duration::from_millis(1), "a real argon2 hash takes measurable time");

    fn eight(op: &(dyn Fn(usize) + Sync)) -> Duration {
        let t = Instant::now();
        std::thread::scope(|s| {
            for i in 0..8 {
                s.spawn(move || op(i));
            }
        });
        t.elapsed()
    }
    let create = eight(&|i| {
        store.create_account(&format!("user{i}@example.com"), PW).unwrap();
    });
    assert!(create * 2 >= one * 5, "8 creates took {create:?}, one hash {one:?}: create_account is not gated");
    let passwd = eight(&|i| store.set_password(&format!("user{i}@example.com"), "new pw").unwrap());
    assert!(passwd * 2 >= one * 5, "8 password changes took {passwd:?}, one hash {one:?}: set_password is not gated");
}

#[test]
fn login_password_and_address_checks_are_public() {
    assert!(check_login(ALICE).is_ok());
    assert!(matches!(check_login("a b"), Err(StoreError::InvalidInput(_))));
    assert!(matches!(check_login(""), Err(StoreError::InvalidInput(_))));
    assert!(check_password(PW).is_ok());
    assert!(matches!(check_password("a\nb"), Err(StoreError::InvalidInput(_))));
    assert_eq!(normalize_address("Alice@EXAMPLE.com").unwrap(), ALICE);
    assert_eq!(normalize_address("@Example.com").unwrap(), "@example.com");
    assert!(matches!(normalize_address("a+b@example.com"), Err(StoreError::InvalidInput(_))));
}
