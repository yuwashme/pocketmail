//! Store: data dir layout, schema v2, PRAGMAs, migrations .

mod common;
use common::*;

#[test]
fn store_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
}

#[test]
fn open_creates_the_data_dir_layout() {
    let (tmp, _store) = setup();
    let d = data_dir(&tmp);
    for sub in ["blobs", "tmp", "unrouted"] {
        assert!(d.join(sub).is_dir(), "{sub}/ missing");
    }
    assert!(d.join("ssm.db").is_file());
}

#[test]
fn schema_v2_tables_columns_and_user_version() {
    let (tmp, _store) = setup();
    let c = raw_db(&tmp);
    let uv: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(uv, 6);
    let jm: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(jm, "wal");
    let expect: &[(&str, &[&str])] = &[
        (
            "accounts",
            &[
                "admin",
                "auth_stamp",
                "created_at",
                "disabled",
                "id",
                "login",
                "password_hash",
            ],
        ),
        ("addresses", &["account_id", "address"]),
        (
            "mailboxes",
            &[
                "account_id",
                "forward_to",
                "highest_modseq",
                "id",
                "keep_copy",
                "name",
                "quota_bytes",
                "recent_uid",
                "subscribed",
                "uidnext",
                "uidvalidity",
                "used_bytes",
            ],
        ),
        (
            "messages",
            &[
                "blob",
                "flags",
                "internal_date",
                "mailbox_id",
                "modseq",
                "sender",
                "size",
                "subject",
                "uid",
            ],
        ),
        ("handoff", &["delivered_at", "key", "mailbox_id", "uid"]),
    ];
    for (table, cols) in expect {
        let mut st = c.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        let mut got: Vec<String> = st
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        got.sort();
        assert_eq!(
            got,
            cols.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "columns of {table}"
        );
    }
}

#[test]
fn pragmas_on_every_connection_writer_and_two_readers() {
    let (_tmp, store) = setup();
    for (name, want) in [
        ("journal_mode", "wal"),
        ("synchronous", "2"), // FULL
        ("foreign_keys", "1"),
        ("busy_timeout", "5000"),
        ("cache_size", "-512"),
        ("mmap_size", "0"),
    ] {
        let got = store.pragma(name).unwrap();
        assert_eq!(got.len(), 3, "1 writer + 2 readers for PRAGMA {name}");
        assert!(
            got.iter().all(|v| v == want),
            "PRAGMA {name}: got {got:?}, want {want}"
        );
    }
}

#[test]
fn reopen_is_idempotent_and_keeps_data() {
    let (tmp, store) = setup();
    let (id, mb) = account(&store, "test@example.com");
    uid_of(deliver(&store, 1, "test@example.com", BODY).unwrap());
    drop(store);
    let store = reopen(&tmp);
    drop(store);
    let store = reopen(&tmp);
    assert_eq!(store.account_id("test@example.com").unwrap(), Some(id));
    assert_eq!(store.messages(mb).unwrap().len(), 1);
    let uv: i64 = raw_db(&tmp)
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(uv, 6);
}

#[test]
fn refuses_a_database_from_a_newer_schema() {
    let (tmp, store) = setup();
    drop(store);
    raw_db(&tmp).pragma_update(None, "user_version", 7).unwrap();
    match Store::open(&data_dir(&tmp)) {
        Err(StoreError::SchemaTooNew { found }) => assert_eq!(found, 7),
        Err(e) => panic!("expected SchemaTooNew, got {e:?}"),
        Ok(_) => panic!("opened a database with user_version 3"),
    }
}

#[test]
fn tmp_is_emptied_at_startup_and_blobs_are_left_alone() {
    let (tmp, store) = setup();
    drop(store);
    let d = data_dir(&tmp);
    std::fs::write(d.join("tmp").join("partial.eml"), b"half a message").unwrap();
    std::fs::create_dir_all(d.join("blobs").join("9").join("202603")).unwrap();
    let keep = d
        .join("blobs")
        .join("9")
        .join("202603")
        .join("1773576000123-0123456789abcdef.eml");
    std::fs::write(&keep, b"x").unwrap();
    let _store = reopen(&tmp);
    assert!(
        files_in(&d.join("tmp")).is_empty(),
        "tmp/ must be emptied at startup"
    );
    assert!(keep.is_file(), "blobs/ must never be touched at startup");
}
