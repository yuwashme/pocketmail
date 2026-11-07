//! Store behaviour beyond the basic API:
//! '+' rejected on registration, quarantine keeps the envelope, exclusive data-dir lock,
//! 0600 files / 0700 dirs, admin open leaves tmp/ alone.

mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn plus_in_the_local_part_is_refused_on_registration() {
    let (_tmp, store) = setup();
    store.create_account("alice", "pw").unwrap();
    assert!(matches!(
        store.add_address("a+b@example.com", "alice"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.add_address("+@example.com", "alice"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.add_address("a@b@example.com", "alice"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.add_address("a@", "alice"),
        Err(StoreError::InvalidInput(_))
    ));
    store.add_address("a@example.com", "alice").unwrap();
}

#[test]
fn quarantine_keeps_the_decoded_envelope_as_headers() {
    let (_tmp, store) = setup();
    account(&store, "test@example.com");
    let k = key(1);
    let out = store
        .deliver(
            &delivery(
                &k,
                "šef@primer.si",
                "nobody+x@other.test\r\nX-Evil: 1",
                MS,
                BODY.len(),
            ),
            &mut &BODY[..],
        )
        .unwrap();
    let DeliveryOutcome::Quarantined { path } = out else {
        panic!("expected Quarantined, got {out:?}")
    };
    let mut want =
        "X-SSM-Envelope-To: nobody+x@other.testX-Evil: 1\r\nX-SSM-Envelope-From: šef@primer.si\r\n"
            .as_bytes()
            .to_vec();
    want.extend_from_slice(BODY);
    assert_eq!(std::fs::read(path).unwrap(), want);
}

#[test]
fn a_second_daemon_open_of_the_same_dir_is_locked_out() {
    let (tmp, store) = setup();
    assert!(matches!(
        Store::open(&data_dir(&tmp)),
        Err(StoreError::Locked(_))
    ));
    drop(store);
    let _again = reopen(&tmp);
}

#[test]
fn admin_open_works_beside_the_daemon_and_leaves_tmp_alone() {
    let (tmp, store) = setup();
    let in_flight = data_dir(&tmp).join("tmp").join("in-flight.eml");
    std::fs::write(&in_flight, b"partial").unwrap();
    let admin = Store::open_admin(&data_dir(&tmp)).unwrap();
    admin.create_account("alice", "pw").unwrap();
    assert!(in_flight.is_file(), "admin open must not empty tmp/");
    assert!(
        store.account_id("alice").unwrap().is_some(),
        "daemon sees the admin's write"
    );
}

#[test]
fn files_are_0600_and_directories_0700() {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    deliver(&store, 1, "test@example.com", BODY).unwrap();
    deliver(&store, 2, "stranger@other.test", BODY).unwrap();
    let d = data_dir(&tmp);
    assert_eq!(mode(&d), 0o700);
    for sub in ["blobs", "tmp", "unrouted"] {
        assert_eq!(mode(&d.join(sub)), 0o700, "{sub}/");
    }
    let blob = d.join(&store.messages(mb).unwrap()[0].blob);
    assert_eq!(mode(blob.parent().unwrap()), 0o700, "month dir");
    assert_eq!(
        mode(blob.parent().unwrap().parent().unwrap()),
        0o700,
        "account dir"
    );
    assert_eq!(mode(&blob), 0o600);
    for f in files_in(&d.join("unrouted")) {
        assert_eq!(mode(&f), 0o600);
    }
    for f in ["ssm.db", "ssm.db-wal", ".lock"] {
        assert_eq!(mode(&d.join(f)), 0o600, "{f}");
    }
}
