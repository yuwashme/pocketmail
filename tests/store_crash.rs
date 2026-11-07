//! Store: crash safety of deliver via failpoints (cargo feature `failpoints`).
//! A failpoint stops `deliver` at that step with no cleanup, like a crash; then the store is
//! dropped and reopened, as after a restart.

mod common;
use common::*;
use synology_mail_server::store::Failpoint;

fn crash_at(fp: Failpoint) -> (TempDir, Store, MailboxId) {
    let (tmp, store) = setup();
    let (_, mb) = account(&store, "test@example.com");
    store.set_failpoint(Some(fp));
    match deliver(&store, 1, "test@example.com", BODY) {
        Err(StoreError::Failpoint(hit)) => assert_eq!(hit, fp),
        other => panic!("expected Failpoint({fp:?}), got {other:?}"),
    }
    (tmp, store, mb)
}

fn assert_clean_after_restart(tmp: &TempDir, mb: MailboxId) -> Store {
    let store = reopen(tmp);
    assert!(
        files_in(&data_dir(tmp).join("tmp")).is_empty(),
        "tmp/ emptied at startup"
    );
    assert!(store.messages(mb).unwrap().is_empty(), "no visible row");
    assert!(
        !store.is_delivered(&key(1)).unwrap(),
        "key not recorded, so the Worker copy is not acked"
    );
    let info = store.mailbox(mb).unwrap();
    assert_eq!(info.uidnext, 1);
    assert_eq!(info.highest_modseq, 1);
    // Redelivery after the restart works and gives exactly one message.
    assert_eq!(
        uid_of(deliver(&store, 1, "test@example.com", BODY).unwrap()),
        1
    );
    assert_eq!(store.messages(mb).unwrap().len(), 1);
    assert!(read_message(&store, mb, 1).ends_with(BODY));
    store
}

#[test]
fn crash_after_tmp_write() {
    let (tmp, store, mb) = crash_at(Failpoint::AfterTmpWrite);
    assert_eq!(
        files_in(&data_dir(&tmp).join("tmp")).len(),
        1,
        "failpoint hit after the tmp file was written"
    );
    assert!(files_in(&data_dir(&tmp).join("blobs")).is_empty());
    drop(store);
    assert_clean_after_restart(&tmp, mb);
}

#[test]
fn crash_after_rename_leaves_only_an_invisible_orphan() {
    let (tmp, store, mb) = crash_at(Failpoint::AfterRename);
    let orphans = files_in(&data_dir(&tmp).join("blobs"));
    assert_eq!(
        orphans.len(),
        1,
        "blob renamed into place before the failpoint"
    );
    assert!(files_in(&data_dir(&tmp).join("tmp")).is_empty());
    drop(store);
    let store = assert_clean_after_restart(&tmp, mb);
    let m = &store.messages(mb).unwrap()[0];
    assert_ne!(
        data_dir(&tmp).join(&m.blob),
        orphans[0],
        "the redelivered message has its own blob"
    );
}

#[test]
fn crash_before_commit_rolls_back() {
    let (tmp, store, mb) = crash_at(Failpoint::BeforeCommit);
    assert_eq!(files_in(&data_dir(&tmp).join("blobs")).len(), 1);
    drop(store);
    assert_clean_after_restart(&tmp, mb);
}

#[test]
fn failpoint_fires_once_then_disarms() {
    let (_tmp, store, mb) = crash_at(Failpoint::BeforeCommit);
    assert!(
        store.messages(mb).unwrap().is_empty(),
        "the same live store does not show the rolled-back row"
    );
    assert_eq!(
        uid_of(deliver(&store, 2, "test@example.com", BODY).unwrap()),
        1
    );
}
