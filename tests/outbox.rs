use synology_mail_server::store::{
    Store,
    outbox::{Next, Outcome},
};

#[test]
fn pending_messages_survive_restart_and_ambiguous_submissions_are_not_replayed() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let alice = s.create_account("alice", "a-password").unwrap();
    let bob = s.create_account("bob", "b-password").unwrap();
    assert!(
        s.enqueue(alice, "alice@example.org", "bob@example.net", b"mime")
            .unwrap()
    );
    assert!(s.outbox_status(bob).unwrap().is_empty());
    drop(s);
    let s = Store::open(d.path()).unwrap();
    let Next::Send(job) = s.next_outgoing().unwrap() else {
        panic!("expected pending message")
    };
    assert_eq!(job.mime, b"mime");
    // A stopped daemon may have reached the relay before it recorded acceptance.
    drop(s);
    let s = Store::open(d.path()).unwrap();
    s.recover_outbox().unwrap();
    assert_eq!(s.outbox_status(alice).unwrap()[0].1, "Check delivery");
    assert!(matches!(s.next_outgoing().unwrap(), Next::Wait(None)));
}

#[test]
fn a_definite_temporary_failure_backs_off_and_pending_quota_is_per_account() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = s.create_account("a", "password").unwrap();
    let b = s.create_account("b", "password").unwrap();
    assert!(s.enqueue(a, "a@a.org", "x@b.org", b"one").unwrap());
    let Next::Send(job) = s.next_outgoing().unwrap() else {
        panic!("missing job")
    };
    s.finish_outgoing(&job, Outcome::Temporary).unwrap();
    assert!(matches!(
        s.next_outgoing().unwrap(),
        Next::Wait(Some(1..=30))
    ));
    for _ in 1..20 {
        assert!(s.enqueue(a, "a@a.org", "x@b.org", b"two").unwrap());
    }
    assert!(!s.enqueue(a, "a@a.org", "x@b.org", b"quota").unwrap());
    assert!(
        s.enqueue(b, "b@a.org", "x@b.org", b"separate quota")
            .unwrap()
    );
}
