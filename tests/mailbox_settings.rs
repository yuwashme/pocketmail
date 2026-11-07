mod common;
use common::*;
use std::sync::Barrier;

#[test]
fn concurrent_deliveries_share_one_limit_and_full_mail_is_retryable() {
    let (tmp, store) = setup();
    let to = "limited@example.org";
    let (id, mb) = account(&store,to);
    assert_eq!(store.mailbox_settings(id).unwrap().1, 1 << 30);
    uid_of(deliver(&store,1,to,BODY).unwrap());
    let used = store.mailbox_settings(id).unwrap().0;
    store.set_mailbox_settings(id,used*2,None).unwrap();
    let gate=Barrier::new(2);
    let results=std::thread::scope(|scope| {
        let threads:Vec<_>=(2..=3).map(|n|scope.spawn({let gate=&gate;let store=&store;move||{
            gate.wait(); (n,deliver(store,n,to,BODY))
        }})).collect();
        threads.into_iter().map(|t|t.join().unwrap()).collect::<Vec<_>>()
    });
    let failed:Vec<_>=results.iter().filter(|(_,r)|matches!(r,Err(StoreError::QuotaExceeded))).collect();
    assert_eq!(failed.len(),1);
    assert_eq!(store.messages(mb).unwrap().len(),2);
    assert_eq!(files_in(&data_dir(&tmp).join("blobs")).len(),2);
    assert_eq!(store.mailbox_settings(id).unwrap().0,used*2);
    store.set_mailbox_settings(id,0,None).unwrap();
    uid_of(deliver(&store,failed[0].0,to,BODY).unwrap());
    assert!(store.set_mailbox_settings(id,0,Some("unauthorized@invalid.example")).is_err());
}

#[test]
fn migration_includes_existing_messages_and_forward_jobs_are_atomic_and_loop_safe() {
    let (tmp,store)=setup();
    let to="original@example.org";
    let (id,_)=account(&store,to);
    let c=raw_db(&tmp);
    // Exercise an already persisted destination without changing process-wide relay configuration.
    c.execute("UPDATE mailboxes SET forward_to='verified@example.net'",[]).unwrap();
    let raw=b"Subject: Test\r\n\r\nbody";
    deliver(&store,1,to,raw).unwrap();
    deliver(&store,1,to,raw).unwrap();
    deliver(&store,2,to,b"X-SSM-Forwarded: yes\r\n\r\nbody").unwrap();
    assert_eq!(store.outbox_status(id).unwrap().len(),1);
    store.set_mailbox_settings(id,0,None).unwrap();
    assert_eq!(store.outbox_status(id).unwrap()[0].1,"Cancelled");
    drop(store);
    c.execute_batch("ALTER TABLE mailboxes DROP COLUMN keep_copy; ALTER TABLE outbox DROP COLUMN queue_only; DROP TRIGGER release_mailbox_space; ALTER TABLE mailboxes DROP COLUMN quota_bytes;
        ALTER TABLE mailboxes DROP COLUMN used_bytes; ALTER TABLE mailboxes DROP COLUMN forward_to;
        ALTER TABLE outbox DROP COLUMN forward_blob; PRAGMA user_version=3").unwrap();
    let store=reopen(&tmp);
    let total:i64=c.query_row("SELECT sum(size) FROM messages",[],|r|r.get(0)).unwrap();
    assert_eq!(store.mailbox_settings(id).unwrap(),(total,1 << 30,None));
}

#[test]
fn forward_only_releases_queue_file_after_acceptance_and_preserves_uncertain_mail() {
    use synology_mail_server::store::outbox::{Next,Outcome};
    let (tmp,s)=setup();
    let to="owner@example.org";
    let (id,mb)=account(&s,to);
    raw_db(&tmp).execute("UPDATE mailboxes SET keep_copy=0,quota_bytes=1,forward_to='recipient@example.net'",[]).unwrap();
    let mail=b"From: human@example.net\r\nAuto-Submitted: no\r\nSubject: Probe\r\n\r\noriginal";
    assert_eq!(deliver(&s,1,to,mail).unwrap(),DeliveryOutcome::ForwardQueued);
    assert_eq!(deliver(&s,1,to,mail).unwrap(),DeliveryOutcome::AlreadyDelivered);
    let Next::Send(job)=s.next_outgoing().unwrap() else {panic!("missing queued mail")};
    let file=job.forward_blob.clone().unwrap();
    assert!(std::fs::read(&file).unwrap().ends_with(mail));
    s.finish_outgoing(&job,Outcome::Accepted).unwrap();
    assert!(!file.exists());
    assert!(s.messages(mb).unwrap().is_empty());
    assert_eq!(s.mailbox_settings(id).unwrap().0,0);
    deliver(&s,2,to,mail).unwrap();
    let Next::Send(job)=s.next_outgoing().unwrap() else {panic!("missing second mail")};
    s.recover_outbox().unwrap();
    assert!(job.forward_blob.unwrap().exists());
    assert!(matches!(s.next_outgoing().unwrap(),Next::Wait(None)));
}
