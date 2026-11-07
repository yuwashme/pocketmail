//! Store: accounts, argon2id auth, addresses and recipient routing (tests D).

mod common;
use common::*;
use std::time::{Duration, Instant};

// ---- accounts -------------------------------------------------------------------------------

#[test]
fn create_account_lists_it_and_creates_its_inbox() {
    let (_tmp, store) = setup();
    let t0 = now();
    let id = store.create_account("test@example.com", "correct horse").unwrap();
    let t1 = now();
    let accts = store.accounts().unwrap();
    assert_eq!(accts.len(), 1);
    assert_eq!(accts[0].id, id);
    assert_eq!(accts[0].login, "test@example.com");
    assert!(!accts[0].disabled);
    assert!((t0..=t1).contains(&accts[0].created_at));
    assert_eq!(store.account_id("test@example.com").unwrap(), Some(id));
    assert_eq!(store.account_id("nobody@example.com").unwrap(), None);

    let boxes = store.mailboxes(id).unwrap();
    assert_eq!(boxes.len(), 1, "only INBOX");
    let inbox = &boxes[0];
    assert_eq!(inbox.name, "INBOX");
    assert_eq!(inbox.account, id);
    assert_eq!(inbox.uidnext, 1);
    assert_eq!(inbox.highest_modseq, 1);
    assert_eq!(inbox.recent_uid, 0);
    assert!(inbox.subscribed);
    assert!(inbox.uidvalidity > 0, "uidvalidity is a nz-number");
    assert!((t0..=t1).contains(&(inbox.uidvalidity as i64)), "uidvalidity = creation unix seconds");
    assert_eq!(store.mailbox(inbox.id).unwrap().name, "INBOX");
}

#[test]
fn duplicate_login_is_refused() {
    let (_tmp, store) = setup();
    store.create_account("test@example.com", "pw1").unwrap();
    assert!(matches!(store.create_account("test@example.com", "pw2"), Err(StoreError::AlreadyExists(_))));
}

#[test]
fn empty_login_or_password_is_refused() {
    let (_tmp, store) = setup();
    assert!(matches!(store.create_account("", "pw"), Err(StoreError::InvalidInput(_))));
    assert!(matches!(store.create_account("test@example.com", ""), Err(StoreError::InvalidInput(_))));
    assert!(store.accounts().unwrap().is_empty());
}

#[test]
fn password_hash_is_an_argon2id_phc_string_with_the_chosen_params() {
    let (tmp, store) = setup();
    store.create_account("a@example.com", "same secret").unwrap();
    store.create_account("b@example.com", "same secret").unwrap();
    let c = raw_db(&tmp);
    let mut st = c.prepare("SELECT password_hash FROM accounts ORDER BY login").unwrap();
    let hashes: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect();
    for h in &hashes {
        assert!(h.starts_with("$argon2id$v=19$m=12288,t=3,p=1$"), "PHC params: {h}");
        let parts: Vec<&str> = h.split('$').collect();
        assert_eq!(parts.len(), 6, "$argon2id$v$params$salt$hash: {h}");
        assert!(parts[4].len() >= 22 && parts[5].len() >= 43, "salt >= 16 B, hash >= 32 B (b64): {h}");
        assert!(!h.contains("same secret"));
    }
    assert_ne!(hashes[0], hashes[1], "a random salt per account");
}

#[test]
fn authenticate_right_wrong_and_unknown() {
    let (_tmp, store) = setup();
    let id = store.create_account("test@example.com", "correct horse").unwrap();
    assert_eq!(store.authenticate("test@example.com", "correct horse").unwrap(), Some(id));
    assert_eq!(store.authenticate("test@example.com", "Correct horse").unwrap(), None);
    assert_eq!(store.authenticate("test@example.com", "").unwrap(), None);
    assert_eq!(store.authenticate("nobody@example.com", "correct horse").unwrap(), None);
}

#[test]
fn unknown_login_still_costs_an_argon2_verify() {
    let (_tmp, store) = setup();
    store.create_account("test@example.com", "correct horse").unwrap();
    let time = |login: &str| {
        (0..3)
            .map(|_| {
                let t = Instant::now();
                assert_eq!(store.authenticate(login, "wrong").unwrap(), None);
                t.elapsed()
            })
            .min()
            .unwrap()
    };
    let wrong_pw = time("test@example.com");
    let unknown = time("nobody@example.com");
    assert!(wrong_pw > Duration::from_millis(1), "a real argon2 verify takes measurable time");
    assert!(unknown * 2 >= wrong_pw, "unknown login {unknown:?} vs wrong password {wrong_pw:?}: dummy verify missing");
}

#[test]
fn set_password_replaces_the_old_one() {
    let (_tmp, store) = setup();
    let id = store.create_account("test@example.com", "old pw").unwrap();
    store.set_password("test@example.com", "new pw").unwrap();
    assert_eq!(store.authenticate("test@example.com", "old pw").unwrap(), None);
    assert_eq!(store.authenticate("test@example.com", "new pw").unwrap(), Some(id));
    assert!(matches!(store.set_password("nobody@example.com", "x"), Err(StoreError::NotFound(_))));
    assert!(matches!(store.set_password("test@example.com", ""), Err(StoreError::InvalidInput(_))));
}

// ---- addresses and routing -----------------------------------------------------------------

fn two_accounts(store: &Store) -> (AccountId, AccountId) {
    let alice = store.create_account("alice", "pw-a").unwrap();
    let bob = store.create_account("bob", "pw-b").unwrap();
    (alice, bob)
}

#[test]
fn routes_exact_address_case_insensitively() {
    let (_tmp, store) = setup();
    let (alice, _) = two_accounts(&store);
    store.add_address("Test@EXAMPLE.com", "alice").unwrap();
    for rcpt in ["test@example.com", "TEST@EXAMPLE.COM", "Test@Example.Com"] {
        assert_eq!(store.route(rcpt).unwrap(), Some(alice), "{rcpt}");
    }
}

#[test]
fn routes_plus_tag_to_the_base_address() {
    let (_tmp, store) = setup();
    let (alice, _) = two_accounts(&store);
    store.add_address("test@example.com", "alice").unwrap();
    assert_eq!(store.route("test+news@example.com").unwrap(), Some(alice));
    assert_eq!(store.route("TEST+News@EXAMPLE.COM").unwrap(), Some(alice));
    assert_eq!(store.route("test+a+b@example.com").unwrap(), Some(alice));
    assert_eq!(store.route("test+@example.com").unwrap(), Some(alice));
}

#[test]
fn routes_utf8_local_parts_rfc6531() {
    let (_tmp, store) = setup();
    let (alice, _) = two_accounts(&store);
    store.add_address("šef@example.com", "alice").unwrap();
    assert_eq!(store.route("šef@example.com").unwrap(), Some(alice));
    assert_eq!(store.route("ŠEF@EXAMPLE.COM").unwrap(), Some(alice));
    assert_eq!(store.route("šef+čžć@example.com").unwrap(), Some(alice));
}

#[test]
fn catch_all_takes_the_rest_and_exact_wins() {
    let (_tmp, store) = setup();
    let (alice, bob) = two_accounts(&store);
    store.add_address("test@example.com", "alice").unwrap();
    store.add_address("@example.com", "bob").unwrap();
    assert_eq!(store.route("test@example.com").unwrap(), Some(alice));
    assert_eq!(store.route("test+x@example.com").unwrap(), Some(alice));
    assert_eq!(store.route("anyone@example.com").unwrap(), Some(bob));
    assert_eq!(store.route("Anyone+x@EXAMPLE.COM").unwrap(), Some(bob));
    assert_eq!(store.route("\"a@b\"@example.com").unwrap(), Some(bob), "domain is after the last '@'");
}

#[test]
fn unknown_or_malformed_recipients_do_not_route() {
    let (_tmp, store) = setup();
    two_accounts(&store);
    store.add_address("test@example.com", "alice").unwrap();
    store.add_address("@example.com", "bob").unwrap();
    for rcpt in ["test@other.test", "test@sub.example.com", "test@example.com.evil.test", "nobody", "", "@", "test@"] {
        assert_eq!(store.route(rcpt).unwrap(), None, "{rcpt:?}");
    }
}

#[test]
fn address_management_errors() {
    let (_tmp, store) = setup();
    two_accounts(&store);
    store.add_address("test@example.com", "alice").unwrap();
    assert!(matches!(store.add_address("x@example.com", "nobody"), Err(StoreError::NotFound(_))));
    assert!(matches!(store.add_address("TEST@example.com", "bob"), Err(StoreError::AlreadyExists(_))));
    assert!(matches!(store.add_address("no-at-sign", "alice"), Err(StoreError::InvalidInput(_))));
    assert!(matches!(store.add_address("", "alice"), Err(StoreError::InvalidInput(_))));
    assert!(matches!(store.remove_address("never@example.com"), Err(StoreError::NotFound(_))));
}

#[test]
fn removed_address_no_longer_routes() {
    let (_tmp, store) = setup();
    let (_, bob) = two_accounts(&store);
    store.add_address("test@example.com", "alice").unwrap();
    store.add_address("@example.com", "bob").unwrap();
    store.remove_address("Test@EXAMPLE.com").unwrap();
    assert_eq!(store.route("test@example.com").unwrap(), Some(bob), "falls through to the catch-all");
    store.remove_address("@example.com").unwrap();
    assert_eq!(store.route("test@example.com").unwrap(), None);
}
