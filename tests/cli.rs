//! CLI (build step 3): `serve`, `account add|passwd|list|admin`, `address add|rm`. Passwords come from
//! stdin only, never argv. Runs the real binary against a temp data dir.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use synology_mail_server::store::{Account, Store, StoreError};

fn ssm(data: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .args(args)
        .env_clear()
        .env("SSM_DATA_DIR", data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "exit {:?}, stderr: {}",
        o.status,
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn data() -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let d = t.path().join("data");
    (t, d)
}

#[test]
fn account_add_reads_the_password_from_stdin() {
    let (_t, d) = data();
    ok(&ssm(
        &d,
        &["account", "add", "test@example.com"],
        "correct horse\n",
    ));
    let s = Store::open_admin(&d).unwrap();
    let id = s
        .account_id("test@example.com")
        .unwrap()
        .expect("account created");
    assert_eq!(
        s.authenticate("test@example.com", "correct horse").unwrap(),
        Some(id)
    );
}

#[test]
fn a_password_on_the_command_line_is_refused() {
    let (_t, d) = data();
    let o = ssm(&d, &["account", "add", "test@example.com", "secret"], "");
    assert_eq!(o.status.code(), Some(2), "usage error");
    assert!(
        !d.join("ssm.db").exists()
            || Store::open_admin(&d)
                .unwrap()
                .accounts()
                .unwrap()
                .is_empty()
    );
}

#[test]
fn empty_password_is_refused() {
    let (_t, d) = data();
    let o = ssm(&d, &["account", "add", "test@example.com"], "\n");
    assert!(!o.status.success());
}

#[test]
fn passwd_list_and_addresses() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "old\r\n"));
    ok(&ssm(&d, &["account", "passwd", "alice"], "new pw\n"));
    ok(&ssm(
        &d,
        &["address", "add", "Alice@EXAMPLE.com", "alice"],
        "",
    ));
    ok(&ssm(&d, &["address", "add", "@example.com", "alice"], ""));
    let list = ok(&ssm(&d, &["account", "list"], ""));
    assert!(list.contains("alice"), "{list}");
    assert!(
        list.contains("alice@example.com") && list.contains("@example.com"),
        "{list}"
    );
    let s = Store::open_admin(&d).unwrap();
    let id = s.account_id("alice").unwrap();
    assert_eq!(s.authenticate("alice", "new pw").unwrap(), id);
    assert_eq!(s.route("alice+x@example.com").unwrap(), id);
    ok(&ssm(&d, &["address", "rm", "alice@example.com"], ""));
    ok(&ssm(&d, &["address", "rm", "@example.com"], ""));
    assert_eq!(s.route("alice@example.com").unwrap(), None);
}

#[test]
fn errors_exit_non_zero_with_a_message() {
    let (_t, d) = data();
    let o = ssm(&d, &["address", "add", "x@example.com", "nobody"], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("nobody"));
    assert_eq!(ssm(&d, &["frobnicate"], "").status.code(), Some(2));
    assert_eq!(ssm(&d, &[], "").status.code(), Some(2));
}

#[test]
fn missing_data_dir_is_reported() {
    let o = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .args(["account", "list"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("SSM_DATA_DIR"));
}

#[test]
fn serve_opens_the_store_holds_the_lock_and_idles() {
    let (_t, d) = data();
    let mut child = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .arg("serve")
        .env_clear()
        .env("SSM_DATA_DIR", &d)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    let locked = loop {
        if d.join("ssm.db").exists() {
            match Store::open(&d) {
                Err(StoreError::Locked(_)) => break true,
                Ok(s) => drop(s), // not locked yet: serve still starting
                Err(_) => {}
            }
        }
        if t0.elapsed() > Duration::from_secs(10) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let still_running = child.try_wait().unwrap().is_none();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(locked, "serve must hold the data dir lock");
    assert!(still_running, "serve must keep running");
}

// admin accounts
const LAST_ADMIN: &str = "At least one admin must remain";

fn acct(data: &Path, login: &str) -> Account {
    Store::open_admin(data)
        .unwrap()
        .accounts()
        .unwrap()
        .into_iter()
        .find(|a| a.login == login)
        .expect("account exists")
}

fn line_of<'a>(list: &'a str, login: &str) -> &'a str {
    list.lines()
        .find(|l| l.split('\t').next() == Some(login))
        .unwrap_or_else(|| panic!("no line for {login}:\n{list}"))
}

#[test]
fn account_admin_on_and_off() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "pw-a\n"));
    ok(&ssm(&d, &["account", "add", "bob"], "pw-b\n"));
    assert!(!acct(&d, "alice").admin);
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    assert!(acct(&d, "alice").admin);
    assert!(!acct(&d, "bob").admin);
    ok(&ssm(&d, &["account", "admin", "bob", "on"], ""));
    ok(&ssm(&d, &["account", "admin", "alice", "off"], ""));
    assert!(!acct(&d, "alice").admin);
    assert!(acct(&d, "bob").admin);

    for bad in [
        &["account", "admin", "alice"][..],
        &["account", "admin", "alice", "yes"],
        &["account", "admin", "alice", "on", "x"],
    ] {
        assert_eq!(
            ssm(&d, bad, "").status.code(),
            Some(2),
            "{bad:?} is a usage error"
        );
    }
    let o = ssm(&d, &["account", "admin", "nobody", "on"], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("nobody"));
}

#[test]
fn account_admin_off_refuses_last_admin() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "pw-a\n"));
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    let o = ssm(&d, &["account", "admin", "alice", "off"], "");
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains(LAST_ADMIN), "{err}");
    assert!(acct(&d, "alice").admin, "nothing changed");
}

#[test]
fn admin_on_recovers_when_no_admin_left() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "pw-a\n"));
    assert!(!Store::open_admin(&d).unwrap().has_active_admin().unwrap());
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    assert!(Store::open_admin(&d).unwrap().has_active_admin().unwrap());
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    assert!(acct(&d, "alice").admin);
}

#[test]
fn passwd_works_for_an_admin() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "old pw\n"));
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    let before = acct(&d, "alice").auth_stamp;
    ok(&ssm(&d, &["account", "passwd", "alice"], "new pw\n"));
    let a = acct(&d, "alice");
    assert!(a.admin);
    assert_ne!(
        a.auth_stamp, before,
        "a CLI password change ends web sessions"
    );
    let s = Store::open_admin(&d).unwrap();
    assert_eq!(s.authenticate("alice", "new pw").unwrap(), Some(a.id));
    assert_eq!(s.authenticate("alice", "old pw").unwrap(), None);
}

/// Each admin's line carries an `ADMIN` field, like `DISABLED`.
#[test]
fn list_shows_admin() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "alice"], "pw-a\n"));
    ok(&ssm(&d, &["account", "add", "bob"], "pw-b\n"));
    ok(&ssm(&d, &["account", "admin", "alice", "on"], ""));
    let list = ok(&ssm(&d, &["account", "list"], ""));
    assert!(
        line_of(&list, "alice").split('\t').any(|f| f == "ADMIN"),
        "{list}"
    );
    assert!(
        !line_of(&list, "bob").split('\t').any(|f| f == "ADMIN"),
        "{list}"
    );
}

#[test]
fn usage_names_account_admin_and_the_web_settings() {
    let o = Command::new(env!("CARGO_BIN_EXE_synology-mail-server"))
        .arg("--help")
        .env_clear()
        .output()
        .unwrap();
    let usage = ok(&o);
    for want in [
        "account admin <login> on|off",
        "SSM_WEB_LISTEN",
        "SSM_WEB_ALLOW_PUBLIC",
    ] {
        assert!(usage.contains(want), "usage must name {want}:\n{usage}");
    }
}

#[test]
fn standalone_delivery_deduplicates_queue_retries() {
    let (_t, d) = data();
    ok(&ssm(&d, &["account", "add", "a"], "password"));
    ok(&ssm(&d, &["address", "add", "a@example.org", "a"], ""));
    for _ in 0..2 {
        ok(&ssm(
            &d,
            &["deliver", "ABC123", "", "a@example.org"],
            "Subject: Test\r\n\r\nHello",
        ));
    }
    let s = Store::open_admin(&d).unwrap();
    let mb = s
        .find_mailbox(s.account_id("a").unwrap().unwrap(), "INBOX")
        .unwrap()
        .unwrap();
    assert_eq!(s.messages(mb.id).unwrap().len(), 1);
}
