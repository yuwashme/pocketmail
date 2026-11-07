//! Group E budget, heap stand-in for "80 idle connections < 4 MB RSS" (RSS is measured on the NAS,
//! a release gate). The server runs on its own thread in this test binary, which counts live heap
//! bytes with a global allocator; the 80 clients run in a child process (this same binary, the
//! ignored `idle_client_child` test) so their TLS state is not counted. Every client logs in and
//! selects INBOX, then stays idle.

mod harness;
mod net;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use harness::*;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size() as isize, Ordering::SeqCst);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::SeqCst);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const USER: &str = "idle@example.com";
const CONNS: usize = 80;
const BUDGET: isize = 4 * 1024 * 1024;
const ADDR_ENV: &str = "SSM_TEST_IMAP_IDLE_ADDR";
const CA_ENV: &str = "SSM_TEST_IMAP_IDLE_CA";

/// Lowest live-heap reading over ~0.5 s (transient buffers settle).
fn settled_live() -> isize {
    let mut low = isize::MAX;
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(50));
        low = low.min(LIVE.load(Ordering::SeqCst));
    }
    low
}

#[test]
fn eighty_idle_connections_use_under_4_mib_of_heap() {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let h = Harness::start_with(|c| {
                c.max_conn = 200;
                c.max_conn_per_ip = 200;
            })
            .await;
            h.simple_account(USER, 20);
            // Warm-up session so one-time allocations (caches, lazy statics) precede the baseline.
            let mut c = h.select(USER).await;
            c.cmd("W1", "FETCH 1:* (FLAGS UID)").await.assert_ok();
            c.cmd("W2", "LOGOUT").await.assert_ok();
            c.expect_closed().await;
            drop(c);
            ready_tx.send((h.addr, h.pki.ca_pem.clone())).unwrap();
            let _ = stop_rx.await;
            drop(h);
        });
    });
    let (addr, ca_pem) = ready_rx.recv_timeout(Duration::from_secs(60)).expect("IMAP server thread did not start (see its panic above)");

    let before = settled_live();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["idle_client_child", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
        .env(ADDR_ENV, addr.to_string())
        .env(CA_ENV, ca_pem)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        let n = out.read_line(&mut line).unwrap();
        assert!(n > 0, "client process ended before READY:\n{seen}");
        seen.push_str(&line);
        if line.trim().ends_with(&format!("READY {CONNS}")) {
            break;
        }
    }
    let during = settled_live();
    let delta = during - before;

    drop(child.stdin.take()); // EOF: the child closes its connections and exits
    let mut rest = String::new();
    let _ = out.read_to_string(&mut rest);
    let status = child.wait().unwrap();
    let _ = stop_tx.send(());
    let _ = server.join();

    assert!(status.success(), "client process failed:\n{seen}{rest}");
    assert!(
        delta < BUDGET,
        "{CONNS} idle selected connections hold {} KiB of server heap ({} KiB each); budget {} KiB",
        delta / 1024,
        delta / 1024 / CONNS as isize,
        BUDGET / 1024
    );
}

#[test]
#[ignore = "helper process for eighty_idle_connections_use_under_4_mib_of_heap"]
fn idle_client_child() {
    let (Ok(addr), Ok(ca)) = (std::env::var(ADDR_ENV), std::env::var(CA_ENV)) else {
        return; // run by hand without the parent: nothing to do
    };
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let root = CertificateDer::from_pem_slice(ca.as_bytes()).unwrap();
    let tls = synology_mail_server::tls::client_config_with_roots(vec![root]).unwrap();
    let addr: std::net::SocketAddr = addr.parse().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let clients = rt.block_on(async {
        let mut clients = Vec::new();
        for i in 0..CONNS {
            let mut c = Client::open_with(addr, tls.clone()).await.unwrap_or_else(|e| panic!("connection {i}: {e}"));
            let g = c.read_response().await.expect("greeting");
            assert!(g.starts_with(b"* OK"), "connection {i}: {}", show(&g));
            c.cmd("L", &format!("LOGIN {USER} {}", password(USER))).await.assert_ok();
            c.cmd("S", "SELECT INBOX").await.assert_ok();
            clients.push(c);
        }
        clients
    });
    println!("READY {CONNS}");
    std::io::stdout().flush().unwrap();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    drop(clients);
}
