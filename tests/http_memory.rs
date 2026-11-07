//! inbound/http.rs: a 25 MiB body is streamed to a file, never buffered
//! ("25 MiB stream raises RSS < 1 MB"). RSS is not portable (no /proc on macOS) and is noisy inside
//! a multi-threaded test binary, so this measures the peak of live heap bytes with a counting
//! global allocator instead. It is its own test binary so no other test allocates meanwhile.

mod net;
use net::*;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use synology_mail_server::inbound::http::HttpClient;
use tokio::io::AsyncWriteExt;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size > layout.size() {
                let now = LIVE.fetch_add(new_size - layout.size(), Ordering::SeqCst) + new_size
                    - layout.size();
                PEAK.fetch_max(now, Ordering::SeqCst);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const SIZE: u64 = 25 * 1024 * 1024;

#[tokio::test]
async fn a_25_mib_body_streams_to_disk_with_under_1_mib_of_heap() {
    let pki = Pki::local();
    let client = HttpClient::new(client_tls(&pki));
    let srv = serve_one(server_tls(&pki), |mut s| async move {
        let _ = s
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\n\r\n").as_bytes())
            .await;
        let chunk = vec![b'm'; 64 * 1024];
        let mut sent = 0u64;
        while sent < SIZE {
            if s.write_all(&chunk).await.is_err() {
                return;
            }
            sent += chunk.len() as u64;
        }
        let _ = s.shutdown().await;
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let url = format!("{}/messages/big", srv.url);

    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let res = tokio::time::timeout(
        Duration::from_secs(120),
        client.get_to_file(&url, &[], dir.path()),
    )
    .await
    .expect("no hang");
    let peak = PEAK.load(Ordering::SeqCst);

    let (head, file) = res.unwrap();
    assert_eq!(head.status, 200);
    assert_eq!(file.len(), SIZE);
    assert_eq!(std::fs::metadata(file.path()).unwrap().len(), SIZE);
    let grew = peak.saturating_sub(base);
    // Includes the in-process server's TLS buffers, so the client's share is smaller still.
    assert!(
        grew < 1024 * 1024,
        "heap grew by {grew} bytes while streaming 25 MiB"
    );
}
