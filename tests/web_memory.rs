//! Sessions are capped at 1,000 and small: 1,000 signed-in sessions hold under 512 KiB of heap,
//! and further sign-ins drop the session seen longest ago instead of growing. Live heap bytes are
//! counted with a global allocator; every request uses a fresh connection, closed before measuring.

mod browser;
mod harness;
mod net;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use browser::*;
use harness::password;

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

const USER: &str = "user@example.com";
const CAP: usize = 1000;
const BUDGET: isize = 512 * 1024;
const OVER_CAP_SLACK: isize = 32 * 1024;

/// Lowest live-heap reading over ~0.5 s, with the server free to finish closing connections.
async fn settled_live() -> isize {
    let mut low = isize::MAX;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        low = low.min(LIVE.load(Ordering::SeqCst));
    }
    low
}

/// One sign-in from a browser that is then forgotten (its session stays on the server).
async fn sign_in(h: &WebHarness) {
    let mut b = h.browser();
    let r = b.sign_in(USER, &password(USER)).await;
    assert_eq!(r.status, 303, "sign-in: {}", r.text());
}

/// `n` sign-ins, two at a time.
async fn sign_ins(h: &WebHarness, n: usize) {
    for _ in 0..n / 2 {
        tokio::join!(sign_in(h), sign_in(h));
    }
    if n % 2 == 1 {
        sign_in(h).await;
    }
}

#[tokio::test]
async fn thousand_sessions_bounded_heap() {
    let h = WebHarness::start().await;
    h.user(USER);
    // Warm-up: the TLS session cache (256 entries) and one-time allocations fill before the baseline.
    for _ in 0..300 {
        assert_eq!(h.get("/login").await.status, 200, "the sign-in page");
    }
    let mut first = h.browser();
    assert_eq!(first.sign_in(USER, &password(USER)).await.status, 303);
    assert_eq!(first.get("/me").await.status, 200);
    let before = settled_live().await;

    let mut second = h.browser();
    assert_eq!(second.sign_in(USER, &password(USER)).await.status, 303);
    sign_ins(&h, CAP - 2).await;
    let full = settled_live().await;
    let delta = full - before;
    assert!(
        delta < BUDGET,
        "{CAP} sessions hold {} KiB of heap ({} bytes each); budget {} KiB",
        delta / 1024,
        delta / CAP as isize,
        BUDGET / 1024
    );
    assert_eq!(
        first.get("/me").await.status,
        200,
        "{CAP} sessions fit; this one is now the most recently seen"
    );

    sign_ins(&h, 200).await;
    let over = settled_live().await;
    assert!(
        over - full < OVER_CAP_SLACK,
        "200 sign-ins past the cap grew the heap by {} KiB",
        (over - full) / 1024
    );
    assert_to_login(
        &second.get("/me").await,
        "the session seen longest ago was dropped for a new one",
    );
    assert_eq!(
        first.get("/me").await.status,
        200,
        "a session seen recently stays"
    );

    let mut newest = h.browser();
    assert_eq!(newest.sign_in(USER, &password(USER)).await.status, 303);
    assert_eq!(
        newest.get("/me").await.status,
        200,
        "the newest session works"
    );
}
