//! inbound/mod.rs: the poller. A real store in a temp dir, the
//! fake Worker over HTTPS on 127.0.0.1, and for the loop tests a simulated clock (tests/net
//! SimClock) so hours of polling run in seconds.

mod common;
mod net;
use common::*;
use net::*;

use std::sync::Arc;
use std::time::Duration;

use synology_mail_server::inbound::http::HttpClient;
use synology_mail_server::inbound::worker_api::{ApiError, WorkerApi};
use synology_mail_server::inbound::{self, MAX_BACKOFF, PassReport, Poller, REDELETE_INTERVAL};
use synology_mail_server::store::Failpoint;

const INTERVAL: Duration = Duration::from_secs(120);

struct Env {
    tmp: TempDir,
    store: Arc<Store>,
    fake: FakeWorker,
    clock: Option<Arc<SimClock>>,
    poller: Option<Poller>,
}

/// Store with account test@example.com, the fake Worker, and a poller (simulated clock when `limit`).
async fn env(limit: Option<Duration>) -> Env {
    let (tmp, store) = setup();
    let store = Arc::new(store);
    account(&store, "test@example.com");
    let pki = Pki::local();
    let clock = limit.map(SimClock::new);
    let fake = FakeWorker::start(&pki, clock.clone()).await;
    let api = WorkerApi::new(HttpClient::new(client_tls(&pki)), &fake.url, TOKEN).unwrap();
    let mut poller = Poller::new(api, store.clone(), INTERVAL);
    if let Some(c) = &clock {
        poller = poller.with_clock(c.clone());
    }
    Env { tmp, store, fake, clock, poller: Some(poller) }
}

impl Env {
    async fn poll(&mut self) -> Result<PassReport, ApiError> {
        let p = self.poller.as_mut().unwrap();
        tokio::time::timeout(Duration::from_secs(30), p.poll_once()).await.expect("poll_once must finish")
    }

    /// Run the poll loop until the simulated clock reaches its limit.
    async fn run(&mut self) {
        let poller = self.poller.take().unwrap();
        let clock = self.clock.clone().expect("loop tests use a SimClock");
        let guard = tokio::time::timeout(Duration::from_secs(120), async {
            tokio::select! {
                _ = poller.run() => panic!("Poller::run must not return"),
                _ = clock.done.notified() => {}
            }
        });
        guard.await.expect("simulated run finishes in real seconds");
    }

    fn inbox(&self) -> MailboxId {
        let id = self.store.account_id("test@example.com").unwrap().unwrap();
        inbox(&self.store, id)
    }

    fn msg_path(n: &str) -> String {
        format!("/messages/{n}")
    }

    fn gets(&self, k: &str) -> usize {
        self.fake.count("GET", &Env::msg_path(k))
    }

    fn deletes(&self, k: &str) -> Vec<Duration> {
        let p = Env::msg_path(k);
        self.fake.requests().into_iter().filter(|r| r.method == "DELETE" && r.path == p).map(|r| r.at).collect()
    }

    fn tmp_files(&self) -> Vec<std::path::PathBuf> {
        files_in(&data_dir(&self.tmp).join("tmp"))
    }
}

/// A key at an exact arrival time (common::key(n) is MS + n ms, all in one second).
fn key_at(ms: i64, n: i64) -> String {
    format!("msg:{ms:013}:00000000-0000-4000-8000-{n:012}")
}

fn gaps(times: &[Duration]) -> Vec<Duration> {
    times.windows(2).map(|w| w[1] - w[0]).collect()
}

// ---------------------------------------------------------------------------------------------
// One pass (poll_once)

#[tokio::test]
async fn happy_path_delivers_inbox_uid_1_then_deletes() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    let r = e.poll().await.unwrap();
    assert_eq!(r, PassReport { lists: 1, delivered: 1, deleted: 1, ..Default::default() });

    let mb = e.inbox();
    let msgs = e.store.messages(mb).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].uid, 1);
    let expected = [format!("Return-Path: <{FROM}>\r\n").as_bytes(), BODY].concat();
    assert_eq!(read_message(&e.store, mb, 1), expected, "Return-Path prepended, body byte-exact");
    let file_len = std::fs::metadata(data_dir(&e.tmp).join(&msgs[0].blob)).unwrap().len();
    assert_eq!(msgs[0].size, file_len, "RFC822.SIZE = blob file length");
    assert_eq!(msgs[0].size, expected.len() as u64);
    assert_eq!(msgs[0].internal_date, (MS + 1) / 1000, "INTERNALDATE from the key's ms");
    assert!(e.store.is_delivered(&key(1)).unwrap());

    assert!(e.fake.keys().is_empty(), "acked");
    let order: Vec<(String, String)> = e.fake.requests().into_iter().map(|r| (r.method, r.path)).collect();
    let k = Env::msg_path(&key(1));
    assert_eq!(
        order,
        vec![("GET".into(), "/messages".into()), ("GET".into(), k.clone()), ("DELETE".into(), k)],
        "list, fetch, then DELETE only after delivery"
    );
    assert!(e.tmp_files().is_empty(), "download removed after delivery");
}

#[tokio::test]
async fn body_is_stored_byte_exact_across_many_tls_records() {
    let mut e = env(None).await;
    // 300 KB with bare LF, NUL, CR alone and 8-bit bytes: nothing may be normalised.
    let mut body = b"Subject: raw\nX-Bin: \x00\xff\r\n\r\n".to_vec();
    body.extend((0..300_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    e.fake.put(&key(1), FROM, "test@example.com", &body);
    assert_eq!(e.poll().await.unwrap().delivered, 1);
    let stored = read_message(&e.store, e.inbox(), 1);
    assert!(stored.ends_with(&body));
    assert_eq!(stored.len(), body.len() + format!("Return-Path: <{FROM}>\r\n").len());
}

#[tokio::test]
async fn commit_failure_means_no_delete_and_a_clean_retry() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.store.set_failpoint(Some(Failpoint::BeforeCommit));
    let r = e.poll().await.unwrap();
    assert_eq!((r.delivered, r.failed, r.deleted), (0, 1, 0));
    assert!(e.deletes(&key(1)).is_empty(), "no DELETE without a committed copy");
    assert_eq!(e.fake.keys(), vec![key(1)]);
    assert!(e.store.messages(e.inbox()).unwrap().is_empty());
    assert!(!e.store.is_delivered(&key(1)).unwrap());

    let r = e.poll().await.unwrap();
    assert_eq!((r.delivered, r.deleted), (1, 1));
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 1, "exactly one copy");
    assert!(e.fake.keys().is_empty());
}

#[tokio::test]
async fn a_delivered_key_listed_again_is_not_fetched_again() {
    // E.g. the DELETE was lost before a restart: the key is in `handoff` but still in KV.
    let mut e = env(None).await;
    deliver(&e.store, 1, "test@example.com", BODY).unwrap();
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    let r = e.poll().await.unwrap();
    assert_eq!((r.already_delivered, r.delivered, r.deleted), (1, 0, 1));
    assert_eq!(e.gets(&key(1)), 0, "never fetched again");
    assert_eq!(e.deletes(&key(1)).len(), 1);
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 1, "no second copy");
}

#[tokio::test]
async fn incomplete_lists_are_drained_at_once() {
    let mut e = env(None).await;
    for n in 1..=5 {
        e.fake.put(&key(n), FROM, "test@example.com", BODY);
    }
    e.fake.with(|s| s.page_size = Some(2));
    let r = e.poll().await.unwrap();
    assert_eq!((r.lists, r.delivered, r.deleted), (3, 5, 5), "pages of 2, 2, 1 in one pass");
    assert!(e.fake.keys().is_empty());
    let uids: Vec<u32> = e.store.messages(e.inbox()).unwrap().iter().map(|m| m.uid).collect();
    assert_eq!(uids, vec![1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn an_incomplete_list_without_progress_does_not_spin() {
    // complete:false forever and every fetch fails: the pass must end instead of burning the
    // 1,000-lists-a-day KV quota.
    let mut e = env(None).await;
    for n in 1..=2 {
        e.fake.put(&key(n), FROM, "test@example.com", BODY);
        e.fake.with(|s| s.get_status.insert(key(n), 500));
    }
    e.fake.with(|s| s.never_complete = true);
    let r = e.poll().await.unwrap();
    assert_eq!(r.failed, 2);
    assert!(r.lists <= 2, "{} lists in one pass", r.lists);
    assert!(e.fake.keys().len() == 2 && e.deletes(&key(1)).is_empty());
}

#[tokio::test]
async fn unknown_recipient_is_quarantined_recorded_and_acked() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "nobody@elsewhere.test", BODY);
    let r = e.poll().await.unwrap();
    assert_eq!((r.quarantined, r.delivered, r.deleted), (1, 0, 1));
    let q = files_in(&data_dir(&e.tmp).join("unrouted"));
    assert_eq!(q.len(), 1);
    assert!(std::fs::read(&q[0]).unwrap().ends_with(BODY));
    assert!(e.store.is_delivered(&key(1)).unwrap(), "recorded in handoff");
    assert!(e.store.messages(e.inbox()).unwrap().is_empty());
    assert!(e.fake.keys().is_empty(), "acked: nothing is lost, it sits in unrouted/");
}

#[tokio::test]
async fn v0_messages_without_an_envelope_are_quarantined_not_lost() {
    // A v0 Worker sends no X-SSM-Envelope-To: the poller cannot route, so the message
    // goes to unrouted/ and is acked.
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.v0 = true);
    let r = e.poll().await.unwrap();
    assert_eq!((r.quarantined, r.deleted), (1, 1));
    assert_eq!(files_in(&data_dir(&e.tmp).join("unrouted")).len(), 1);
}

#[tokio::test]
async fn uids_ascend_in_key_order_with_internaldate_from_each_key() {
    let mut e = env(None).await;
    let times = [MS, MS + 61_000, MS + 3_600_000];
    let keys: Vec<String> = times.iter().enumerate().map(|(i, ms)| key_at(*ms, i as i64)).collect();
    for (i, k) in keys.iter().enumerate() {
        e.fake.put(k, FROM, "test@example.com", format!("Subject: {i}\r\n\r\n{i}\r\n").as_bytes());
    }
    e.fake.with(|s| s.reverse_list = true); // newest first: the poller must order by key itself
    assert_eq!(e.poll().await.unwrap().delivered, 3);
    let msgs = e.store.messages(e.inbox()).unwrap();
    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(m.uid, i as u32 + 1);
        assert_eq!(m.internal_date, times[i] / 1000, "uid {} INTERNALDATE", m.uid);
        assert!(read_message(&e.store, e.inbox(), m.uid).ends_with(format!("\r\n\r\n{i}\r\n").as_bytes()));
    }
}

#[tokio::test]
async fn tagged_uppercase_and_utf8_envelopes_route_to_the_inbox() {
    let mut e = env(None).await;
    e.store.add_address("\u{161}ef@example.com", "test@example.com").unwrap();
    for (n, rcpt) in [(1, "test+news@example.com"), (2, "TEST@EXAMPLE.COM"), (3, "\u{160}ef@example.com")] {
        e.fake.put(&key(n), FROM, rcpt, BODY);
    }
    let r = e.poll().await.unwrap();
    assert_eq!((r.delivered, r.quarantined), (3, 0));
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 3);
}

#[tokio::test]
async fn size_mismatch_is_not_delivered_or_acked_and_leaves_no_tmp_file() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.kv.get_mut(&key(1)).unwrap().size_header = Some((BODY.len() + 7).to_string()));
    let r = e.poll().await.unwrap();
    assert_eq!((r.failed, r.delivered, r.deleted), (1, 0, 0));
    assert!(e.deletes(&key(1)).is_empty());
    assert!(e.tmp_files().is_empty());
    assert!(!e.store.is_delivered(&key(1)).unwrap());
    // Fixed on the Worker side: the next pass delivers it.
    e.fake.with(|s| s.kv.get_mut(&key(1)).unwrap().size_header = None);
    assert_eq!(e.poll().await.unwrap().delivered, 1);
}

#[tokio::test]
async fn gone_and_malformed_keys_are_counted_and_not_deleted() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.put(&key(2), FROM, "test@example.com", BODY);
    e.fake.put("msg:garbage", FROM, "test@example.com", BODY);
    e.fake.with(|s| s.get_status.insert(key(1), 404)); // acked meanwhile / expired
    let r = e.poll().await.unwrap();
    assert_eq!((r.gone, r.skipped, r.delivered), (1, 1, 1));
    assert_eq!(e.gets("msg:garbage"), 0, "a key without a 13-digit time is not fetched");
    assert!(e.deletes("msg:garbage").is_empty(), "nor deleted: nothing is destroyed, KV's TTL removes it");
    assert!(!e.store.is_delivered(&key(1)).unwrap());
}

#[tokio::test]
async fn list_failures_are_errors_of_the_pass() {
    let mut e = env(None).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.unauthorized_until = Some(hours(1)));
    assert!(matches!(e.poll().await, Err(ApiError::Unauthorized)));
    e.fake.with(|s| {
        s.unauthorized_until = None;
        s.list_status = Some(503)
    });
    assert!(matches!(e.poll().await, Err(ApiError::Status(503))));
    assert!(e.store.messages(e.inbox()).unwrap().is_empty());
    assert_eq!(e.gets(&key(1)), 0);
}

// ---------------------------------------------------------------------------------------------
// The loop (run) on a simulated clock

#[test]
fn backoff_delay_doubles_from_the_interval_up_to_30_minutes() {
    let s = Duration::from_secs;
    assert_eq!(MAX_BACKOFF, s(1800));
    let got: Vec<Duration> = (0..=5).map(|n| inbound::backoff_delay(s(120), n)).collect();
    assert_eq!(got, vec![s(120), s(240), s(480), s(960), s(1800), s(1800)]);
    assert_eq!(inbound::backoff_delay(s(600), 1), s(1200));
    assert_eq!(inbound::backoff_delay(s(600), 2), s(1800));
    // No overflow panic after days of failures.
    assert_eq!(inbound::backoff_delay(s(120), 64), s(1800));
    assert_eq!(inbound::backoff_delay(s(120), u32::MAX), s(1800));
}

#[tokio::test]
async fn quota_guard_at_most_720_lists_in_24_hours() {
    let mut e = env(Some(hours(24))).await;
    e.run().await;
    let lists = e.fake.lists();
    assert!(lists.len() <= 720, "{} lists in 24 h (KV free tier: 1,000 a day)", lists.len());
    assert!(lists.len() >= 700, "it must keep polling: {} lists", lists.len());
    assert!(gaps(&lists).iter().all(|g| *g >= INTERVAL), "never faster than every 120 s");
}

#[tokio::test]
async fn unauthorized_backs_off_to_30_minutes_then_recovers() {
    let mut e = env(Some(hours(6))).await;
    e.fake.with(|s| s.unauthorized_until = Some(hours(3)));
    e.run().await;
    let lists = e.fake.lists();
    let (failing, ok): (Vec<Duration>, Vec<Duration>) = lists.iter().partition(|t| **t < hours(3));
    let g = gaps(&failing);
    assert!(g[0] > INTERVAL, "backs off after the first 401: {g:?}");
    assert!(g.windows(2).all(|w| w[1] >= w[0]), "never shorter again while failing: {g:?}");
    assert!(g.iter().all(|d| *d <= MAX_BACKOFF), "capped at 30 min: {g:?}");
    assert_eq!(*g.last().unwrap(), MAX_BACKOFF, "reaches the cap: {g:?}");
    assert!(failing.len() <= 12, "{} lists in 3 h of 401s", failing.len());
    // First list after the token works again is at most 30 min late; then back to every 120 s.
    assert!(ok[0] - *failing.last().unwrap() <= MAX_BACKOFF);
    assert!(gaps(&ok).iter().all(|d| *d == INTERVAL), "{:?}", gaps(&ok));
    assert!(ok.len() >= 75);
}

#[tokio::test]
async fn server_errors_back_off_too() {
    let mut e = env(Some(hours(2))).await;
    e.fake.with(|s| s.list_status = Some(503));
    e.run().await;
    let lists = e.fake.lists();
    assert!(lists.len() <= 9, "{} lists in 2 h of 503s (60 without backoff)", lists.len());
    assert!(lists.len() >= 3);
}

#[tokio::test]
async fn failed_delete_is_retried_after_10_minutes_without_a_second_copy() {
    let mut e = env(Some(mins(15))).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.delete_failures.insert(key(1), 1));
    e.run().await;
    let d = e.deletes(&key(1));
    assert_eq!(d.len(), 2, "one failed DELETE, one retry: {d:?}");
    assert!(d[1] - d[0] >= REDELETE_INTERVAL, "{d:?}");
    assert!(e.fake.keys().is_empty());
    assert_eq!(e.gets(&key(1)), 1, "fetched once");
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 1);
}

#[tokio::test]
async fn a_relisted_delivered_key_gets_delete_at_most_once_per_10_minutes() {
    assert_eq!(REDELETE_INTERVAL, mins(10));
    let mut e = env(Some(hours(1))).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.delete_failures.insert(key(1), u32::MAX));
    e.run().await;
    let d = e.deletes(&key(1));
    assert!((2..=7).contains(&d.len()), "{} DELETEs in 1 h (30 passes): {d:?}", d.len());
    assert!(gaps(&d).iter().all(|g| *g >= REDELETE_INTERVAL), "{d:?}");
    assert_eq!(e.gets(&key(1)), 1);
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 1, "never a second copy");
}

#[tokio::test]
async fn stale_lists_after_a_delete_cost_no_extra_requests() {
    // KV list is eventually consistent: a deleted key can be listed again for a while.
    let mut e = env(Some(mins(15))).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    e.fake.with(|s| s.stale_lists_after_delete = 3);
    e.run().await;
    assert_eq!(e.deletes(&key(1)).len(), 1);
    assert_eq!(e.gets(&key(1)), 1);
    assert_eq!(e.store.messages(e.inbox()).unwrap().len(), 1);
}

#[tokio::test]
async fn mail_arriving_between_passes_is_picked_up_on_the_next_pass() {
    let mut e = env(Some(mins(10))).await;
    e.fake.put(&key(1), FROM, "test@example.com", BODY);
    let clock = e.clock.clone().unwrap();
    let fake_state = e.fake.state.clone();
    // A second message lands in KV once simulated time passes 5 min; the arrival time is recorded.
    let arrived = Arc::new(std::sync::Mutex::new(None));
    let arrived_w = arrived.clone();
    let watcher = tokio::spawn(async move {
        loop {
            let now = inbound::Clock::now(&*clock);
            if now >= mins(5) {
                let mut s = fake_state.lock().unwrap();
                s.kv.insert(
                    key(2),
                    StoredMsg { body: BODY.to_vec(), from: Some(FROM.into()), to: Some("test@example.com".into()), size_header: None },
                );
                *arrived_w.lock().unwrap() = Some(now);
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    e.run().await;
    watcher.abort();
    let arrived = arrived.lock().unwrap().expect("the watcher ran before the limit");
    let uids: Vec<u32> = e.store.messages(e.inbox()).unwrap().iter().map(|m| m.uid).collect();
    assert_eq!(uids, vec![1, 2]);
    let t2 = e.fake.requests().into_iter().find(|r| r.method == "GET" && r.path == Env::msg_path(&key(2))).unwrap().at;
    assert!(t2 >= arrived && t2 - arrived <= INTERVAL, "fetched on the first pass after arrival ({arrived:?}): {t2:?}");
}
