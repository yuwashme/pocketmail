mod browser;
mod harness;
mod net;

use browser::*;
use synology_mail_server::store::Delivery;

#[tokio::test]
async fn tunnel_serves_only_the_signed_in_mailbox() {
    let h = WebHarness::start_with(|c| {
        c.mailbox_only = true;
        c.allow_public = true;
    })
    .await;
    assert!(h.server.setup_path().is_none());
    let alice = "alice@example.org";
    let bob = "bob@example.org";
    h.user(alice);
    h.user(bob);
    let raw =
        b"From: sender@example.org\r\nSubject: A <notice>\r\n\r\nPrivate <script>mail</script>";
    h.store
        .deliver(
            &Delivery {
                key: "webmail-test",
                envelope_from: "sender@example.org",
                envelope_to: alice,
                expected_size: raw.len() as u64,
                received_ms: 1_780_000_000_000,
            },
            &mut raw.as_slice(),
        )
        .unwrap();
    assert_eq!(h.get("/inbox").await.status, 303);
    assert_eq!(h.get("/setup").await.status, 404);
    let mut a = h.browser();
    assert_eq!(
        a.sign_in(alice, &harness::password(alice))
            .await
            .header("location"),
        Some("/inbox")
    );
    assert!(a.get("/inbox").await.text().contains("A &lt;notice&gt;"));
    assert!(
        a.get("/message?uid=1")
            .await
            .text()
            .contains("Private &lt;script&gt;")
    );
    assert_eq!(a.get("/accounts").await.status, 404);
    let mut b = h.browser();
    b.sign_in(bob, &harness::password(bob)).await;
    assert_eq!(b.get("/message?uid=1").await.status, 404);
}
