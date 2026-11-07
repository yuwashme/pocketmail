# Test standalone MX delivery

From the repository root, start Docker and supply a static Linux app binary matching the Docker engine architecture. On Apple Silicon with Colima:

    colima start
    cargo zigbuild --release --target aarch64-unknown-linux-musl
    tests/mx-lab/run.sh target/aarch64-unknown-linux-musl/release/synology-mail-server

For an x86-64 Docker engine use an x86_64-unknown-linux-musl binary. The first run downloads Debian and Postfix. The lab creates an internal Docker network (172.29.231.0/24) and four temporary containers. It publishes no ports and changes no public DNS records. Allow about three minutes for an already-built image. The server may take up to two minutes to notice a new job created by the separate Postfix delivery process.

The sender queries private DNS for mailbox.test and delivers by SMTP to its Postfix MX. A separate unauthorized relay request must fail. The test first checks ordinary local delivery. It then enables forward-only for a synthetic mailbox, sends another message, and checks delivery through the outbound Postfix queue to the MX for outside.test. The destination receives the message, the first original remains in the app inbox, and the second body is removed from the queue after relay acceptance. Containers and network are removed on exit.

Public-MX testing uses a dedicated subdomain with its own MX and A/AAAA records, an SMTP listener reachable on TCP/25, configured recipient maps including postmaster, and an outbound transport permitted by the network provider. Check from a separate network. Your production domain can keep its existing MX throughout.
