# Pocketmail

A small IMAP mail server for a Synology NAS. One static Rust
binary, about 3 MB, a few MB of RAM when idle.

Mail arrives through a Cloudflare Email Worker (`worker/`) that stores each message; the server pulls
them over outbound HTTPS, so the NAS needs no open inbound port. Messages are kept as files, with
mailboxes, UIDs and flags in SQLite. Clients read mail over IMAP with implicit TLS.

Webmail provides a browser inbox, text message reader, and account settings. An optional local
Postfix queue enables sending from webmail and standalone SMTP delivery. See the
[webmail and independent-host setup](docs/WEBMAIL.md). IMAP supports reading, marking
read/starred, and search. APPEND, COPY, UID COPY, and EXPUNGE are supported within INBOX. Creating additional folders and MOVE are still unavailable.
See the [standalone MX lab](tests/mx-lab/README.md). Detailed deviations are listed in [docs/DEVIATIONS.md](docs/DEVIATIONS.md).

## Build

    cargo build --locked --release
    export PATH="$PWD/target/release:$PATH"
    cargo test --locked

For the NAS: `cargo zigbuild --release --target aarch64-unknown-linux-musl`.

## Run

    # Choose a private data directory and supply a TLS certificate and key.
    export SSM_DATA_DIR=/path/to/data
    synology-mail-server account add me@example.com
    synology-mail-server address add me@example.com me@example.com
    SSM_TLS_CERT=cert.pem SSM_TLS_KEY=key.pem synology-mail-server serve

`synology-mail-server` without arguments prints all commands and `SSM_*` variables. Set `SSM_PULL_URL` and
`SSM_PULL_TOKEN_FILE` to pull from a deployed Worker; see `worker/wrangler.toml` for its setup.

Connect your IMAP client to the server on port 9993 using implicit TLS and the account you created.

## Settings UI

A small web interface for accounts, served by the same binary over HTTPS.

- It is on by default, on `SSM_WEB_LISTEN` (default `0.0.0.0:8443`), and uses the same certificate
  files as IMAP (`SSM_TLS_CERT`, `SSM_TLS_KEY`). Without them the web interface is off. If its
  address cannot be bound (the port is taken), `serve` logs a warning and runs without it. Set
  `SSM_WEB_LISTEN=off` to turn it off.
- By default only clients on the home network are served: loopback, private (RFC 1918, RFC 4193) and
  link-local addresses. Others, Tailscale (100.64.0.0/10) and global IPv6 addresses included, are
  disconnected before the TLS handshake. Set `SSM_WEB_ALLOW_PUBLIC=yes` to serve everyone.
- The check uses the peer address, so behind a reverse proxy every client would look local. Unless
  `SSM_WEB_ALLOW_PUBLIC=yes`, a request with a `Forwarded`, `X-Forwarded-For`, `X-Real-IP` or
  `CF-Connecting-IP` header gets 403. Do not put the interface behind a proxy.
- With no active admin, `serve` logs a one-time setup link at start. It is valid for one hour and
  for one use, and either creates the first admin or makes an existing account one (with that
  account's password). Alternatively: `synology-mail-server account admin <login> on`. `off` removes
  admin rights; the last active admin cannot be removed.
- Every user can see the addresses delivering to their account and change their password.
  Admins can also list and add accounts, set a password, block and allow sign-in, make and remove
  admins, and add and remove addresses. Deleting an account is not available yet. The CLI cannot
  block sign-in; `account list` shows a blocked account as `DISABLED`. Mail apps already connected
  stay connected until they disconnect.
- Passwords set on the web need at least 12 characters; the CLI rules are unchanged.
- Sessions are kept in memory, so a restart signs everyone out. They end after 30 minutes idle or
  12 hours. Failed sign-ins are rate limited.
- This release upgrades the database to schema v6 with forwarding modes and a 1 GiB default mailbox quota. The upgrade applies this default to previously unlimited mailboxes and preserves existing positive limits. Back up the stopped data directory before upgrading. A v1 database is first
  copied to `ssm.db.v1.bak` next to it, or to `ssm.db.v1.<unix-seconds>.bak` if that name is
  taken. Any command of the new binary upgrades it too, `account list` included, even while an
  older `serve` is running.
- Cost: the aarch64 musl binary is 3,454,064 bytes, 178,304 more than without the web interface
  (3,275,760). Idle RSS on a Mac: 3,056 kB with the web listener on, 2,944 kB with it off.

### Rolling back a schema upgrade

Stop all writers and keep a copy of the current data directory. Restore the pre-upgrade
data directory together with its matching binary and configuration. Mail received after
that backup and newer outgoing queue records need reconciliation before replacing the
live store. An older binary cannot process pending submissions from the newer schema.

### Restoring the original v1 database

1. Stop the server.
2. Move `ssm.db-wal` and `ssm.db-shm` out of the data dir, if they exist.
3. Copy the newest `ssm.db.v1*.bak` over `ssm.db`.
4. Start the old binary.

Changes made since the upgrade are lost from the database: accounts, passwords and addresses go
back to their state at the upgrade, and mail delivered since keeps its file under `blobs/` but
loses its index rows, so IMAP no longer lists it.

## Inbound Worker setup

From `worker/`, use Wrangler with your own Cloudflare account. Create a KV namespace with `wrangler kv namespace create INBOX` and enable the sample binding in `wrangler.toml` with the returned ID. Set a generated secret with `wrangler secret put PULL_TOKEN`, then run `wrangler deploy`. Enable Email Routing for your domain and route the chosen recipient addresses to this Worker. On the server, store the same secret in a service-user-only file, set `SSM_PULL_TOKEN_FILE` to its path and `SSM_PULL_URL` to the Worker's HTTPS origin, then restart the service.

## Development and license

See [contribution guidance](CONTRIBUTING.md) and the [DSM package build instructions](packaging/README.md). Pocketmail is licensed under the [MIT License](LICENSE), copyright © 2026 Blaž Umek. Dependencies retain their [upstream notices](THIRD-PARTY-NOTICES.txt).
