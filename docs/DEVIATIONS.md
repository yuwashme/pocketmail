# Deviations from the RFCs

Where the server knowingly differs from the letter of the IMAP and mail RFCs, and why.


## IMAP (RFC 3501)

- **No STARTTLS, no plaintext port** (RFC 3501 6.2.1, RFC 8314): implicit TLS only.
- **NUL bytes are replaced with 0x80 in output.** A literal may not carry NUL. Stored messages
  are never altered; the replacement is byte for byte, so RFC822.SIZE, partial offsets and
  BODYSTRUCTURE sizes all stay consistent with the bytes sent. Dovecot does the same.
- **A message without a blank line after its header** is treated as all header: HEADER and
  RFC822.HEADER return the whole message, TEXT returns "".
- **SEARCH nesting is limited to 9 levels** (imap-codec 1.0 parser limit); deeper commands get BAD.
- **Header strings are returned as written.** ENVELOPE and BODYSTRUCTURE keep RFC 2047 encoded
  words, which the RFC requires anyway. Raw 8-bit header bytes are sent in a literal rather than
  being decoded.
- **An address without a domain** gets the host `MISSING_DOMAIN` (as in Dovecot). A NIL host would
  read as the start of a group.
- **SEARCH text matching is case-insensitive for ASCII only** (RFC 3501 6.4.4 leaves the method to
  the server). Header values are matched after RFC 2047 decoding, bodies after transfer and
  charset decoding; `Štefan` matches only with that exact case of `Š`.
- **SEARCH BODY / TEXT look at text parts only** (text/*, nested messages included); attachments
  (base64 images, PDFs) are not searched.
- **SENTBEFORE / SENTON / SENTSINCE never match a message without a valid Date header** (Dovecot
  falls back to INTERNALDATE; RFC 3501 says nothing).
- **SEARCH with a sequence number past EXISTS matches nothing** instead of BAD (FETCH and STORE do
  answer BAD).
- **INBOX only.** APPEND accepts synchronizing literals up to 25 MiB and streams them to disk. COPY and UID COPY can target the existing INBOX. STORE supports the Deleted flag. EXPUNGE and read-write CLOSE remove marked messages. CREATE, RENAME, DELETE mailbox and MOVE remain unavailable.
- **`serve` runs without TLS, with IMAP off and a warning.** `tests/cli.rs` needs `serve` to start
  and idle with only `SSM_DATA_DIR`. Startup does refuse, with exit 1 and a message, when the
  TLS files or the pull token file are set but missing, unreadable or empty, or when the IMAP listen
  address cannot be bound. The TLS and token checks run before the store is opened. The web
  listener is on by default (`0.0.0.0:8443`); if its address cannot be bound, `serve` logs a
  warning and runs without it, so a taken port never stops mail. `SSM_WEB_LISTEN=off` turns it off.
- **tokio gets the `signal` feature** (adds `signal-hook-registry` 1.4.8), for a clean SIGINT/SIGTERM
  shutdown. Running store calls get 10 s to finish.
- **The binary keeps the name `synology-mail-server`.** Renaming it to `ssm` would break
  `tests/cli.rs`, which uses `CARGO_BIN_EXE_synology-mail-server`.


## Settings web UI (HTTP/1.1, RFC 9110 and 9112)

- **Chunked request bodies get 501.** Any request with `Transfer-Encoding` is refused (400 if it
  also has `Content-Length`). Browsers send the small forms with `Content-Length`, and bodies are
  limited to 16 KiB, so chunked decoding is not worth its code.
- **HEAD is supported** and answered like GET without the body. PUT, DELETE, PATCH, OPTIONS, TRACE and
  CONNECT get 405; other methods get 501.
- **No HSTS header.** The certificate is usually self-signed, and HSTS would take away the
  browser's option to accept it.
- **No Host allow-list.** Any Host is served. Access is decided by the peer address, and a POST must
  carry an Origin equal to `https://` plus its Host. `Referrer-Policy: same-origin` (not
  `no-referrer`) keeps that Origin: with `no-referrer` Chrome sends `Origin: null` on form posts.
- **A peer outside the home network gets no HTTP answer.** Unless `SSM_WEB_ALLOW_PUBLIC=yes`, it is
  disconnected before the TLS handshake instead of getting a 403. Tailscale (100.64.0.0/10) and
  global IPv6 addresses are outside it.
- **Proxied requests get 403.** Behind a reverse proxy the peer address is the proxy's, so the
  home-network check cannot hold. Unless `SSM_WEB_ALLOW_PUBLIC=yes`, a request carrying
  `Forwarded`, `X-Forwarded-For`, `X-Real-IP` or `CF-Connecting-IP` is refused. A proxy that
  sends none of them still makes every client look local.
- **Already-open IMAP connections are not cut** when an account is disabled or its password
  changes; only new logins fail. Web sessions do end, checked on every request.
- **The web sign-in limit does not apply to IMAP.** Failed web sign-ins are counted per client address
  and per user name, in memory. IMAP logins are not counted there.
- **The web interface is off without TLS files.** There is no plain HTTP port; `serve` logs a warning.
