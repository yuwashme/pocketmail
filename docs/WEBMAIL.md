# Using webmail

Open **https://mail.example.org** and sign in with your full mailbox name and mail password.
Choose a subject to read a message. **Account settings** shows which addresses deliver to you
and lets you change your password. **Write a message** opens the composer when outgoing delivery is configured. Large messages and attachments can be read with an IMAP app on the LAN.

To change a password from the server terminal, set `SSM_DATA_DIR` and run `synology-mail-server account passwd me@example.org`.

## Manage accounts on your home network

Open the settings listener (by default, HTTPS on port 8443 of your NAS) and sign in as a **mail-server admin**. A DSM login alone does not grant mail-admin rights. The public mailbox site has no admin pages.

| Task | Where to go |
| --- | --- |
| Create a mailbox | **Accounts → Add an account**. Use the full email address as the user name. On the new account page, use **Addresses → Add address** to route that address to its inbox. |
| Add another local address | **Accounts → choose the receiving mailbox → Addresses**. Adding an alias routes incoming mail to that mailbox; it does not forward a copy externally. |
| Reset another user's password | **Accounts → choose the mailbox → Password → Set password**. Existing web sessions for that account end. |
| Change your own password | **Your account** in settings, or **Account settings** in webmail. |
| Set storage | **Accounts → choose the mailbox → Mailbox settings → Storage limit (MiB)**. Mailboxes start at 1024 MiB (1 GiB). Enter a whole number to change it, or leave blank for unlimited. Existing mail counts toward the limit. Lowering the limit keeps all current messages. |
| Forward incoming mail | In **Mailbox settings**, select a verified address under **Forward to**, then choose **Save mailbox settings**. Choose **Keep a copy in this inbox** or **Forward only**. Choose **Off** to stop forwarding. In forward-only mode the NAS temporarily holds the body until the relay accepts it. |

Full mailboxes reject local sends and defer upstream deliveries for retry. Forwarding applies to new deliveries, skips automatic messages and bounces, and sends the original as an attached email. The Outbox shows the relay result. With copy mode the original remains in the inbox. Forward-only defers new deliveries when the queue is full. On failed or uncertain submissions the queue retains the body for recovery. Bounces and loop-suppressed mail go to the inbox subject to its quota.

On the server, set `SSM_VERIFIED_FORWARD_TO` to a comma-separated list of externally verified recipients and `SSM_FORWARD_FROM` to the relay-authorized sender. Restart the service after changing these settings. Only list addresses the provider has already verified. The Cloudflare relay enforces its own verified-recipient restriction on each submission.

With Postfix as an unrestricted outbound transport, set `SSM_FORWARD_POLICY=external` to let the admin enter an external recipient directly. Keep the verified-only default when using the Cloudflare free relay. The MX record controls inbound routing independently of these settings.

To create another administrator, check **Make this account an admin** under **Add an account** or open an existing account and select **Access → Make admin**.

With no active admin, the server logs a one-time setup link that lets the owner create a dedicated admin. Use it on your home network and keep it private. Alternatively, create a dedicated account and promote it using the CLI on the NAS:

    synology-mail-server account add mailadmin
    synology-mail-server account admin mailadmin on

Enter the new password at the terminal prompt. The admin account does not need an email address to manage mailboxes.

## Choose how to run the server

| Setting | NAS using Cloudflare | Independent mail host |
| --- | --- | --- |
| Incoming mail | The Worker holds new mail until the NAS pulls it. | A local Postfix SMTP service receives mail and delivers it to SSM. |
| Browser access | The tunnel connects to a private HTTPS listener on the NAS. | Serve browser HTTPS yourself, or run your own reverse proxy in front of the loopback mailbox listener. |
| Outgoing mail | Webmail sends from sender@example.org to verified external destinations and delivers directly to exact local mailboxes. | Set the path to Postfix's sendmail program to enable sending from webmail. |
| Accounts and storage | Local SSM accounts and SQLite on disk. | The same accounts, password prompts, and on-disk mailboxes. |

### Browser access through the NAS tunnel

Use `SSM_WEBMAIL_LISTEN=127.0.0.1:9443` in the start script. The normal settings listener
remains available for local administration. Publish only the mailbox listener over the tunnel.
Use HTTPS to the origin with its certificate as the trusted CA and a server name listed in
that certificate. Keep origin TLS verification enabled. The public site uses mailbox passwords.
The Cloudflare Tunnel carries browser requests. Incoming email follows the domain's MX records.

### Cloudflare-independent installation

On a host you control, install Postfix and SSM. Give the dedicated service user (called
`ssm` below) exclusive access to the data directory. Configure SSM with a TLS certificate
for your chosen host, its private key, and `SSM_DATA_DIR=/var/lib/ssm`.
Omit the Worker URL and token. IMAP and browser sign-in use the local store.
For a reverse proxy, use the loopback mailbox listener and preserve the public Host and Origin.
Only a trusted local Cloudflare connector should supply CF-Connecting-IP; remove that header
when proxying client requests yourself.

Point the mail domain's MX at a publicly reachable SMTP hostname with an address record.
On the independent host, configure Postfix for the recipient domain with a virtual mailbox map
of accepted addresses. Keep the normal SMTP relay restrictions for external destinations.
For example, for a dedicated installation that owns example.org, use these main.cf settings:

    virtual_mailbox_domains = example.org
    virtual_mailbox_maps = hash:/etc/postfix/ssm-recipients
    virtual_transport = ssm
    ssm_destination_recipient_limit = 1
    enable_long_queue_ids = yes
    message_size_limit = 25000000
    smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

Add each accepted address to SSM and to the Postfix map, for example
`person@example.org OK` in /etc/postfix/ssm-recipients, then run
`postmap /etc/postfix/ssm-recipients`. Use this master.cf transport with Postfix 2.11 or later:

    ssm unix - n n - 2 pipe
      flags=D user=ssm null_sender= eol=\r\n
      argv=/usr/bin/env SSM_DATA_DIR=/var/lib/ssm /usr/local/bin/synology-mail-server deliver ${queue_id} ${sender} ${recipient}

Run `postfix check` before reloading Postfix. A repeated queue delivery for the same recipient
is deduplicated. Temporary delivery failures stay in the SMTP queue for retry.
The standalone mail host needs working port 25 for direct internet delivery and appropriate
PTR, SPF, DKIM and DMARC settings for its own sending IP and domain.

To enable **Write a message**, set `SSM_SENDMAIL=/usr/sbin/sendmail` for SSM and restart it.
The authenticated user needs an explicit sending address matching their login. Messages are
handed to the Postfix queue; queue acceptance is reported separately from delivery.
Set the queue's outgoing rate and delivery policies before enabling sending.

[Postfix pipe transport](https://www.postfix.org/pipe.8.html)

### Outgoing mail on the NAS

Sign in as sender@example.org. Choose **Write a message**, or open a message and choose **Reply**.
Reply fills in the recipient and subject and includes the original message ID for threading.
An exact local mailbox receives its messages immediately. For other addresses, the NAS
starts a small HTTPS helper on demand. Set ALLOWED_SENDER in the outbound Worker configuration to your own sending address (for example sender@example.org). The Worker submits messages from that address
to Cloudflare Email Routing's verified destinations.
For general internet recipients, configure an authorized SMTP relay or the local Postfix queue.

The Worker is in `worker/outbound/`. Its `SUBMIT_TOKEN` secret matches the bearer token in
the NAS user's private `~/ssm/outbound.curl`. The run script sets `SSM_SENDMAIL` to the
absolute path of `submit.sh`. Keep the curl configuration readable only by the server user.


### Delivery status

After sending an external message, choose **Outbox** to see its status. *Queued* means the
server saved it for sending. *Accepted* means the relay took it. *Failed* means delivery was
refused or the retry limit was reached. For *Check delivery*, ask the recipient before sending
again: the server lost confirmation and the message might already have arrived.

The server sleeps between submissions. A definite temporary refusal is retried with increasing
delays (up to five attempts). The queue limits each account to 20 pending submissions and 100
submissions per rolling 24 hours. Status history is pruned on submission. Local recipients
normally receive their message immediately.

For operators, `SSM_PASSWORD_JOBS=1` limits simultaneous Argon2 work to one 12 MiB workspace.
Use `2` for faster bursts on machines with more RAM. Both settings use the same password hashes.
