#!/bin/sh
set -eu
if [ "$1" = dns ]; then
    exec dnsmasq --no-daemon --no-resolv --no-hosts --local=/test/ \
        --mx-host=mailbox.test,mx.mailbox.test,10 --host-record=mx.mailbox.test,172.29.231.12 \
        --mx-host=outside.test,mx.outside.test,10 --host-record=mx.outside.test,172.29.231.13
fi
postconf -e 'inet_protocols = ipv4' 'mydestination = localhost' 'mynetworks = 127.0.0.0/8' 'relayhost =' 'smtp_host_lookup = dns' 'smtp_tls_security_level = none' 'smtpd_relay_restrictions = permit_mynetworks,reject_unauth_destination' 'maillog_file = /var/log/mail.log'
# The SMTP clients must see the container's private DNS resolver.
sed -i -E '/^[^#[:space:]]+[[:space:]]+(inet|unix|fifo|pass)/s/^(([^[:space:]]+[[:space:]]+){4})[^[:space:]]+/\1n/' /etc/postfix/master.cf
case "$1" in
sender) postconf -e 'myhostname = sender.origin.test' ;;
sink) postconf -e 'myhostname = mx.outside.test' 'mydestination = outside.test,localhost'
      useradd -m recipient ;;
mx) postconf -e 'myhostname = mx.mailbox.test' 'virtual_mailbox_domains = mailbox.test' 'virtual_mailbox_maps = hash:/etc/postfix/targets' 'virtual_transport = ssm' 'ssm_destination_recipient_limit = 1' 'enable_long_queue_ids = yes'
    useradd -m ssm
    export SSM_DATA_DIR=/home/ssm/data SSM_SENDMAIL=/usr/sbin/sendmail SSM_FORWARD_POLICY=external SSM_FORWARD_FROM=forward@mailbox.test SSM_WEB_LISTEN=off
    printf '%s\n' 'person@mailbox.test OK' 'postmaster@mailbox.test OK' >/etc/postfix/targets
    postmap /etc/postfix/targets
    cat >>/etc/postfix/master.cf <<'PIPE'
ssm unix - n n - 2 pipe
  flags=D user=ssm null_sender= eol=\r\n
  argv=/usr/local/bin/ssm deliver ${queue_id} ${sender} ${recipient}
PIPE
    # The pipe daemon does not inherit arbitrary environment variables.
    sed -i 's|argv=/usr/local/bin/ssm|argv=/usr/bin/env SSM_DATA_DIR=/home/ssm/data /usr/local/bin/ssm|' /etc/postfix/master.cf
    runuser -u ssm -- sh -c 'head -c 32 /dev/urandom | base64 | /usr/local/bin/ssm account add person@mailbox.test'
    runuser -u ssm -- /usr/local/bin/ssm address add person@mailbox.test person@mailbox.test
    runuser -u ssm -- /usr/local/bin/ssm address add postmaster@mailbox.test person@mailbox.test
    runuser -u ssm -- /usr/local/bin/ssm serve &
    ;;
esac
exec postfix start-fg
