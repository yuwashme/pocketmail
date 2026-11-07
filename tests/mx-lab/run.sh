#!/bin/sh
# Run with an architecture-matched static Linux binary. No published host ports.
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
test -x "$bin"
image=ssm-private-mx-lab
lab=ssm-mx-$$
nodes=""
cleanup() {
    for node in $nodes; do docker rm -f "$node" >/dev/null 2>&1 || true; done
    docker network rm "$lab" >/dev/null 2>&1 || true
}
docker build -q -t "$image" "$base" >/dev/null
docker network create --internal --subnet 172.29.231.0/24 "$lab" >/dev/null
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
start() {
    role=$1; address=$2
    docker run -d --network "$lab" --ip "172.29.231.$address" --dns 172.29.231.10 --name "$lab-$role" -v "$bin:/usr/local/bin/ssm:ro" "$image" "$role" >/dev/null
    nodes="$lab-$role $nodes"
}
start dns 10
start sink 13
start mx 12
start sender 11
mx="$lab-mx"; sender="$lab-sender"; sink="$lab-sink"
wait_for() {
    count=0
    until "$@" >/dev/null 2>&1; do
        count=$((count+1))
        if [ "$count" -ge 85 ]; then
            for node in $nodes; do docker logs --tail 12 "$node"; docker exec "$node" tail -12 /var/log/mail.log 2>/dev/null || true; done
            return 1
        fi
        sleep 2
    done
}
for node in "$sender" "$mx" "$sink"; do wait_for docker exec "$node" postfix status; done
test "$(docker exec "$sender" dig +short MX mailbox.test)" = '10 mx.mailbox.test.'
test "$(docker exec "$mx" dig +short MX outside.test)" = '10 mx.outside.test.'
echo 'Private DNS resolved both MX records.'
docker exec -i "$sender" python3 - <<'PY'
import smtplib
with smtplib.SMTP('mx.mailbox.test',25,timeout=10) as s:
 s.ehlo()
 assert s.mail('user@origin.test')[0]==250
 assert s.rcpt('recipient@outside.test')[0] in (550,554)
PY
echo 'MX refused unauthorized third-party relay.'
send_probe() {
    printf 'From: user@origin.test\nTo: person@mailbox.test\nSubject: %s\n\n%s\n' "$1" "$1" |
        docker exec -i "$sender" /usr/sbin/sendmail -i -f user@origin.test -- person@mailbox.test
}
db=/home/ssm/data/ssm.db
send_probe MX-LOCAL-COPY
wait_for docker exec "$mx" python3 -c "import sqlite3;assert sqlite3.connect('$db').execute('select subject from messages').fetchall()==[('MX-LOCAL-COPY',)]"
echo 'Postfix delivered the first message to the local inbox.'
docker exec "$mx" python3 -c "import sqlite3;c=sqlite3.connect('$db');c.execute(\"update mailboxes set forward_to='recipient@outside.test',keep_copy=0\");c.commit()"
send_probe MX-FORWARD-ONLY
wait_for docker exec "$sink" grep -q MX-FORWARD-ONLY /var/mail/recipient
docker exec -i "$mx" python3 - <<'PY'
import sqlite3
from pathlib import Path
d=Path('/home/ssm/data')
c=sqlite3.connect(d/'ssm.db')
assert c.execute('select subject from messages').fetchall()==[('MX-LOCAL-COPY',)]
assert c.execute("select state,forward_blob from outbox where queue_only").fetchall()==[('Accepted',None)]
assert len(list((d/'blobs').rglob('*.eml')))==1
PY
echo 'Forward arrived at the independent destination. No inbox copy or queued body remains.'
