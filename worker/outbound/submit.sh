#!/bin/sh
# Called with Postfix-compatible arguments by the authenticated webmail process.
set -eu
[ "$#" -eq 5 ] && [ "$1" = -i ] && [ "$2" = -f ] && [ "$4" = -- ] || exit 64
# Supply a length and stream binary MIME to the relay without buffering an attachment in RAM.
umask 077
message=$(mktemp "${TMPDIR:-/tmp}/ssm-submit.XXXXXX") || exit 75
trap 'rm -f "$message"' EXIT
cat > "$message" || exit 75
status=$(curl --silent --show-error --write-out "%{http_code}" --connect-timeout 5 --max-time 25 \
  --config "$HOME/ssm/outbound.curl" --header "X-Envelope-From: $3" \
  --header "X-Envelope-To: $5" --header 'Content-Type: message/rfc822' \
  --request POST --upload-file "$message" --output /dev/null) || {
  case $? in 6|7) exit 75 ;; *) exit 76 ;; esac
}
case "$status" in
  204) exit 0 ;;
  429) exit 75 ;;
  4??) exit 65 ;;
  *) exit 76 ;; # Outcome unknown; automatic retry could deliver twice.
esac
