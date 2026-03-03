#!/usr/bin/env zsh
set -euo pipefail

cd /Users/sandra/OpenHealth-Core

READER="${READER:-$(
  cargo run -q -p healthcard-apdu-tools --bin apdu_record --features pcsc -- --list-readers \
    | sed -n '2p' | sed 's/^  //'
)}"

if [[ -z "${READER}" ]]; then
  echo "Kein PC/SC Reader gefunden." >&2
  exit 1
fi

case "${1:-}" in
  contactless)
    cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- \
      --reader "${READER}" \
      --can 123123 \
      --out ./pace-contactless.jsonl
    ;;
  contact-based)
    cargo run -p healthcard-apdu-tools --bin apdu_record --features "pcsc trusted-channel" -- \
      --reader "${READER}" \
      --out ./trusted-channel.jsonl \
      --trusted-channel \
      --select-private-key \
      --trusted-channel-verbose
    ;;
  *)
    echo "Usage: $0 {contactless|contact-based}"
    exit 2
    ;;
esac
