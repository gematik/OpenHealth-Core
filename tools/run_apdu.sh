# SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik,
# find details in the "Readme" file.

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
