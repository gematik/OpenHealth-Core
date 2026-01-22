#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

set -eu

BASE_REF="${1:-origin/main}"
HEAD_REF="${2:-HEAD}"

if tmp_file="$(mktemp 2>/dev/null)"; then
  :
else
  tmp_file="$(mktemp -t reuse-annotate-changed)"
fi
tmp_lines_file="${tmp_file}.lines"
tmp_existing_file="${tmp_file}.existing"

cleanup() {
  rm -f "$tmp_file" "$tmp_lines_file" "$tmp_existing_file"
}
trap cleanup EXIT INT TERM

git diff -z --name-only "$BASE_REF" "$HEAD_REF" -- ':(exclude)LICENSES/**' >"$tmp_file"

if [ ! -s "$tmp_file" ]; then
  printf '%s\n' "No changed files between $BASE_REF and $HEAD_REF."
  exit 0
fi

# Filter out deleted paths so reuse annotate does not fail on missing files.
: >"$tmp_existing_file"
while IFS= read -r -d '' file; do
  [ -e "$file" ] || continue
  printf '%s\0' "$file" >>"$tmp_existing_file"
done <"$tmp_file"

if [ ! -s "$tmp_existing_file" ]; then
  printf '%s\n' "No existing changed files between $BASE_REF and $HEAD_REF."
  exit 0
fi

xargs -0 reuse annotate \
  --license Apache-2.0 \
  --copyright "gematik GmbH" \
  --template gematik \
  --copyright-prefix spdx-string \
  --merge-copyrights \
  --skip-unrecognised \
  <"$tmp_existing_file"

tr '\0' '\n' <"$tmp_existing_file" >"$tmp_lines_file"

# Special handling for changed files with unusual/unrecognised comment styles.
# Format: path|style|mode(single-line|multi-line)
SPECIAL_STYLE_FILES="
core-modules/asn1/src/spec/cvc_schema.txt|haskell|single-line
"

printf '%s' "$SPECIAL_STYLE_FILES" | while IFS='|' read -r file style mode; do
  [ -n "$file" ] || continue
  grep -Fqx "$file" "$tmp_lines_file" || continue

  case "$mode" in
    single-line) mode_flag="--single-line" ;;
    multi-line) mode_flag="--multi-line" ;;
    *) mode_flag="" ;;
  esac

  if [ -n "$mode_flag" ]; then
    reuse annotate \
      --style "$style" \
      "$mode_flag" \
      --license Apache-2.0 \
      --copyright "gematik GmbH" \
      --template gematik \
      "$file"
  else
    reuse annotate \
      --style "$style" \
      --license Apache-2.0 \
      --copyright "gematik GmbH" \
      --template gematik \
      "$file"
  fi
done
