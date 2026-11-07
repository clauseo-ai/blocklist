#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fetch the currently published asset and print its entry count, or "none"
# when there is no asset yet (HTTP 404: the first publish).
#
#   scripts/previous-count.sh <work dir>
#
# The old asset is trusted only after its signature verifies with the
# committed minisign.pub. Any other outcome is a failure.
set -euo pipefail

dir=${1:?usage: previous-count.sh <work dir>}
base=${ASSET_BASE:-https://github.com/clauseo-ai/blocklist/releases/download/current}
pub=${MINISIGN_PUB:-minisign.pub}

if [ ! -s "$pub" ]; then
  echo "error: $pub is missing or empty; refusing to continue" >&2
  exit 1
fi

mkdir -p "$dir"
gz="$dir/blocklist-v1.txt.gz"
sig="$gz.minisig"

code=$(curl -sS -L --retry 3 -o "$gz" -w '%{http_code}' "$base/blocklist-v1.txt.gz")
if [ "$code" = 404 ]; then
  echo "no current asset (HTTP 404): first publish, the 50 % drop rule is skipped" >&2
  echo none
  exit 0
fi
if [ "$code" != 200 ]; then
  echo "error: fetching the current asset gave HTTP $code" >&2
  exit 1
fi
code=$(curl -sS -L --retry 3 -o "$sig" -w '%{http_code}' "$base/blocklist-v1.txt.gz.minisig")
if [ "$code" != 200 ]; then
  echo "error: the current asset exists but its .minisig gave HTTP $code" >&2
  exit 1
fi

if ! comment=$(minisign -V -p "$pub" -m "$gz" -x "$sig" -Q); then
  echo "error: the current asset's signature does not verify with $pub" >&2
  exit 1
fi
count=$(gzip -dc "$gz" | grep -vc '^#' || true)
signed=${comment##*entries=}
if [ "$count" != "$signed" ]; then
  echo "error: current asset has $count entries but its trusted comment says $signed" >&2
  exit 1
fi
echo "current asset: $comment" >&2
echo "$count"
