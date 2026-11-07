#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Verify a minisign signature with the committed minisign.pub and check that
# the signed trusted comment is exactly the expected one.
#
#   scripts/verify.sh <file> <signature> <expected trusted comment>
#
# Fails closed: a missing or empty minisign.pub is an error.
set -euo pipefail

file=${1:?usage: verify.sh <file> <signature> <expected comment>}
sig=${2:?usage: verify.sh <file> <signature> <expected comment>}
expected=${3:?usage: verify.sh <file> <signature> <expected comment>}
pub=${MINISIGN_PUB:-minisign.pub}

if [ ! -s "$pub" ]; then
  echo "error: $pub is missing or empty; refusing to continue" >&2
  exit 1
fi

# -Q prints only the trusted comment, after both signatures verified
if ! got=$(minisign -V -p "$pub" -m "$file" -x "$sig" -Q); then
  echo "error: signature on $file does not verify with $pub" >&2
  exit 1
fi
if [ "$got" != "$expected" ]; then
  echo "error: trusted comment mismatch" >&2
  echo "  expected: $expected" >&2
  echo "  got:      $got" >&2
  exit 1
fi
echo "verified $file: $got"
