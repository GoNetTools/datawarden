#!/usr/bin/env bash
# Copyright 2026 The pii-scanner Authors
# SPDX-License-Identifier: Apache-2.0
#
# Packages the binaries from build.sh into release archives.
#
#   scripts/release/package.sh <bindir> <outdir>
#
# <bindir> holds <goos>_<goarch>/pii-scanner[.exe] directories. Writes
# pii-scanner_<goos>_<goarch>.tar.gz (.zip for Windows), each with the binary,
# LICENSE, NOTICE, THIRD_PARTY_LICENSES.txt, README.md and CHANGELOG.md, plus
# checksums.txt. Asset names carry no version so that
# releases/latest/download/<asset> always works (the GitHub Action uses it).
set -euo pipefail

bindir=${1:?usage: scripts/release/package.sh <bindir> <outdir>}
out=${2:?usage: scripts/release/package.sh <bindir> <outdir>}
root=$(cd "$(dirname "$0")/../.." && pwd)
bindir=$(cd "$bindir" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)

# Reproducible archives: fixed timestamps, owners and file order.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export TZ=UTC

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$root/scripts/third-party-licenses.sh" > "$work/THIRD_PARTY_LICENSES.txt"

shopt -s nullglob
found=0
for dir in "$bindir"/*_*/; do
  target=$(basename "$dir")
  stage="$work/$target"
  mkdir -p "$stage"
  cp "$dir"/pii-scanner* "$stage/"
  chmod 0755 "$stage"/pii-scanner*
  cp "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$root/CHANGELOG.md" "$work/THIRD_PARTY_LICENSES.txt" "$stage/"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  files=$(cd "$stage" && ls | sort)
  name="pii-scanner_${target}"
  case "$target" in
    windows_*)
      # shellcheck disable=SC2086 # file names contain no spaces
      (cd "$stage" && zip -q -X "$out/$name.zip" $files)
      ;;
    *)
      # shellcheck disable=SC2086
      tar -C "$stage" --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -cf - $files | gzip -n -9 > "$out/$name.tar.gz"
      ;;
  esac
  found=$((found + 1))
done

if [ "$found" -eq 0 ]; then
  echo "no <goos>_<goarch> directories in $bindir" >&2
  exit 1
fi

cd "$out"
assets=(pii-scanner_*.tar.gz pii-scanner_*.zip)
sha256sum "${assets[@]}" > checksums.txt
cat checksums.txt
