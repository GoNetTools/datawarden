#!/usr/bin/env bash
# Copyright 2026 The pii-scanner Authors
# SPDX-License-Identifier: Apache-2.0
#
# Prints the license texts of everything compiled into the pii-scanner binary
# (the Go standard library and every module dependency, for all release
# platforms). Release archives and the container image ship the output as
# THIRD_PARTY_LICENSES.txt. Fails if a dependency has no license file.
set -euo pipefail
cd "$(dirname "$0")/.."

main=$(go list -m)
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

paths=$(for t in $targets; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=1 \
    go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/pii-scanner
done | sort -u | grep -vx "$main" || true)

rule() { printf '%s\n' "================================================================================"; }

echo "The pii-scanner binary and container image include the following third-party software."
echo "pii-scanner itself is licensed under the Apache License 2.0 (see LICENSE and NOTICE)."
echo

goroot=$(go env GOROOT)
rule
echo "Go standard library and runtime ($(go env GOVERSION))"
echo "https://go.dev"
rule
cat "$goroot/LICENSE"
if [ -f "$goroot/PATENTS" ]; then echo; cat "$goroot/PATENTS"; fi
echo

if [ -n "$paths" ]; then
  # shellcheck disable=SC2086 # word splitting of module paths is intended
  go mod download $paths
  # shellcheck disable=SC2086
  go list -m -f '{{.Path}} {{.Version}} {{.Dir}}' $paths | while read -r path version dir; do
    files=$(find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) | sort)
    if [ -z "$files" ]; then
      echo "no license file found for $path $version in $dir" >&2
      exit 1
    fi
    rule
    echo "$path $version"
    echo "https://pkg.go.dev/$path"
    rule
    first=1
    while IFS= read -r f; do
      [ "$first" -eq 1 ] || echo
      first=0
      cat "$f"
    done <<< "$files"
    echo
  done
fi
