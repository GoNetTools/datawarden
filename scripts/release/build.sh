#!/usr/bin/env bash
# Copyright 2026 The piiflow Authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds one release binary with cgo, so all frontends (Go, Kotlin, Java,
# TypeScript) are included.
#
#   scripts/release/build.sh <version> [outdir]
#
# The target is GOOS/GOARCH from the environment (default: this machine);
# set CC for cross builds (e.g. CC="clang -arch x86_64" on an arm64 Mac).
# Writes <outdir>/<goos>_<goarch>/piiflow[.exe] (default outdir: dist/bin).
set -euo pipefail
cd "$(dirname "$0")/../.."

version=${1:?usage: scripts/release/build.sh <version> [outdir]}
out=${2:-dist/bin}
goos=$(go env GOOS)
goarch=$(go env GOARCH)
module=$(go list -m)

ext=""
tags=""
ldflags="-s -w -X ${module}/internal/app.Version=${version}"
case "$goos" in
  linux|windows)
    # Link statically: Linux binaries then run on any glibc or musl distro,
    # Windows binaries need no MinGW runtime DLLs.
    tags="netgo,osusergo"
    ldflags="$ldflags -linkmode=external -extldflags=-static"
    ;;
  darwin)
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
    ;;
esac
[ "$goos" = windows ] && ext=".exe"

dest="$out/${goos}_${goarch}"
mkdir -p "$dest"
CGO_ENABLED=1 go build -trimpath -tags "$tags" -ldflags "$ldflags" -o "$dest/piiflow$ext" ./cmd/piiflow
echo "$dest/piiflow$ext"
