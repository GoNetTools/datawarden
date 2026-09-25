# syntax=docker/dockerfile:1
# Copyright 2026 The datawarden Authors
# SPDX-License-Identifier: Apache-2.0
#
# Multi-arch image (linux/amd64, linux/arm64). The binary is cross-compiled
# with cgo (tree-sitter) on the build platform, so no emulation is needed.
# The runtime image keeps the Go toolchain (the Go frontend type-checks with
# go/packages) and git (for --diff).

FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
RUN set -eux; \
    case "$TARGETARCH:$(dpkg --print-architecture)" in \
      amd64:amd64|arm64:arm64) pkgs="" ;; \
      arm64:*) pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      amd64:*) pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ -n "$pkgs" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $pkgs && rm -rf /var/lib/apt/lists/*; \
    fi
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN set -eux; \
    case "$TARGETARCH:$(dpkg --print-architecture)" in \
      amd64:amd64|arm64:arm64) export CC=gcc ;; \
      arm64:*) export CC=aarch64-linux-gnu-gcc ;; \
      amd64:*) export CC=x86_64-linux-gnu-gcc ;; \
    esac; \
    GOOS="$TARGETOS" GOARCH="$TARGETARCH" bash scripts/release/build.sh "$VERSION" /out; \
    cp "/out/${TARGETOS}_${TARGETARCH}/datawarden" /out/datawarden; \
    bash scripts/third-party-licenses.sh > /out/THIRD_PARTY_LICENSES.txt

FROM golang:1.27-trixie
LABEL org.opencontainers.image.title="datawarden" \
      org.opencontainers.image.description="Finds sensitive data (PII, PHI, card data, credentials) flowing to logs, analytics/crash SDKs and third parties" \
      org.opencontainers.image.source="https://github.com/GoNetTools/pii-scanner" \
      org.opencontainers.image.licenses="Apache-2.0"
# CI checkouts are often owned by another user; let git (for --diff) read them.
COPY <<EOT /etc/gitconfig
[safe]
	directory = *
EOT
COPY --from=build /out/datawarden /usr/local/bin/datawarden
COPY --from=build /out/THIRD_PARTY_LICENSES.txt /usr/share/doc/datawarden/
COPY LICENSE NOTICE /usr/share/doc/datawarden/
WORKDIR /src
ENTRYPOINT ["datawarden"]
CMD ["scan", "."]
