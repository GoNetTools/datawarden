# Copyright 2026 The piiflow Authors
# SPDX-License-Identifier: Apache-2.0

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
MODULE      := $(shell go list -m)
LDFLAGS     := -s -w -X $(MODULE)/internal/app.Version=$(VERSION)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1

.PHONY: build build-nocgo test test-nocgo race vet lint headers check release-local docker scan-self clean

## build: full binary (Go + Kotlin + Java + TypeScript); needs a C compiler
build:
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/piiflow ./cmd/piiflow

## build-nocgo: portable binary with the Go frontend and literal detector only
build-nocgo:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/piiflow-nocgo ./cmd/piiflow

test:
	CGO_ENABLED=1 go test ./...

test-nocgo:
	CGO_ENABLED=0 go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

vet:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)
	CGO_ENABLED=1 go vet ./...
	CGO_ENABLED=0 go vet ./...

lint:
	go run $(STATICCHECK) ./...

headers:
	bash scripts/check-headers.sh

## check: everything CI's lint and test jobs run
check: vet lint headers test test-nocgo

## release-local: release archives for this machine's platform in dist/
release-local:
	bash scripts/release/build.sh $(VERSION) dist/bin
	bash scripts/release/package.sh dist/bin dist

docker:
	docker build --build-arg VERSION=$(VERSION) -t piiflow:$(VERSION) .

scan-self: build
	./bin/piiflow scan . --no-fail

clean:
	rm -rf bin dist
