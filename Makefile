# Copyright 2026 The datawarden Authors
# SPDX-License-Identifier: Apache-2.0

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
MODULE      := $(shell go list -m)
LDFLAGS     := -s -w -X $(MODULE)/internal/app.Version=$(VERSION)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1

.PHONY: build build-nocgo test test-nocgo race vet lint headers check eval eval-external bench release-local docker scan-self clean

## build: full binary (Go + Kotlin + Java + TypeScript); needs a C compiler
build:
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/datawarden ./cmd/datawarden

## build-nocgo: portable binary with the Go frontend and literal detector only
build-nocgo:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/datawarden-nocgo ./cmd/datawarden

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

## eval: precision/recall/F1 and scan timings on the labelled corpus (testdata/eval.yaml)
eval:
	CGO_ENABLED=1 go run ./cmd/datawarden-bench -runs 3 -check

## eval-external: eval plus the open-source apps pinned in testdata/eval.yaml (fetched with git)
eval-external:
	CGO_ENABLED=1 go run ./cmd/datawarden-bench -runs 1 -check -external

## bench: Go benchmarks (engine scaling, detectors, end-to-end fixture scans)
bench:
	CGO_ENABLED=1 go test -run '^$$' -bench . -benchmem ./...

## release-local: release archives for this machine's platform in dist/
release-local:
	bash scripts/release/build.sh $(VERSION) dist/bin
	bash scripts/release/package.sh dist/bin dist

docker:
	docker build --build-arg VERSION=$(VERSION) -t datawarden:$(VERSION) .

scan-self: build
	./bin/datawarden scan . --no-fail

clean:
	rm -rf bin dist
