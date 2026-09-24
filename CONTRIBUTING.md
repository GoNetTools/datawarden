# Contributing to piiflow

Thanks for helping. Bug reports, false-positive and missed-leak reports, new sink rules and new language frontends are all welcome.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through the private process in [SECURITY.md](SECURITY.md), not public issues.

## Never commit or paste real personal data

This is a PII scanner, so issues, pull requests and fixtures are full of phone numbers, ID numbers and emails. **Use synthetic values only.**

- Invent values that still pass validation: an unallocated phone number with a valid carrier prefix, a CCCD with a valid province code, a card number that passes Luhn, `@example.com` emails.
- Put fixture files under `testdata/` (excluded in `.piiflowignore`) so piiflow's own CI scan does not flag them.
- When you paste piiflow output into an issue, the values are already masked. Keep them that way.

## Development setup

You need:

- **Go**: the version in `go.mod` or newer. CI tests the current and previous Go releases.
- **A C compiler**, for the tree-sitter frontends (Kotlin, Java, TypeScript) which use cgo: `gcc` or `clang` on Linux/macOS, MinGW-w64 `gcc` on Windows. Without one, `CGO_ENABLED=0` still builds the Go frontend and the literal detector.
- `git`, for `--diff` mode and its tests.

```sh
git clone https://github.com/GoNetTools/pii-scanner && cd pii-scanner
go test ./...                    # everything (cgo)
CGO_ENABLED=0 go test ./...      # Go frontend + literal detector only
go build -o bin/piiflow ./cmd/piiflow && ./bin/piiflow scan testdata/web --root testdata/web --no-baseline
```

`make` wraps the common commands (`make test test-nocgo vet lint build`).

Before opening a pull request, the same checks CI runs:

```sh
gofmt -l cmd internal                                           # must print nothing
go vet ./... && CGO_ENABLED=0 go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go test -race ./...
scripts/check-headers.sh                                        # SPDX header on every Go file
```

## How the code is organised

The README's [Development](README.md#development) section has the full layout. The rules that keep the code testable:

- **Interfaces belong to the package that uses them.** `scan` declares the `Frontends`, `Analyzer` and `VCS` it needs; `cli` declares `Scanner` and `Workspace`.
- **Only `internal/app` builds concrete types**, and only `internal/platform` touches the OS (files, `git`, the cache on disk). Everything else reads files through `fs.FS` and receives its clock, environment and HTTP client.
- **No `init()` registration and no package-level mutable state.** Frontends are added to a `frontend.Registry` in `app.NewComponents`; the name taxonomy is passed to `detect.NewClassifier`.
- **Tests use fakes and in-memory filesystems** (`fstest.MapFS`, `httptest`). End-to-end tests over the fixtures live in `internal/app`.

## Common contributions

### Report a false positive or a missed leak

Use the issue templates. The most useful report is a **minimal snippet** (synthetic data) plus the piiflow output line, which names the rule (`[sdk.ts.sentry.set_user]`), data type and confidence.

### Add or fix a sink rule

Built-in rules are YAML files in `internal/rules/builtin/` (`go.yaml`, `jvm.yaml`, `typescript.yaml`, `sources.yaml`, `transforms.yaml`), embedded in the binary. The README's [Sink rules](README.md#sink-rules) section documents the fields.

1. Add the rule with a stable, dotted `id` (`sdk.<lang>.<vendor>.<call>`); ids are part of baseline fingerprints, so don't rename existing ones.
2. Add a case to a fixture under `testdata/` that the rule should catch, and one it should not, then add the expected flow to the fixture's test in `internal/app` (`expectFlows`) and label it in `testdata/eval.yaml`.
3. `go run ./cmd/piiflow rules --lang <lang>` lists the loaded rules.

### Keep the accuracy corpus honest

`testdata/eval.yaml` labels what a reviewer would report in each fixture, not what piiflow reports today. When you add or change a fixture, label every real leak in it, including ones piiflow misses (add a `note`), and use `ambiguous` only for flows that are genuinely acceptable either way. `go run ./cmd/piiflow-bench -check` (`make eval`) prints precision, recall and every miss and false positive. Raise `min_precision`/`min_recall` when your change improves them; lowering one needs a reason in the pull request.

### Add a data type or identifier name

The taxonomy (English and Vietnamese names, negative context words, transforms) is in `internal/detect/taxonomy.go`; the literal validators are in `internal/detect/literal.go`. Add table-driven cases to `internal/detect/detect_test.go`.

### Add a language

Implement `frontend.Frontend` (lower the language to the IR in `internal/ir`), expose `Register(*frontend.Registry)`, call it from `app.NewComponents`, add rules with that `lang`, and add a fixture under `testdata/`. Tree-sitter frontends in `internal/frontend/treesitter` are the easiest model to copy.

## Pull requests

- Keep each pull request to one change, with tests. CI must be green on Linux, macOS and Windows.
- Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- New Go files start with the license header:

  ```go
  // Copyright 2026 The piiflow Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- Contributions are accepted under the [Apache License 2.0](LICENSE), the project's license (section 5 of the license).

## Releasing (maintainers)

1. Move the **Unreleased** entries in `CHANGELOG.md` under the new version and merge that to `main`.
2. Tag and push: `git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`.
3. The `release` workflow tests the tag, builds the binaries (linux/macOS/windows, amd64/arm64), publishes the GitHub Release with checksums, pushes `ghcr.io/gonettools/piiflow`, and moves the `v0` tag that `uses: GoNetTools/pii-scanner@v0` resolves to. Tags with a suffix (`v0.2.0-rc.1`) become pre-releases and leave `v0` and `latest` alone.
