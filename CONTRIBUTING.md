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

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the pipeline, the layers and the interfaces between components; the README's [Development](README.md#development) section has the full layout. The rules that keep the code testable:

- **Components talk only through interfaces.** A package declares the small interface it needs next to the code that uses it (`scan` declares `FileLister`, `Frontends`, `Analyzer`; `cli` declares `Scanner`, `Policy`, `Reporter`, ...), and the other package implements it. `TestComponentsTalkThroughInterfaces` (in `internal/app`) fails on any call into another component's concrete functions or methods. Calls into `ir`, `finding` and `lang` are fine: they are the shared vocabulary. To use a new service, add an interface where you need it, a field to inject it, and the wiring in `internal/app`.
- **Only `internal/app` builds concrete types**, and only `internal/platform` touches the OS (files, `git`, the cache on disk). Everything else reads files through `fs.FS` and receives its clock, environment and HTTP client.
- **No `init()` registration and no package-level mutable state.** Frontends are added to a `frontend.Registry` in `app.NewComponents`; the name taxonomy is passed to `detect.NewClassifier`.
- **Tests use fakes and in-memory filesystems** (`fstest.MapFS`, `httptest`). End-to-end tests over the fixtures live in `internal/app`.

## Common contributions

### Report a false positive or a missed leak

Use the issue templates. The most useful report is a **minimal snippet** (synthetic data) plus the piiflow output line, which names the rule (`[sdk.ts.sentry.set_user]`), data type and confidence.

### Add or fix a rule

Built-in rules are YAML files in `internal/rules/builtin/` (`go.yaml`, `jvm.yaml`, `typescript.yaml`, `sources.yaml`, `transforms.yaml`), embedded in the binary. The README's [Sink rules](README.md#sink-rules) section documents the fields. Rule files are read strictly: a misspelt key, an unknown `lang` or an id defined twice in one file is an error.

1. **Write the rule.** Give it a stable, dotted id. Sinks start with their category (`log.`, `sdk.`, `net.`, `storage.`, `ipc.`), sources with `src.` and transforms with `xform.`: for example `sdk.<lang>.<vendor>.<call>`. Ids are part of baseline fingerprints, so don't rename existing ones. A source rule must produce a data type from the taxonomy. `TestBuiltinRuleConventions` checks all of this.
2. **Add an example** under `internal/rules/testdata/examples/<language>/`. Write the call the way real code writes it, and annotate the line above it:

   ```kotlin
   // ruleid: sdk.acme.telemetry
   Telemetry.send("signup", mapOf("email" to email))
   // ok: sdk.acme.telemetry
   Telemetry.send("order", mapOf("orderId" to orderId))
   ```

   `ruleid:` means the next line must produce a finding for that rule; `ok:` means it must not produce a violation. Every violation in an example file must be annotated. If an idiomatic form isn't caught yet, mark it `todoruleid:` (or `todook:` for a known false positive) and open an issue: the test fails as soon as the gap is fixed, so the markers never go stale. Go examples import third-party SDKs through small stubs in `internal/rules/testdata/gostubs/`; add one with a `replace` line in `examples/go/go.mod`.
3. **Run** `go test ./internal/app -run TestRuleExamples`. It also fails when any built-in rule has no example.
4. If a fixture under `testdata/` exercises the rule, label the flow in `testdata/eval.yaml`.

A rule for one repository's own SDK belongs in that repository's `.piiflow/rules/*.yaml`. Test it the same way: put annotated examples in `.piiflow/rules/examples/` (scans never report that directory) and run `piiflow rules test .piiflow/rules/examples`.

### Keep the accuracy corpus honest

`testdata/eval.yaml` labels what a reviewer would report in each fixture, not what piiflow reports today. When you add or change a fixture, label every real leak in it, including ones piiflow misses (add a `note`), and use `ambiguous` only for flows that are genuinely acceptable either way. `go run ./cmd/piiflow-bench -check` (`make eval`) prints precision, recall and every miss and false positive. Raise `min_precision`/`min_recall` when your change improves them; lowering one needs a reason in the pull request.

### Add a data type or identifier name

The taxonomy (identifier words, negative context words, transforms) is in `internal/detect/taxonomy.go`; the literal validators are in `internal/detect/literal.go`. Add table-driven cases to `internal/detect/detect_test.go`.

### Add a language

A new language touches five places, and a test checks each one:

1. **Describe it** in `internal/lang/lang.go`: name, aliases, file extensions, test-file suffixes. The file walker, config validation and rule loading all read this table (`TestTableIsConsistent`).
2. **Write the frontend.** Implement `frontend.Frontend`: lower each source file to the IR in `internal/ir` (functions, named and typed variables, calls with qualified callee names, field loads and stores, type declarations with their fields). The tree-sitter frontends in `internal/frontend/treesitter` are the easiest model to copy; `common.go` holds their shared helpers.
3. **Register it** in `app.NewComponents`, and as unavailable in builds that cannot include it, the way the tree-sitter languages are without cgo (`TestEveryLanguageIsWired`).
4. **Port the conformance programs.** Copy `internal/frontend/testdata/conformance/go` to `internal/frontend/testdata/conformance/<language>` and translate each `scenario:` function. The scenarios are the constructs the taint engine relies on: parameters, locals, string building, fields, getters, map and object keys, helper calls, return values, closures, field stores, collections, whole objects, masking, and three non-PII cases. Mark a construct the frontend can't lower yet with `todoruleid:` (`TestFrontendConformance`).
5. **Add rules** with the new `lang`, each with an example as described above, and a fixture under `testdata/` labelled in `testdata/eval.yaml` so the accuracy report covers the language.

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
