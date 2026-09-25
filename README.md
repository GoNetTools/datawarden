# piiflow

[![ci](https://github.com/GoNetTools/pii-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/GoNetTools/pii-scanner/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/GoNetTools/pii-scanner?sort=semver)](https://github.com/GoNetTools/pii-scanner/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/GoNetTools/pii-scanner.svg)](https://pkg.go.dev/github.com/GoNetTools/pii-scanner)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

piiflow is a static analyzer that finds **personal data (PII) flowing into places it shouldn't go**: logs, crash reporters, analytics SDKs, third-party APIs, device storage and other apps. It also catches **real personal data committed to the repository** (fixtures, samples, seed files).

It understands Go, Kotlin, Java and TypeScript/JavaScript, recognises Vietnam-specific data (CCCD/CMND citizen IDs, BHXH/BHYT insurance numbers, Vietnamese mobile numbers), and is built for CI: SARIF for code scanning, a PR/MR comment, a baseline so only *new* problems fail the build, and an incremental PR mode.

```
$ piiflow scan --diff origin/main
piiflow v0.1.0 · diff scan vs origin/main · 2 files (typescript:2) · 5 functions · 17ms
changed: 1 files, callers: 1 files

NEW      high   phone → Sentry / sentry.io (third-party)  [sdk.ts.sentry.set_user]
         source  src/api/user.ts:22:32  field User.phoneNumber (field name phoneNumber)
         sink    src/lib/mask.ts:10:3  @sentry/react.addBreadcrumb  in src/lib/mask:logInfo
         path    src/api/user.ts:22 → src/lib/mask.ts:8 → :10
         confidence 0.90

1 new violation(s): 1 flow(s), 0 literal(s) · 9 baselined
```

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [How it works](#how-it-works)
- [Source detectors](#source-detectors)
- [Sink rules](#sink-rules)
- [Configuration](#configuration)
- [Baseline](#baseline)
- [CI integration](#ci-integration)
- [Pre-commit](#pre-commit)
- [Data map (DPIA)](#data-map-dpia)
- [Accuracy and limits](#accuracy-and-limits)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Install

The Kotlin, Java and TypeScript frontends use tree-sitter, whose Go bindings need **cgo**, so release binaries are built per platform:

| Option | Languages | Notes |
|---|---|---|
| [Release archive](https://github.com/GoNetTools/pii-scanner/releases/latest) `piiflow_<os>_<arch>` | all | linux amd64/arm64 (static), macOS amd64/arm64, windows amd64 |
| `docker run --rm -v "$PWD:/src" ghcr.io/gonettools/piiflow scan .` | all | linux amd64/arm64; includes Go and git |
| `CGO_ENABLED=1 go install github.com/GoNetTools/pii-scanner/cmd/piiflow@latest` | all | Go 1.26+ and a C compiler |
| `CGO_ENABLED=0 go install github.com/GoNetTools/pii-scanner/cmd/piiflow@latest` | Go + literal detector | no C compiler; tree-sitter languages are reported as skipped |

```sh
# Linux/macOS: download, verify and install the latest release
os=$(uname -s | tr A-Z a-z); arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
base=https://github.com/GoNetTools/pii-scanner/releases/latest/download
curl -sSfL -O "$base/piiflow_${os}_${arch}.tar.gz" -O "$base/checksums.txt"
grep " piiflow_${os}_${arch}.tar.gz$" checksums.txt | shasum -a 256 -c -
tar -xzf "piiflow_${os}_${arch}.tar.gz" piiflow && sudo install piiflow /usr/local/bin/
```

The Go frontend loads packages with `go/packages`, so scanning Go code needs the Go toolchain and the module's dependencies (as for `go build`).

## Quick start

```sh
piiflow init                      # writes .piiflow.yaml, .piiflowignore, .piiflow/rules/example.yaml
piiflow scan .                    # full scan, text report, exit 1 on violations
piiflow baseline                  # accept today's findings; commit .piiflow/baseline.json
piiflow scan --diff origin/main   # PR mode: changed files + their callers, only new findings fail
piiflow map --format dpia > docs/data-map.md
```

## Commands

| Command | What it does |
|---|---|
| `piiflow scan [paths...]` | Full scan, or only the given files/directories. |
| `piiflow scan --diff <ref>` | PR mode: files changed since the merge base with `<ref>` plus their callers, found through the cached call graph. |
| `piiflow scan --literals-only` | Only the committed-PII detector. `--staged` reads the git index (pre-commit). |
| `piiflow baseline` | Full scan; writes the current violations to the baseline. |
| `piiflow map --format dpia\|json\|csv\|mermaid` | Personal-data inventory. |
| `piiflow rules [--kind sink] [--lang kotlin]` | Effective rules (built-in + repository overrides). |
| `piiflow rules test DIR` | Checks annotated example code in `DIR` against the effective rules (see [Sink rules](#sink-rules)). |
| `piiflow comment piiflow.md` | Creates or updates the PR (GitHub) / MR (GitLab) comment. |
| `piiflow init` | Writes starter config files. |

Useful `scan` flags: `--format text|json|sarif|markdown|gitlab`, `--sarif FILE`, `--markdown FILE`, `--json FILE`, `--gitlab FILE` (write several reports in one run), `--baseline FILE`, `--no-baseline`, `--caller-depth N`, `--min-confidence F`, `--all`, `--no-cache`, `--no-fail`, `--verbose`, `--cpuprofile FILE`, `--memprofile FILE` (pprof profiles of the analysis; also on `baseline` and `map`). Flags can come before or after paths.

**Exit codes:** `0` no new violations · `1` at least one new policy violation · `2` error. CI only needs the exit code.

## How it works

```
 repo ──► Ingest ──► Frontends ──────────► IR ──► Detectors ──► Taint engine ──► Policy + Baseline ──► Reports
          .piiflowignore   Go: go/packages + SSA      sources: names,        per-function       violation? new?      text, JSON,
          --diff: changed  Kotlin/Java/TS:            schema hints,          summaries,                              SARIF, Markdown,
          files + callers  tree-sitter (cgo)          literals               SCC fixpoint,                           GitLab SAST, DPIA
          (call graph      ─ shared interface ─       sinks: YAML rules      cached by file hash
           cache)
```

- **Ingest** walks the repository, applies built-in ignores plus `.piiflowignore` (gitignore syntax, `!` re-includes), and classifies files by language. In PR mode it asks git for the files changed since the merge base and adds their callers (transitively, `--caller-depth`) from the call graph cached by the last full scan.
- **Frontends** implement one interface and lower code into a small common IR (variables and five instructions: assign, load, store, call, return):

  ```go
  type Frontend interface {
      Lang() string
      Lower(ctx context.Context, files []string) (*ir.Module, error)
  }
  ```

  - *Go* uses `golang.org/x/tools/go/packages` and `go/ssa` (with debug info for source names): callees and types are exact, struct tags come from the type checker, closures and interface calls are handled.
  - *Kotlin, Java, TypeScript/JavaScript* use tree-sitter with best-effort resolution: imports, declared types of parameters/locals/fields, constructor calls, `X.getInstance()` idioms, class hierarchies, extension functions, lambdas (as callbacks), string templates and named arguments.
- **Detectors** mark sources (below). **Sinks** come from YAML rules.
- **Taint engine**: each function is analyzed to a fixpoint with parameters as symbolic labels, which yields both concrete flows and a *summary* (parameter → return, parameter → sink, parameter → parameter, PII returned or written into arguments). Functions are processed callees-first by strongly connected component; recursion iterates until summaries stabilize. Summaries are cached by function ID and **validated by the content hash of the defining file**, so a PR scan re-analyzes only changed files and their callers and reuses everything else.
- Each flow carries data type, source, sink, rule, destination, path, transforms and confidence:

  ```go
  type Flow struct {
      DataType     string      // "email", "vn_cccd"
      Source, Sink ir.Pos
      SinkRule     string      // "sdk.sentry.set_user"
      Dest         Destination // host, kind, first-party?, region, vendor
      Path         []ir.Pos
      Transforms   []string    // "masked", "sha256"
      Confidence   float64
      // + Function, SourceDesc, Fingerprint, Violation, Severity, Baselined
  }
  ```

## Source detectors

**1. Identifier names.** Identifiers are split on camelCase, PascalCase, ACRONYMS, snake/kebab case and letter/digit boundaries. Token sequences are matched against a taxonomy of 23 data types, for example:

| Data type | Identifiers |
|---|---|
| `phone` | phone, phoneNumber, mobile, msisdn |
| `vn_cccd` | cccd, cccdNumber, cmnd |
| `person_name` | fullName, firstName, lastName |
| `dob` | dob, dateOfBirth, birthday |
| `address` | streetAddress, shippingAddress |
| `bank_account` | accountNumber, iban |
| `tax_id` | taxId, taxCode |
| `insurance_id` | socialInsurance, bhxh, bhyt |
| `license_plate` | licensePlate |

Names are matched as English words. Vietnam-specific documents keep their own acronyms (`cccd`, `cmnd`, `bhxh`, `bhyt`); other Vietnamese words (`soDienThoai`, `hoTen`, …) are not recognised.

Also email, IP address, national ID, US SSN, passport, driver's license, payment card, precise location, device/advertising IDs, gender, ethnicity, religion, health and biometric data. Sensitive categories (GDPR art. 9 / Decree 13/2023/ND-CP) are marked and raise severity.

Negative context avoids the usual noise: `emailValidator`, `isEmailValid`, `phoneFormatter`, `EMAIL_KEY`, `serverAddress`, `microphone`. Names that say the value is already protected carry a transform: `maskedPhone` → masked, `emailHash` → hashed.

String keys label their values: `put("email", x)`, `bundleOf("phone" to x)`, `zap.String("phone", x)`, `r.FormValue("cccd")`, `{ phone: x }`, `m["email"] = x`.

**2. Schema hints.** Field-level hints from:
- Go struct tags: `json`, `db`, `bson`, `gorm:"column:phone_number"`, `protobuf:"...,name=email"`; explicit `pii:"email"` or `pii:"-"` (not PII).
- JPA/Room/Moshi/Gson annotations: `@Column(name=...)`, `@ColumnInfo`, `@SerializedName`, `@JsonProperty`, `@Json`; explicit `@PII("email")`.
- TypeORM decorators (`@Column({ name: ... })`), TypeScript interfaces and type aliases.
- Protobuf messages (`string contact = 3 [(pii) = "phone"];` or `// pii: phone`).
- SQL migrations (`CREATE TABLE`, `ALTER TABLE ... ADD COLUMN`, `-- pii: phone` comments).

A value whose type is a data class/entity with PII fields (a `Customer`) carries those data types: `Sentry.setUser(customer)` is a flow. Service classes (repositories, view models) are excluded.

**3. Literal values** (committed PII), validated by format so random numbers don't match:

| Detector | Validation |
|---|---|
| Vietnamese mobile | `0`/`+84` + 9 digits, current carrier prefixes (03x, 05x, 07x, 08x, 09x), placeholders like `0123456789` rejected |
| CCCD | 12 digits, valid province code, century/gender digit, birth year not in the future; needs a label on the line (`cccd`, `cmnd`, ...) |
| CMND | 9 digits, only next to a label |
| Email | skips `example.com`, role accounts (`noreply@`, `support@`), author/copyright lines, npm scopes, Kotlin `this@label` |
| Payment card | Luhn + issuer prefix (Visa, Mastercard, Amex, JCB, UnionPay, NAPAS `9704`); well-known test cards skipped |
| IBAN | mod-97; documentation IBANs skipped |
| US SSN | area/group/serial rules; advertising SSNs skipped |

Reports never print the value, only a masked form (`091*****65`) and, in the baseline, a hash.

## Sink rules

Rules are YAML files embedded in the binary (`internal/rules/builtin/`: 89 rules for Go, Kotlin/Java and TypeScript). A repository adds, replaces or disables rules in `.piiflow/rules/*.yaml` (or any path listed under `rules:` in `.piiflow.yaml`).

```yaml
- id: sdk.sentry.set_user
  lang: kotlin                       # or a list: [kotlin, java]
  call: io.sentry.Sentry.setUser     # qualified callee; '*' is a wildcard; may be a list
  arg: 0                             # 0-based, receiver excluded; a list, or "*" for all
  dest: { host: sentry.io, kind: third_party, vendor: Sentry, region: us }

- id: sdk.acme.telemetry             # a repository-specific SDK
  lang: [kotlin, java]
  call: com.acme.telemetry.Telemetry.send
  receiver: "(?i)telemetry"          # optional: match unresolved receivers by name
  arg: "*"
  dest: { host: telemetry.acme.vn, kind: third_party }

- id: log.go.fmt_print               # same id as a built-in: replaced; here disabled
  disabled: true
```

Rule files are read strictly: a misspelt key, an unknown `lang` or an id defined twice in one file is an error, not a silently weaker rule.

**Test your rules** with annotated examples, the way the built-in rules are tested. Put code that uses the SDK in `.piiflow/rules/examples/` (scans never report that directory) and annotate each call on the line above it:

```kotlin
// ruleid: sdk.acme.telemetry
Telemetry.send("signup", mapOf("email" to email))
// ok: sdk.acme.telemetry
Telemetry.send("order", mapOf("orderId" to orderId))
```

`piiflow rules test .piiflow/rules/examples` scans the directory with the repository's rules and policy, and fails if an expected finding is missing, an `ok:` line is reported, or any violation is unannotated. `todoruleid:` and `todook:` record known misses and false positives. Every built-in rule has such an example in `internal/rules/testdata/examples/`.

Other fields: `kind: source` (with `data_type`) and `kind: transform` (with `transform`, e.g. `sha256`), `host_arg` (take the destination host from a constant URL argument, as for `http.Post` and `fetch`), `match_bare` (match an unresolved call without receiver, for Kotlin scope functions such as `prefs.edit { putString(...) }`), `severity`, `category`, `description`.

Destination kinds: `third_party`, `first_party`, `log`, `storage` (device/local), `network` (host unknown or not first-party), `ipc` (clipboard, broadcasts).

Callee names:
- Go: `importpath.Func`, `importpath.Type.Method` (pointer receivers and type parameters dropped): `github.com/getsentry/sentry-go.Scope.SetUser`, `log/slog.Logger.Info`.
- Kotlin/Java: `package.Class.method`; unqualified class references resolve through imports.
- TypeScript: `<module>.<export>`: `@sentry/react.setUser`, `axios.post`, `mixpanel-browser.people.set`, globals such as `console.log`, `localStorage.setItem`, `fetch`.

Calls that cannot be resolved still match heuristically on the receiver type name (`Sentry.setUser` behind a wildcard import) or a `receiver` regex (`logger.info`), with lower confidence.

## Configuration

`.piiflow.yaml` (all keys optional; `piiflow init` writes a commented copy):

```yaml
languages: [go, kotlin, java, typescript]   # default: all present
include_tests: false          # analyze test sources for flows (literals always scan tests)
first_party_domains: [api.example.vn]       # network sinks to these hosts become first-party
rules: [.piiflow/rules]
baseline: .piiflow/baseline.json
cache_dir: .piiflow/cache
literals: { enabled: true, min_confidence: 0.6 }
policy:
  fail_on: [third_party, log, network, storage, ipc]
  safe_transforms: [masked, redacted, encrypted, tokenized, anonymized]
  min_confidence: 0.55
  fail_on_literals: true
  ignore_data_types: []
  allow:
    - sink: sdk.sentry.set_user
      data_types: [email]
      reason: DPA with Sentry, EU region
    - dest_host: api.example.vn
    - path: "legacy/**"
```

Hashes (`sha256`, `hashed`) are not safe transforms by default: phone and CCCD numbers are low-entropy, so their hashes can be reversed by enumeration. Add them to `safe_transforms` if you salt or key them.

## Baseline

`piiflow baseline` records every current violation in `.piiflow/baseline.json` (commit it). A flow's fingerprint is a hash of **data type, sink rule, destination and enclosing function**; line numbers are left out, so adding code above a sink, moving a function within its package or reformatting does not raise new alerts. Committed literals are fingerprinted by data type, file and a hash of the value. Only findings whose fingerprint is not in the baseline fail the build; SARIF marks the others `baselineState: unchanged`.

## CI integration

### GitHub Actions

```yaml
# .github/workflows/piiflow.yml (full example in examples/github/piiflow.yml)
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read, security-events: write, pull-requests: write }
jobs:
  piiflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: actions/setup-go@v7          # only for Go code
        with: { go-version-file: go.mod }
      - uses: GoNetTools/pii-scanner@v0
```

The action installs the release binary (verified against the release's `checksums.txt`), restores the analysis cache saved by the last run on the base branch, runs `piiflow scan --diff origin/<base>` on pull requests (full scan on pushes), uploads SARIF to code scanning, writes the Markdown summary to the job summary, creates or updates one PR comment, and fails the job on new violations. Inputs: `version`, `repository`, `path`, `args`, `diff`, `sarif`, `comment`, `fail-on-new`, `token`. Pin `@v0` to follow 0.x releases, or a full tag or commit SHA.

### Caching

PR mode needs the call graph and summaries from a previous full scan (`.piiflow/cache/`, git-ignored automatically). The GitHub Action caches it per base branch. Without a cache, `--diff` falls back to analyzing the whole repository and still reports only new findings.

## Pre-commit

Only the literal detector runs at commit time; full tracing is too slow for a hook and belongs in CI.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/GoNetTools/pii-scanner
    rev: v0.1.0
    hooks:
      - id: piiflow          # or piiflow-docker
```

Without the framework: `cp scripts/pre-commit .git/hooks/pre-commit` (runs `piiflow scan --staged`, which reads the staged content). Accepted values in the baseline do not block commits.

## Data map (DPIA)

`piiflow map --format dpia` writes a Markdown inventory for a Data Protection Impact Assessment (GDPR art. 35) or the impact assessment dossier required by Vietnamese rules (Decree 13/2023/ND-CP, Law on Personal Data Protection 2025):

1. personal data processed (category, sensitive or not, where stored, where sent);
2. recipients and transfers (vendor, host, data types, safeguards detected, open issues);
3. data at rest (entities, tables and messages with PII fields);
4. flows needing review;
5. a table of processing activities with the columns code cannot answer (purpose, legal basis, data subjects, retention, owner).

`--format json|csv|mermaid` give the same data for spreadsheets, other tools or a diagram.

## Accuracy and limits

piiflow favours explainable, low-noise results over completeness. Every finding has a confidence score and a source description; `policy.min_confidence` and `min_confidence` tune the trade-off.

- The analysis is flow-insensitive inside a function and field-sensitive only for direct stores/loads. Objects are tracked through summaries, not heap models.
- Go interface calls are matched by the interface method (rules can target `io.Writer.Write`); implementations are not enumerated.
- Kotlin/Java/TypeScript resolution is syntactic: no type inference across generics, overloads share an ID, reflection/DI-provided instances resolve only through declared types or receiver-name rules.
- Dynamic destinations (URLs built at runtime) show up as `network (unknown host)`.
- Name-based sources depend on naming. Add explicit hints (`pii:"..."` tags, `@PII`, proto options, SQL comments) where names are unhelpful, and `pii:"-"` to silence a field.

### Measuring accuracy and speed

`testdata/eval.yaml` labels every leak in the fixtures, as a reviewer reading the code would report it, plus deliberate traps that must not be reported. `piiflow-bench` scans each case the way `piiflow scan --no-cache --no-baseline` does and scores it:

```sh
go run ./cmd/piiflow-bench                     # or: make eval
go run ./cmd/piiflow-bench -runs 5 -json eval.json -markdown eval.md
go run ./cmd/piiflow-bench -manifest my-corpus.yaml -check
```

- **Precision** = TP / (TP + FP) and **recall** = TP / (TP + FN), per case, per data type and per sink category (`log`, `sdk`, `net`, `storage`, `literal`). A label matched by several findings is one true positive; any other reported violation is a false positive. Findings matching an `ambiguous` label (for example data sent to a host that may be first party) count as neither.
- A **confidence sweep** rescores every case at each threshold in `thresholds`, which shows what raising `policy.min_confidence` would cost in recall.
- **Timings**: median wall time over `-runs` cold scans, memory allocated by the scan, files and functions. The Go frontend's `go list` runs in a child process, so its time is included but its memory is not.
- `-check` exits 1 when a case scores below its `min_precision` or `min_recall`. CI runs it on every pull request and publishes the tables in the job summary; timings are reported but not gated.

**See it on a realistic app:** [`testdata/vulnshop`](testdata/vulnshop) is a small shop (Go API, TypeScript checkout, Kotlin/Java Android app, CSV seed data) with 32 planted leaks and a set of traps. Run **Actions → demo → Run workflow** to scan it, or any other directory, and get the findings, the data map and the accuracy tables in the job summary.

To measure piiflow on your own code, write a manifest whose case `dir` points at a checkout (absolute, or relative to the manifest) and label the leaks you know about. For recall on unlabelled code, plant known leaks in a copy and label those.

For speed work:

```sh
make bench                                                  # engine scaling, detectors, fixture scans
piiflow scan . --no-cache --cpuprofile cpu.out --memprofile mem.out
go tool pprof -http=:8080 cpu.out
go tool pprof -sample_index=alloc_space mem.out
```

## Development

### Design: inversion of control

Components talk to each other only through interfaces. Each package declares the small interfaces it needs, next to the code that uses them, and receives its collaborators through struct fields. Only the composition root (`internal/app`) picks concrete implementations, and only `internal/platform` touches the operating system. `TestComponentsTalkThroughInterfaces` type-checks the module and fails on any call from one component into another's concrete code; the shared vocabulary (`ir`, `finding`, `lang`) is the only exception:

```
cmd/piiflow ──► internal/app (composition root) ──► cli.App ──► scan.Scanner ──► frontends, analysis, detectors
                     │                                  │              │
                     └─ wires ─► platform.OS            │              └─ reads everything through fs.FS
                                 platform.ExecGit       └─ Workspace, Scanner, CacheOpener, Commenter, Catalog, Clock,
                                                           ConfigLoader, RuleLoader, Policy, BaselineCodec, Reporter,
                                                           DataMapper, RuleTester
                                 platform.FileBlob
                                 cicomment.Client{HTTP, Getenv, ReadFile}
                                 frontend.Registry (golang.Register, treesitter.Register)
```

| Consumer | Depends on (interface) | Production implementation | Test double |
|---|---|---|---|
| `cli.App` | `Workspace`, `Scanner`, `CacheOpener`, `Commenter`, `Catalog`, `Clock` | `platform.OS`, `scan.Scanner`, `cache.Open`+`platform.FileBlob`, `cicomment.Client`, `detect.Classifier`, `time.Now` | in-memory workspace, fake scanner and commenter (`internal/cli/cli_test.go`) |
| `cli.App` services | `ConfigLoader`, `RuleLoader` (→ `RuleSet`), `Policy`, `BaselineCodec`, `Reporter`, `DataMapper`, `RuleTester` | `config.Loader`, `rules.Load` (adapted in `app`), `policy.Policies`, `baseline.Codec`, `report.Writer`, `datamap.Mapper`, `ruletest.Tester` | the same implementations, or any fake that satisfies the interface |
| `scan.Scanner` | `FileLister`, `Frontends`, `Analyzer`, `LiteralDetector`, `SchemaParser`, `VCS`, `Cache`, `Clock`, `fs.FS` | `ingest.Lister`, `frontend.Registry`, `analysis.Engine`, `detect.LiteralScanner`, `detect.Schemas`, `ingest.Git`, `cache.Store`, `os.DirFS` | `fstest.MapFS`, fake frontends/VCS/analyzer (`internal/scan/scan_test.go`) |
| `analysis.Engine` | `RuleMatcher`, `SchemaIndex`, `NameClassifier` | `rules.Set`, `detect.Schema`, `detect.Classifier` | fake rule matcher (`internal/analysis/engine_test.go`) |
| `ingest.Git` | `Runner` | `platform.ExecGit` | scripted runner (`internal/ingest/ignore_test.go`) |
| `cache.Store` | `Persister`, `Hasher` | `platform.FileBlob`, `ingest.Hasher` | `cache.Memory`, map hasher |
| frontends | `frontend.Registrar`, `frontend.Options.FS`, `golang.PackageLoader` | `frontend.Registry`, `os.DirFS`, `packages.Load` | `fstest.MapFS`, fake loader |
| `report` | `RuleLookup` | `rules.Set` | nil (no rule metadata) |
| `cicomment.Client` | `Doer`, `Getenv`, `ReadFile` | `http.Client`, `os.Getenv`, `os.ReadFile` | `httptest` servers |
| `policy`, `report`, `datamap` | `Catalog`, injected time and link builder | `detect.Classifier`, `time.Now`, `report.CILinks(os.Getenv)` | fixed catalogs and times |

There is no package-level mutable state: the name classifier is built from a taxonomy (`detect.NewClassifier(detect.DefaultTaxonomy())`, or your own data types), frontends are registered explicitly instead of in `init()`, and rules are loaded from an `fs.FS`. Scanner and CLI report missing dependencies instead of silently falling back to globals.

`app.NewWith(stdout, stderr, app.Deps{...})` builds the production wiring with a different workspace, clock, environment or HTTP client, which the end-to-end tests in `internal/app` use.

### Layout

```
cmd/piiflow/            entry point: app.New(os.Stdout, os.Stderr).Run(ctx, args)
cmd/piiflow-bench/      accuracy and timing on the labelled corpus (testdata/eval.yaml)
internal/lang/          the language table: names, aliases, extensions, test-file conventions
internal/app/           composition root + end-to-end tests on testdata/
internal/platform/      OS adapters: workspace on disk, git binary, cache file
internal/cli/           commands, flags, exit codes (App with injected deps)
internal/scan/          pipeline (Scanner + Request)
internal/ir/            the common IR
internal/ingest/        walker, .piiflowignore, git queries
internal/frontend/      interface + Registry
  golang/               go/packages + SSA (PackageLoader injectable)
  treesitter/           Kotlin, Java, TypeScript (cgo; Register records them unavailable without cgo)
  testdata/conformance/ the same scenarios in every language: what a frontend must lower
internal/detect/        Classifier + taxonomy, schema hints, literal validators
internal/rules/         YAML rules (builtin/ embedded) and matcher; testdata/examples/ has an example per rule
internal/analysis/      taint engine and summaries
internal/cache/         summary + call graph cache (Persister, Hasher)
internal/baseline/      fingerprints and baseline encoding
internal/policy/        violations and severity (Evaluator)
internal/report/        text, JSON, SARIF, Markdown, GitLab SAST
internal/datamap/       DPIA/JSON/CSV/Mermaid data map
internal/cicomment/     PR/MR comment upsert (HTTP client injected)
internal/eval/          labelled-corpus scoring: precision, recall, F1, confidence sweep
internal/ruletest/      ruleid/ok annotations in example code, checked against scan results
testdata/               fixtures with deliberate leaks (Go, Android, web, vulnshop demo); eval.yaml labels them
scripts/                release build and packaging, license header check, third-party licenses
.github/workflows/      ci.yml (lint, vulncheck, tests on Linux/macOS/Windows, accuracy, self-scan, image), demo.yml (on demand), release.yml
```

Building needs Go 1.26 or newer and, for the tree-sitter frontends, a C compiler.

```sh
make test          # all frontends (cgo)
make test-nocgo    # Go frontend + literal detector only
make check         # what CI runs: gofmt, vet, staticcheck, license headers, both test suites
make eval          # precision/recall/F1 and timings on testdata/eval.yaml
make bench         # Go benchmarks
make release-local # release archives for this machine in dist/
go test -coverpkg=./internal/... ./...   # ~76% of statements
```

The version is set with `-ldflags "-X github.com/GoNetTools/pii-scanner/internal/app.Version=v1.2.3"` (`scripts/release/build.sh` does this).

Adding a language or a rule is a checklist in [CONTRIBUTING.md](CONTRIBUTING.md#add-a-language), and tests enforce each step: `TestEveryLanguageIsWired` (language table, frontends and rules agree), `TestFrontendConformance` (the frontend lowers every scenario), `TestRuleExamples` (every rule has an example that passes) and `TestBuiltinRuleConventions` (ids, categories, data types).

## Contributing

Contributions are welcome: false-positive and missed-leak reports, sink rules for more SDKs, data types, and languages. Read [CONTRIBUTING.md](CONTRIBUTING.md) first; it covers the development setup, the checks CI runs and how to add rules. **Never put real personal data in issues, pull requests or fixtures.** Report security problems privately as described in [SECURITY.md](SECURITY.md). This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

piiflow is licensed under the [Apache License 2.0](LICENSE). Release archives and the container image also include the licenses of the third-party code compiled into the binary (`THIRD_PARTY_LICENSES.txt`).
