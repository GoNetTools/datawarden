# Getting started as a datawarden developer

This guide takes you from a fresh clone to your first pull request. It explains what the project does, how a scan moves through the code, where things live, and the conventions that tests and reviewers will hold you to. It links to the reference documents instead of repeating them, so read it first and follow the links when you need depth.

## Contents

- [The project in two minutes](#the-project-in-two-minutes)
- [Set up (10 minutes)](#set-up-10-minutes)
- [See it work (15 minutes)](#see-it-work-15-minutes)
- [The mental model](#the-mental-model)
- [Follow one scan through the code](#follow-one-scan-through-the-code)
- [Where to find things](#where-to-find-things)
- [How changes are checked](#how-changes-are-checked)
- [Common first tasks](#common-first-tasks)
- [Rules of the road](#rules-of-the-road)
- [Glossary](#glossary)
- [Suggested reading order](#suggested-reading-order)

## The project in two minutes

datawarden is a **static taint analyzer** written in Go. It reads a repository without running it and reports two kinds of findings:

- **Flows:** sensitive data (a *source*, such as a variable named `email`, a field tagged `pii:"phone"`, or the result of `getLine1Number()`) that reaches a place it should not go (a *sink*, such as a logger, Sentry, an analytics SDK, a third-party API, or device storage).
- **Literals:** real-looking sensitive values committed to the repository (a Luhn-valid card number in a fixture, a live API key in a config file).

It analyses **Go, Python, Java, Kotlin, Swift and TypeScript/JavaScript**. Each language is lowered into one shared intermediate representation (IR), so the analysis, the rules and the reports are written once.

It is built for CI: exit code 1 on a *new* violation, a baseline of accepted findings, SARIF and PR comments, and a fast `--diff` mode for pull requests.

What counts as "sensitive" (the taxonomy), which calls are sinks (the rules), and what counts as a violation (the policy) are all **data, not code**. Most day-to-day contributions are YAML plus an annotated example, not engine changes.

## Set up (10 minutes)

You need:

- **Go**, at the version in `go.mod` or newer.
- **A C compiler** (`gcc` or `clang`), because the tree-sitter frontends use cgo. Without one, `CGO_ENABLED=0` still builds the Go frontend and the literal detector.
- `git`.

```sh
git clone https://github.com/GoNetTools/datawarden && cd datawarden
make build          # bin/datawarden, all languages
make test           # the full test suite (cgo), a few minutes
```

If `make test` passes, you are ready. `make check` runs everything CI's lint and test jobs run (gofmt, vet with and without cgo, staticcheck, license headers, both test suites). Run it before every push.

## See it work (15 minutes)

`testdata/vulnshop` is a small demo shop with deliberate leaks in every language. Scan its web client:

```sh
cd testdata/vulnshop
../../bin/datawarden scan web --root . --no-baseline
```

```
datawarden dev · paths scan · 1 files (typescript:1) · 5 functions · 10ms

NEW      high   email → Sentry / sentry.io (third-party)  [sdk.ts.sentry.set_user]
         source  web/src/checkout.ts:21:44  identifier "email"
         sink    web/src/checkout.ts:21:3  @sentry/browser.setUser  in web/src/checkout:placeOrder
         confidence 0.90 · explain: datawarden explain bb6c8bd8592e
...
```

Each finding names the data type, the destination, the **rule id** in brackets, the source and sink positions, and a confidence. Now ask the tool to explain one finding:

```sh
../../bin/datawarden explain bb6c8bd8 --root .
```

The output walks through the whole decision: why `email` is an email (a name pattern), each step of the path, why the sink rule matched (the resolved callee `@sentry/browser.setUser` matches the rule's call patterns), how the policy decided, and what configuration would silence it. **`explain` is your best debugging tool.** When a rule does or does not fire, start here.

Finally, look at what the analysis actually sees:

```sh
../../bin/datawarden ir web/src/checkout.ts --root . --func placeOrder
```

```
func web/src/checkout:placeOrder(v0:shopper, v1:card, v2:orderId, v3:items)
b0:
  v6 = v0:shopper.email
  v7:email = assign v6
  v8 = new {}()
  v8.email = v7:email
  v9 = call @sentry/browser.setUser(v8)
  ...
```

This is the IR: SSA variables, field loads and stores, calls with qualified callee names. The engine never sees TypeScript, only this. When a rule does not match, the question is almost always "what callee name or receiver did the frontend produce?", and `datawarden ir` answers it.

Try the other directories (`backend`, `android`, `ios`, `recommender`) and `datawarden graph` to see the same findings drawn as a picture.

## The mental model

```
repo ──► Ingest ──► Frontends ──► IR ──► Detectors ──► Taint engine ──► Policy + Baseline ──► Reports
```

1. **Ingest** lists files, applies `.datawardenignore`, and picks targets. In `--diff` mode those are the changed files plus their callers, from the cached call graph.
2. **Frontends** lower source files to IR. Go uses `go/packages` and SSA, so its types and callees are exact. The other languages use tree-sitter with best-effort resolution of imports, declared types and class hierarchies.
3. **Detectors** mark sources. Identifier names are classified against the taxonomy (`phoneNumber` is a phone, `phoneFormatter` is not). Schema hints come from struct tags, ORM models, protobuf and SQL. Source rules match calls such as `getLine1Number()` or `request.json`.
4. **The taint engine** analyses each function to a fixpoint with its parameters as symbolic labels. That yields concrete flows and a **summary** (parameter → sink, parameter → return, and so on). Functions are processed callees-first by strongly connected component, and callers apply their callees' summaries. This is how data is followed through helpers several calls deep.
5. **Sinks** come from YAML rules. A flow is emitted when a fact reaches a sink argument, with confidence = source × propagation × rule match.
6. **Policy** decides which flows are violations: which destination kinds fail the build, the minimum confidence (default 0.55), safe transforms such as hashing and masking, and allow-list entries. **The baseline** marks the violations accepted before. **Reporters** render the result.

A useful rule of thumb when triaging: **is it the analysis, the rules, or the policy?** A wrong data type or path is an engine or frontend problem. A call that should or should not be a sink is a rule problem. A real flow that should not fail the build is a policy question. `explain` shows all three.

## Follow one scan through the code

Read these in order with the code open. It is the fastest way to learn the codebase.

| Step | File | What to look at |
|---|---|---|
| 1 | `cmd/datawarden/main.go` | A few lines: build the app and run it. |
| 2 | `internal/app/app.go` | The **composition root**: `NewComponents` builds every concrete component and wires them together. This is the only place that does. |
| 3 | `internal/cli/commands.go`, `session.go` | Command parsing, loading the config and rules into a session, exit codes. `explaincmd.go`, `graphcmd.go` and `ircmd.go` are the other commands. |
| 4 | `internal/scan/scan.go` | `Scanner.Run`: list files, select targets, run the literal detector, lower with frontends, build the schema index, and call the analyzer. |
| 5 | `internal/frontend/treesitter/common.go`, then one language file (`typescript.go`) | How syntax becomes IR. `common.go` holds the shared builder helpers (`redefine`, `branches`, `tryCatch`, `emitCall`, `newObject`, ...). |
| 6 | `internal/ir/ir.go` and [docs/IR.md](IR.md) | The IR every frontend produces and the engine consumes. |
| 7 | `internal/detect/names.go`, `taxonomy.go` and `builtin/datatypes.yaml` | How names become data types. |
| 8 | `internal/rules/rules.go`, `match.go` and `builtin/*.yaml` | Rule loading and matching. See [How a sink rule matches](#how-a-sink-rule-matches). |
| 9 | `internal/analysis/engine.go`, then `summary.go` | The taint engine. The other files each handle one topic: `order.go` (flow-sensitive ordering of mutations), `pointsto.go` (aliasing), `closures.go` and `callbacks.go` (lambdas), `hierarchy.go` (dynamic dispatch), `checks.go` (validation checks), `guard.go` (consent guards), `order_facts.go` (deterministic tie-breaking). |
| 10 | `internal/policy`, `internal/baseline`, `internal/report` | Deciding, remembering, rendering. |

[docs/ARCHITECTURE.md](ARCHITECTURE.md) has the same pipeline as a diagram, the full package table, and the section on [the taint analysis](ARCHITECTURE.md#the-taint-analysis). Read that section once you have done steps 1–9.

### How a sink rule matches

This matters for almost every rule you will write:

- If the frontend **resolved** the callee (for example `@sentry/browser.setUser` or `android.util.Log.d`), the rule matches only by its `calls` patterns, at confidence 1.0.
- If the callee is **unresolved** (a method on a variable whose type the frontend could not infer), the rule can still match through its receiver settings: the receiver's type or text at 0.8, or a receiver-name regex at 0.75.

So when a rule does not fire, run `datawarden ir` on the example. If the callee is resolved to something your pattern does not cover (for example `@opentelemetry/api.trace.getActiveSpan().addEvent`), add that pattern. If it is unresolved, check the receiver text against the rule's receiver regex.

## Where to find things

| You want to change... | Look in |
|---|---|
| Which calls are sinks (a logger, an SDK, an HTTP client) | `internal/rules/builtin/<lang>.yaml`, plus an example in `internal/rules/testdata/examples/<lang>/` |
| Which calls or parameters are sources (framework request data, device ids) | `internal/rules/builtin/sources.yaml`, `requests.yaml` |
| Which functions mask or hash data | `internal/rules/builtin/transforms.yaml`, and the shared words in `internal/detect/names.go` |
| Which names count as which data type, and new data types or classes | `internal/detect/builtin/datatypes.yaml` |
| Committed-secret and value patterns | the `values:` entries in `datatypes.yaml` |
| How a language construct is lowered | `internal/frontend/treesitter/<lang>.go` or `internal/frontend/golang` |
| How data moves through code | `internal/analysis` |
| Violations, severity and allow-lists | `internal/policy` |
| Output formats | `internal/report` |
| The TypeScript globals that resolve by name (`Sentry`, `heap`, `newrelic`, ...) | `tsGlobals` in `internal/frontend/treesitter/typescript.go` |
| Configuration keys | `internal/config`, documented in the README's [Configuration](../README.md#configuration) section |

## How changes are checked

The test suite enforces most conventions, so a mistake usually fails a test with a clear message rather than slipping through review.

| Check | What it guards | Run it with |
|---|---|---|
| `TestRuleExamples` | Every built-in rule has an annotated example, every `ruleid:` line fires, every `ok:` line does not, and every violation in an example is annotated. | `go test ./internal/app -run TestRuleExamples` |
| `TestBuiltinRuleConventions` | Rule id prefixes (`log.`, `sdk.`, `net.`, `storage.`, `ipc.`, `src.`, `xform.`), categories, destinations, known data types. | `go test ./internal/rules` |
| `TestFrontendConformance` | Every frontend lowers the same scenarios (`internal/frontend/testdata/conformance/<lang>`). | `go test ./internal/app -run TestFrontendConformance` |
| `TestLoweredIRVerifies` | The IR is valid (SSA, blocks, terminators, see [IR.md](IR.md)). | `go test ./internal/app -run TestLoweredIRVerifies` |
| `TestComponentsTalkThroughInterfaces` | No package calls another component's concrete code. | `go test ./internal/app -run TestComponents` |
| `TestScansAreDeterministic` | Two scans of the same code give identical results. | `go test ./internal/app -run TestScansAreDeterministic` |
| Accuracy corpus | Precision and recall on the labelled fixtures (`testdata/eval.yaml`) stay above each case's minimum. | `make eval`; `make eval-external` also scans pinned open-source apps |
| Coverage | Total statement coverage stays at or above 85%. | `go test -coverpkg=./internal/... ./...` |

The annotated examples use this format:

```python
# ruleid: sdk.py.otel
span.set_attribute("user.email", user.email)
# ok: sdk.py.otel
span.set_attribute("order.id", order.id)
```

`todoruleid:` and `todook:` mark known gaps and known false positives. The test fails as soon as a gap is fixed, so the markers never go stale.

### Checking a rule change against real code

Tests and the corpus catch regressions in the fixtures. For a rule or engine change that could add noise, also compare the findings on a real application before and after your change:

```sh
git stash && go build -o /tmp/dw-main ./cmd/datawarden && git stash pop
go build -o /tmp/dw-new ./cmd/datawarden
for b in main new; do /tmp/dw-$b scan --root ~/src/some-app --no-baseline --no-cache --no-fail --json /tmp/$b.json ~/src/some-app; done
# diff the flows and violations in /tmp/main.json and /tmp/new.json
```

Read every new violation and say in the pull request whether it is a real leak. The apps pinned in `testdata/eval.yaml` are good candidates, because they are already fetched by `make eval-external`.

## Common first tasks

**Add a sink rule for an SDK.** This is the most common contribution and the best first task. Follow the checklist in [CONTRIBUTING](../CONTRIBUTING.md#add-or-fix-a-rule):

1. Add the rule to `internal/rules/builtin/<lang>.yaml` with a stable dotted id.
2. Write an annotated example the way real code calls the SDK. Go examples import small offline stubs from `internal/rules/testdata/gostubs/`, wired with a `replace` in `examples/go/go.mod`.
3. Run `TestRuleExamples`. If a line does not fire, run `datawarden ir` on it.
4. Add a CHANGELOG line.

**Fix a false positive or a missed leak.** Reduce the report to a minimal snippet and run `datawarden explain` on it. Decide whether it is the analysis, a rule, or the policy (see [docs/FINDINGS.md](FINDINGS.md)). Add the snippet as an example or a conformance case before fixing it, so the fix is pinned by a test.

**Teach a frontend a construct.** Add the construct to the conformance programs for every language, check the IR with `datawarden ir --verify`, and change the lowering in `common.go` or the language file.

**Add a data type.** Add an entry in `datatypes.yaml`, add cases (including look-alikes that must not match) in `detect_test.go`, and plant and label a leak in a fixture.

**Add a language.** This is a larger change. The five steps and their tests are in [CONTRIBUTING](../CONTRIBUTING.md#add-a-language).

The open issues and [docs/ROADMAP.md](ROADMAP.md) show what is planned.

## Rules of the road

- **Synthetic data only.** Never commit or paste real personal data or live secrets, in code, fixtures, issues or PRs. Build secret-shaped test strings from pieces (`"sk_" + "live_" + ...`) so push protection does not block them.
- **Components talk through interfaces.** A package declares the small interface it needs next to the code that uses it. Only `internal/app` builds concrete types, and only `internal/platform` touches the OS. No `init()` registration and no package-level mutable state.
- **Scans must be deterministic.** Go map iteration order is random. Whenever the analysis keeps one candidate out of several (a fact per slot, a capped list), it must choose by a total order, not by arrival order. Use the comparisons in `internal/analysis/order_facts.go`, and sort before iterating a map when the order can reach the output.
- **Rule ids are stable.** They are part of baseline fingerprints, so renaming one invalidates users' baselines. Add new ids, and don't rename old ones.
- **Changed the IR or the analysis semantics?** Bump `ir.Version` (with a note in [IR.md](IR.md#changes)) and/or `cache.FormatVersion`, so stale caches are not reused.
- **Label the corpus honestly.** `testdata/eval.yaml` records what a reviewer would report, not what datawarden reports today. Label misses too, with a `note`.
- **Every Go file starts with the SPDX header** (`scripts/check-headers.sh` checks it). Every user-visible change gets a line under **Unreleased** in [CHANGELOG.md](../CHANGELOG.md).
- **One change per pull request**, using the template (What and why / How it was tested / Checklist). CI must be green on Linux, macOS and Windows.

## Glossary

| Term | Meaning |
|---|---|
| **Source** | Where sensitive data enters: a name, a schema field, or a source-rule call. |
| **Sink** | Where data must not go: a call matched by a sink rule. |
| **Flow** | A path from a source to a sink, with data type, destination, path, transforms and confidence. |
| **Literal** | A sensitive value committed as text in the repository. |
| **Data type / class** | `email`, `us_ssn`, `api_key`, ... grouped into classes: `pii`, `phi`, `pci`, `credential`. |
| **Destination** | Where a sink sends data: its kind (`log`, `third_party`, `network`, `storage`, `ipc`), host and vendor. First-party destinations are not violations by default. |
| **Transform** | Something done to the data on the way: `masked`, `sha256`, ... Safe transforms can make a flow acceptable. |
| **Guard** | A consent check that dominates the sink (`if (hasConsent())`). |
| **IR** | The shared intermediate representation: SSA variables, instructions, basic blocks, a class table. |
| **Lowering** | Converting a language's syntax tree to IR (the frontend's job). |
| **Summary** | What a function does with its parameters, reused at every call site and cached by file hash. |
| **SCC** | Strongly connected component of the call graph: mutually recursive functions analysed together to a fixpoint. |
| **Violation** | A flow the policy fails the build on. |
| **Baseline** | Accepted violations, by line-independent fingerprint, so that only new ones fail CI. |
| **Fingerprint** | A stable hash of a finding, used by the baseline and by `explain`. |
| **Confidence** | Source × propagation × rule match, from 0 to 1. Below `min_confidence` (0.55 by default), a flow is informational. |

## Suggested reading order

1. **Day 1:** this guide, the [README](../README.md) (install, commands, how it works), and a scan of each `testdata/vulnshop` directory.
2. **Day 2:** [CONTRIBUTING](../CONTRIBUTING.md), [docs/ARCHITECTURE.md](ARCHITECTURE.md), and the code tour above.
3. **Day 3:** [docs/IR.md](IR.md) with `datawarden ir` open next to it, then [docs/FINDINGS.md](FINDINGS.md) to learn how findings are triaged.
4. **First PR:** a sink rule with an example, or a small false-positive fix from the issue tracker.

Stuck? Open a draft pull request early, or ask in the issue you are working on.
