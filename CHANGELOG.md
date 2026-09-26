# Changelog

All notable changes to datawarden are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change rule ids, fingerprints or output formats; such changes are called out here.

## [Unreleased]

### Added

- Python and Swift frontends, with rules for their logging, crash-reporting, analytics, messaging, HTTP, storage and IPC APIs, annotated examples for every rule, the shared conformance scenarios and construct programs, and planted leaks in `testdata/vulnshop` (a Flask recommender and an iOS app). Swift unified logging (`Logger`, `os_log`) counts only values marked public, since the rest are redacted.
- `datawarden scan` with full, path, PR (`--diff <ref>`, changed files plus their callers from the cached call graph) and pre-commit (`--literals-only`, `--staged`) modes. Exit codes: 0 clean, 1 new violation, 2 error.
- Frontends lowering to a shared IR: Go (`go/packages` + SSA), Kotlin, Java and TypeScript/JavaScript (tree-sitter).
- Source detectors: identifier names (`phoneNumber`, `dateOfBirth`, `fullName`, `ssn`, …), schema hints (Go struct tags and GORM, JPA/Room/Gson/Moshi, TypeORM, protobuf, SQL migrations, explicit `pii` annotations) and validated literal values (cards with Luhn, IBAN, US SSN, email).
- 123 embedded sink, source and transform rules for logging, crash reporting, analytics, HTTP clients, storage and IPC, overridable per repository.
- Interprocedural taint analysis with function summaries cached by file content hash.
- Baseline with line-independent fingerprints (data type, sink rule, destination, enclosing function).
- Reports: text, JSON, SARIF 2.1.0, Markdown PR summary, GitLab SAST.
- `datawarden map` data inventory for DPIAs (Markdown, JSON, CSV, Mermaid).
- GitHub Action, pre-commit hooks and a multi-arch container image.
- `datawarden-bench` and a labelled corpus (`testdata/eval.yaml`): precision, recall and F1 per case, data type and sink, a confidence-threshold sweep, and scan timings; CI fails when accuracy drops below the corpus minimums.
- `testdata/vulnshop`, a vulnerable-by-design shop (Go, Python, TypeScript, Kotlin, Java, Swift, CSV) with 51 labelled leaks of personal data, health data and credentials, and a `demo` workflow to scan it or any directory on demand.
- `datawarden rules test DIR`: check repository rules against annotated example code (`ruleid:`, `ok:`, `todoruleid:`, `todook:`). `.datawarden/rules/examples/` is never scanned as part of the repository.
- Every built-in rule has an annotated example (`internal/rules/testdata/examples/`), and every frontend passes the same conformance scenarios (`internal/frontend/testdata/conformance/`).
- Data classes: every data type belongs to `pii`, `phi`, `pci` or `credential`, findings carry a `class` (JSON, a SARIF tag, a data-map column), and the policy has `ignore_classes` and per-class `fail_on`/`safe_transforms` overrides (`policy.classes`). Phi, pci and credential findings are high severity.
- Credential and health data types: `password`, `api_key`, `access_token`, `secret_key`, `private_key`, `session_token` and `medical_record_number`.
- Committed-secret detection through value patterns in the taxonomy (regex, keywords, confidence, minimum entropy): AWS access key ids, Stripe, Google, SendGrid, Anthropic and OpenAI API keys, GitHub, GitLab and Slack tokens, JWTs and private key blocks. Documentation values and templates are skipped; reports show only the first four characters.
- `--cpuprofile` and `--memprofile` on `scan`, `baseline` and `map`, and Go benchmarks for the taint engine, the detectors and end-to-end fixture scans.

### Changed

- The IR is specified in `docs/IR.md` (version 2) and checked: `ir.Verify` validates SSA form, phis, terminators and exceptional edges, and every frontend's output passes it in the tests. It now has phis tied to predecessor blocks, typed operations for what were flags (`compute`, `new`, `throw`, `catch`, `closure`, `yield`), branch conditions and exceptional edges in the control-flow graph, cells for weak updates, closures as functions of their own with capture parameters, and a class table (`Module.Classes`) from which the engine resolves overrides for every language. `ir.Format` prints a function. What this changes in results:
  - A sink that runs only after a consent check (`hasConsent()`, `optedIn`, `analyticsEnabled`, ...) is reported with the check in `guards`, and reports say "guarded by" / "only after".
  - Access paths are followed three fields deep (`user.profile.note = email`), within a function and through summaries.
  - A closure's summary is applied where it runs, with its captured variables; a closure assigning a captured variable updates it (Go included), and a handler in a `try` sees the state at each call or `throw` that can raise.
  - Flows inside a Go function literal are now reported in the enclosing function (`service.Register`, was `service.Register$1`), as they already were in the other languages, which changes their baseline fingerprints. The cache format changes.
- Frontends and the engine follow much more of each language:
  - Objects across methods and constructors: summaries track fields (`this.addr`), constructors run on the new object, factories return objects with their fields, and keyword/named arguments reach the parameter of their name.
  - Calls through an interface, protocol, abstract class or overridable method reach every override and implementation (class hierarchy analysis), in all six languages. Go now lowers the methods of every declared type, not only of types the program instantiates.
  - Exceptions: `throw`/`raise` reaches the `catch` that handles it, across calls (`ParamThrow`, `ThrowFacts` in summaries).
  - Lambdas stored in variables, Java method references and Kotlin callable references, computed properties (`@property`, Kotlin `get()`, Swift computed properties), Kotlin properties of Java classes as their getters (`telephony.line1Number`), generators, builder chains, TypeScript inline object types and Swift `case let` bindings.
  - JVM reflection with constant names: `Class.forName`, class literals, `getDeclaredField`/`getMethod`, `Field.get`/`set`, `Method.invoke`, `newInstance`, and `Proxy.newProxyInstance` handlers.
  - Syntax errors: code inside what a tree-sitter grammar cannot parse is still lowered, and the file gets a warning.
  - All known gaps in the conformance programs and rule examples are closed. Labelled corpus: recall 0.92 to 0.95 at precision 0.99. The cache format changes.
- Control flow follows `break` and `continue` (with labels) to their loop or switch, Java and JavaScript `switch` cases fall through until a `break`, and Python `for`/`while ... else` runs only without a break. This finds leaks that were missed (a value set in one case and logged in the next, a value set before `break outer`) and drops false positives after `continue`.
- String building and arithmetic are snapshots in the IR (`Instr.Snapshot`): `msg = "items=" + items` no longer picks up data added to `items` afterwards.
- Constant conditions are folded in every language: `if false`, `while true`, `for (;;)` and booleans declared as constants (`static final boolean DEBUG = false`, Kotlin `const val`, TypeScript `const`, Swift `let`, Python `UPPER_CASE = False`, Go `const`). Code under a false constant is no longer reported. The cache format changes again.
- The IR carries a control-flow graph (basic blocks and successors) next to its SSA variables, making it a small code property graph, and the analysis orders mutations of objects along it in every language. An object logged before personal data is added to it (`log(items); items.add(email)`, `log(user); user.note = email`) is no longer reported, and in the tree-sitter languages a value assigned on a path that returns no longer reaches the code after it. Mutations inside a loop, in a lambda that may run later, and through an alias are still reported. Two conformance scenarios cover this (`mutated-later`, `early-return`). The cache format changes, so the first scan after upgrading re-analyses everything.
- Variable reassignment is followed in order in Python, Java, Kotlin, Swift and TypeScript/JavaScript, as it already was in Go: each assignment to a local is a new version (SSA form), merged after `if`/`else`, `switch`/`when`/`match`, loops and `try`/`catch`. A value that is overwritten (`x = "anonymous"`) or replaced by its masked or hashed form (`email = mask(email)`) no longer reaches later sinks. A variable is no longer a new name-based source when its value is computed from a same-named variable, in every language including Go, so `email = sha256(email)` reports only the hashed flow. Four conformance scenarios cover this (`overwritten`, `remasked`, `branch-merge`, `loop-carried`).
- The README and generated files (`datawarden init`, DPIA text, SARIF help) no longer refer to one country's laws or formats.
- Vietnam-specific detection is removed: the `vn_cccd` data type, the Vietnamese mobile number and CCCD/CMND literal detectors, the NAPAS card range and the `bhxh`/`bhyt` identifier words. Phone and national ID numbers are found through names and schema hints; committed phone and ID values are no longer reported as literals (US SSNs still are).

- Renamed from piiflow to **datawarden**: the command is `datawarden` (and `datawarden-bench`), configuration lives in `.datawarden.yaml`, `.datawardenignore` and `.datawarden/`, the image is `ghcr.io/gonettools/datawarden`, release archives are `datawarden_<os>_<arch>`, and the GitLab token variable is `DATAWARDEN_GITLAB_TOKEN`. The repository is now `GoNetTools/datawarden` (was `GoNetTools/pii-scanner`; GitHub redirects the old URLs): the Go module path is `github.com/GoNetTools/datawarden` and the Action is `uses: GoNetTools/datawarden@v0`. SARIF rule names are `SensitiveDataFlow…` and `CommittedSensitiveValue…`.
- The taxonomy moved from Go code to `internal/detect/builtin/datatypes.yaml`, read strictly and validated; adding a data type, a class or a secret pattern is a YAML change. High severity for identity documents comes from the taxonomy (`severity: high`) instead of a hard-coded list.
- Rule files are read strictly: unknown keys, unknown `lang` values and ids defined twice in one file are errors.
- Construct programs for every frontend (control flow, loops, exceptions, ternaries and elvis, destructuring, spread, optional chaining, async, lambdas, statics, channels, goroutines), more unit tests, and a CI floor of 85% statement coverage (81% → 87%).
- `docs/ARCHITECTURE.md`: the scan pipeline, layers, design rules, interfaces, data model, analysis, extension points and test strategy.
- Components communicate only through interfaces: the CLI reaches configuration, rules, policy, baselines, reports, the data map and rule tests through injected services, the scanner lists files through `FileLister`, frontends register through `frontend.Registrar`. An architecture test enforces it.
- Languages are defined in one table (`internal/lang`); `languages:` in `.datawarden.yaml` accepts the same aliases as rules (`kt`, `ts`, `js`, `golang`).

### Fixed

- A closure passed to a function that runs it before returning (`forEach`, `map`, `filter`, `apply`, `let`, `sort.Slice`, …) sees its captured variables as they are at the call: `items.forEach { log(xs) }; xs.add(email)` is no longer reported. Closures passed to other functions are still treated as possibly running later.
- Closures kept in a field, added to a collection or returned by a function are followed to where they are called: a handler passed to a constructor and called by another method (`Notifier { log(it) }.send(email)`), listeners added to a list and called in a loop (an event bus), and a closure returned by a factory and called by the caller (`makePrinter()(email)`). A call runs the closures held in the variable it calls, in its receiver (`h.accept(v)`, `r.run()`) or in the field it is named after (`this.onSend(v)`); calling a local that holds a closure no longer matches a sink rule of the same name (`log(email)` with `val log = makeLogger()`). Go functions used as values, such as a func literal that captures nothing or a named function passed as a callback, are closures in the IR. The cache format changes.
- Python: assigning a name inside a nested function binds a local of that function unless it is declared `nonlocal` or `global`; it no longer taints the enclosing function's variable.

- PR (`--diff`) and path scans resolve calls through an interface or overridable method to implementations in files that were not re-analysed: the class table is cached per file with the schema. The cache format changes.

- `sdk.onesignal` now matches the OneSignal v5 API (`OneSignal.User.addEmail`, `addSms`, `addTag`).
- A network call's response no longer inherits the taint of its request (a login reply was reported as the password it was sent with).
- A map or object literal key labels its value (`map[string]any{"email": v}`) even when some type in the repository has a field of the same name.

[Unreleased]: https://github.com/GoNetTools/datawarden/commits/main
