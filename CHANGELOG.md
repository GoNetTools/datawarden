# Changelog

All notable changes to piiflow are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change rule ids, fingerprints or output formats; such changes are called out here.

## [Unreleased]

### Added

- `piiflow scan` with full, path, PR (`--diff <ref>`, changed files plus their callers from the cached call graph) and pre-commit (`--literals-only`, `--staged`) modes. Exit codes: 0 clean, 1 new violation, 2 error.
- Frontends lowering to a shared IR: Go (`go/packages` + SSA), Kotlin, Java and TypeScript/JavaScript (tree-sitter).
- Source detectors: identifier names (`phoneNumber`, `dateOfBirth`, `fullName`, `cccd`, …), schema hints (Go struct tags and GORM, JPA/Room/Gson/Moshi, TypeORM, protobuf, SQL migrations, explicit `pii` annotations) and validated literal values (Vietnamese mobile numbers, CCCD/CMND, cards with Luhn and NAPAS, IBAN, SSN, email).
- 89 embedded sink, source and transform rules for logging, crash reporting, analytics, HTTP clients, storage and IPC, overridable per repository.
- Interprocedural taint analysis with function summaries cached by file content hash.
- Baseline with line-independent fingerprints (data type, sink rule, destination, enclosing function).
- Reports: text, JSON, SARIF 2.1.0, Markdown PR summary, GitLab SAST.
- `piiflow map` data inventory for DPIAs (Markdown, JSON, CSV, Mermaid).
- GitHub Action, pre-commit hooks and a multi-arch container image.
- `piiflow-bench` and a labelled corpus (`testdata/eval.yaml`): precision, recall and F1 per case, data type and sink, a confidence-threshold sweep, and scan timings; CI fails when accuracy drops below the corpus minimums.
- `testdata/vulnshop`, a vulnerable-by-design shop (Go, TypeScript, Kotlin, Java, CSV) with 32 labelled leaks, and a `demo` workflow to scan it or any directory on demand.
- `piiflow rules test DIR`: check repository rules against annotated example code (`ruleid:`, `ok:`, `todoruleid:`, `todook:`). `.piiflow/rules/examples/` is never scanned as part of the repository.
- Every built-in rule has an annotated example (`internal/rules/testdata/examples/`), and every frontend passes the same conformance scenarios (`internal/frontend/testdata/conformance/`).
- `--cpuprofile` and `--memprofile` on `scan`, `baseline` and `map`, and Go benchmarks for the taint engine, the detectors and end-to-end fixture scans.

### Changed

- Rule files are read strictly: unknown keys, unknown `lang` values and ids defined twice in one file are errors.
- Components communicate only through interfaces: the CLI reaches configuration, rules, policy, baselines, reports, the data map and rule tests through injected services, the scanner lists files through `FileLister`, frontends register through `frontend.Registrar`. An architecture test enforces it.
- Languages are defined in one table (`internal/lang`); `languages:` in `.piiflow.yaml` accepts the same aliases as rules (`kt`, `ts`, `js`, `golang`).

### Fixed

- `sdk.onesignal` now matches the OneSignal v5 API (`OneSignal.User.addEmail`, `addSms`, `addTag`).
- A map or object literal key labels its value (`map[string]any{"email": v}`) even when some type in the repository has a field of the same name.

[Unreleased]: https://github.com/GoNetTools/pii-scanner/commits/main
