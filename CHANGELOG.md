# Changelog

All notable changes to piiflow are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change rule ids, fingerprints or output formats; such changes are called out here.

## [Unreleased]

### Added

- `piiflow scan` with full, path, PR (`--diff <ref>`, changed files plus their callers from the cached call graph) and pre-commit (`--literals-only`, `--staged`) modes. Exit codes: 0 clean, 1 new violation, 2 error.
- Frontends lowering to a shared IR: Go (`go/packages` + SSA), Kotlin, Java and TypeScript/JavaScript (tree-sitter).
- Source detectors: identifier names in English and Vietnamese (`soDienThoai`, `sdt`, `cccd`, `ngaySinh`, `hoTen`, `diaChi`, …), schema hints (Go struct tags and GORM, JPA/Room/Gson/Moshi, TypeORM, protobuf, SQL migrations, explicit `pii` annotations) and validated literal values (Vietnamese mobile numbers, CCCD/CMND, cards with Luhn and NAPAS, IBAN, SSN, email).
- 89 embedded sink, source and transform rules for logging, crash reporting, analytics, HTTP clients, storage and IPC, overridable per repository.
- Interprocedural taint analysis with function summaries cached by file content hash.
- Baseline with line-independent fingerprints (data type, sink rule, destination, enclosing function).
- Reports: text, JSON, SARIF 2.1.0, Markdown PR summary, GitLab SAST.
- `piiflow map` data inventory for DPIAs (Markdown, JSON, CSV, Mermaid).
- GitHub Action, pre-commit hooks and a multi-arch container image.

[Unreleased]: https://github.com/GoNetTools/pii-scanner/commits/main
