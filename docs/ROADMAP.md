# Roadmap

Where datawarden is going, and why. Progress is tracked on GitHub: [the Roadmap issue](https://github.com/GoNetTools/datawarden/issues/21) has one sub-issue per milestone, and each milestone has its work items. Comment there to discuss a direction or pick up an item. This page changes when priorities do.

## Where we are: v0.1

datawarden follows personal data, health data, card data and credentials through Go, Python, Java, Kotlin, Swift and TypeScript/JavaScript. It reports where they reach logs, crash reporters, analytics SDKs, third-party APIs, storage and IPC, and it finds sensitive values committed to the repository. It is built for CI: SARIF, PR comments, a baseline, and a diff mode.

On fixtures and intentionally vulnerable apps, precision is 0.99 and recall 0.91. On four real open-source applications, about half of the flow findings are real leaks ([results](../README.md#results-on-real-applications)). Closing that gap is the next milestone.

## Milestones

### v0.1.x: Launch · [#22](https://github.com/GoNetTools/datawarden/issues/22)

Publish the first release and open the repository to contributors.

- Publish v0.1.0 and verify the release: [#27](https://github.com/GoNetTools/datawarden/issues/27)
- Repository settings for a public project: [#28](https://github.com/GoNetTools/datawarden/issues/28)
- Green CI on `main` (the SARIF upload needs code scanning): [#29](https://github.com/GoNetTools/datawarden/issues/29)

### v0.2: Precision on real code · [#24](https://github.com/GoNetTools/datawarden/issues/24)

A scanner nobody trusts gets turned off. The false positives that remain on real code come from a few patterns:
- calls into libraries the engine cannot see into, which it assumes return everything they were given;
- framework objects seen as holding whatever was put into any part of them;
- a few source rules and key labels that are broader than they should be.

Goal: precision of at least 80% on a labelled corpus of real applications, gated in CI, with no loss of recall.

- Real-application corpus in the eval, gated in CI: [#30](https://github.com/GoNetTools/datawarden/issues/30)
- Library models, which say what unknown library calls return: [#31](https://github.com/GoNetTools/datawarden/issues/31)
- Values seeded by type reach unrelated sinks: [#32](https://github.com/GoNetTools/datawarden/issues/32)
- Source rules conditioned on arguments (`ContentResolver.query`): [#33](https://github.com/GoNetTools/datawarden/issues/33)
- Key labels should respect what the value is: [#34](https://github.com/GoNetTools/datawarden/issues/34)
- Values passed to dynamically dispatched plugin calls: [#35](https://github.com/GoNetTools/datawarden/issues/35)

### v0.3: Developer experience · [#25](https://github.com/GoNetTools/datawarden/issues/25)

Make a finding cheap to act on for the person who gets it in a pull request.

- Inline suppressions with a reason: [#36](https://github.com/GoNetTools/datawarden/issues/36)
- Self-contained HTML report with the flow graph: [#37](https://github.com/GoNetTools/datawarden/issues/37)
- `datawarden explain <fingerprint>`: [#38](https://github.com/GoNetTools/datawarden/issues/38)
- Editor integration: [#39](https://github.com/GoNetTools/datawarden/issues/39)
- Performance targets and a scale benchmark: [#40](https://github.com/GoNetTools/datawarden/issues/40)

### v0.4: Coverage · [#26](https://github.com/GoNetTools/datawarden/issues/26)

Find more of the leaks that matter in the code people actually run.

- OpenTelemetry and APM sinks: [#41](https://github.com/GoNetTools/datawarden/issues/41)
- More SDK and logging sink rules (good first issues): [#42](https://github.com/GoNetTools/datawarden/issues/42)
- Web framework request data as sources: [#43](https://github.com/GoNetTools/datawarden/issues/43)
- Kotlin and Swift parse gaps on real code: [#44](https://github.com/GoNetTools/datawarden/issues/44)
- The next language, chosen by vote: [#45](https://github.com/GoNetTools/datawarden/issues/45)

### v1.0: Stable · [#23](https://github.com/GoNetTools/datawarden/issues/23)

Within 1.x, an upgrade never breaks a CI setup: baselines keep matching, reports keep parsing and configs keep loading. Users can also verify what they install.

- JSON Schemas for the report and config, and a compatibility policy: [#46](https://github.com/GoNetTools/datawarden/issues/46)
- Fingerprint stability, with tests and `baseline migrate`: [#47](https://github.com/GoNetTools/datawarden/issues/47)
- Signed releases, provenance and an SBOM: [#48](https://github.com/GoNetTools/datawarden/issues/48)
- A documentation site: [#49](https://github.com/GoNetTools/datawarden/issues/49)

## What guides the order

1. **Precision before coverage.** Each new rule adds findings; it's only worth it once the existing ones can be trusted.
2. **Measured on real code.** Every precision claim comes from a pinned, labelled corpus that CI re-scores, never from fixtures written to be found.
3. **Explainable over clever.** A finding must say why it exists. We prefer a documented, conservative rule over a heuristic nobody can predict.
4. **Offline and local.** Scanning never sends code or findings anywhere. Only `datawarden comment` talks to the network, to post to your own GitHub or GitLab.

## Not planned

- **A hosted service or dashboard.** The reports (SARIF, JSON, Markdown, and HTML in v0.3) are meant to feed the tools you already use.
- **Runtime monitoring or DLP.** datawarden reads source code and does not observe running systems.
- **Deep secret scanning of git history.** Pair datawarden with gitleaks or GitHub secret scanning; the README explains how to avoid double reports.
