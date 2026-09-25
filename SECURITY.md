# Security policy

pii-scanner looks for personal data in other people's code, so it handles sensitive material by design. We take reports about pii-scanner itself seriously.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: go to the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/GoNetTools/pii-scanner/security/advisories/new)). Include:

- the pii-scanner version (`pii-scanner version`) and how you installed it (release binary, Docker image, `go install`, GitHub Action, pre-commit);
- what an attacker controls (the scanned repository, its `.pii-scanner.yaml` or rule files, a pull request, CI environment variables, …) and what they gain;
- a minimal reproduction. **Use synthetic data only**: never send real personal data, even to show that it leaks.

We aim to acknowledge a report within 3 working days and to agree on a fix and disclosure date with you. Reporters are credited in the advisory unless they prefer otherwise.

## Supported versions

Security fixes are released for the latest minor version. Before 1.0, that means the newest `v0.x` release only.

## Scope

In scope, for example:

- pii-scanner writing **unmasked personal data** found in a scanned repository to its outputs: text/JSON/SARIF/Markdown/GitLab reports, the PR/MR comment, the baseline, the data map or the cache in `.pii-scanner/cache/`;
- a crafted repository, config file, rule file, baseline or cache that makes pii-scanner write outside the repository or its configured output paths, run commands, or crash in a way that hides findings;
- leaking the CI token used by `pii-scanner comment` or the GitHub Action;
- problems with release artifacts: binaries, checksums, the container image, the GitHub Action's download and verification step.

Out of scope (please open a normal issue instead):

- leaks pii-scanner **misses** (false negatives) or reports wrongly (false positives), unless they are caused by a flaw an attacker can trigger on purpose to hide a leak;
- vulnerabilities in third-party dependencies with no demonstrated impact on pii-scanner (Dependabot and `govulncheck` in CI track those).

## How pii-scanner handles scanned data

- **Values are masked.** Literal findings show masked values (for example `091*****78`). The baseline stores a truncated SHA-256 of the value, never the value itself. Phone and ID numbers have few enough possible values that such a hash can be brute-forced, so treat the baseline as no more secret than the files it describes, and remove real personal data from the repository instead of baselining it.
- **Scans are offline.** Only `pii-scanner comment` (which the GitHub Action calls) talks to the network, to post the Markdown summary to the GitHub or GitLab API with the token from the environment.
- **Scanning Go code runs the Go toolchain.** The Go frontend loads packages with `go/packages`, which runs `go list` and compiles dependencies for type information (including cgo preprocessing), and may download modules or the toolchain named in `go.mod`, as `go build` would. Treat scanning untrusted Go code like building it: run it in CI or in the Docker image, not on a workstation with secrets.
- Kotlin, Java and TypeScript are parsed with tree-sitter; no code from the scanned repository is executed for them.
