# Releasing datawarden

For maintainers. A release is a pushed version tag; `.github/workflows/release.yml` does the rest.

## What the release workflow does

On a tag matching `v<major>.<minor>.<patch>[-suffix]`:

1. **test**: `go vet` and the test suites with and without cgo.
2. **binaries**: builds `datawarden` natively with cgo for linux amd64/arm64 (static), macOS arm64/amd64 and windows amd64, and smoke-tests each one on its runner.
3. **package**: `datawarden_<os>_<arch>.tar.gz` (`.zip` on Windows) with the binary, `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md` and `THIRD_PARTY_LICENSES.txt`, reproducible (fixed timestamps and owners), plus `checksums.txt` (SHA-256).
4. **image**: `ghcr.io/gonettools/datawarden` for linux/amd64 and linux/arm64, tagged `<version>` and `<major>.<minor>` (and `<major>` from 1.0 on). `latest` moves only for tags without a suffix.
5. **publish**: creates the GitHub release with generated notes and the archives, and moves the major tag (`v0`) that `uses: GoNetTools/datawarden@v0` resolves to. Tags with a suffix (`v0.2.0-rc.1`) are pre-releases and move neither `latest` nor `v0`.

## Before tagging

- [ ] `main` is green in CI, including the accuracy check (`make eval-external`).
- [ ] `make check` passes locally, and `make release-local VERSION=vX.Y.Z` builds an archive for your platform. Unpack it and run `./datawarden version` and `./datawarden scan testdata/vulnshop --root testdata/vulnshop --no-fail`.
- [ ] `CHANGELOG.md`: move the `[Unreleased]` entries under `## [X.Y.Z] - YYYY-MM-DD`, and call out anything that changes baseline fingerprints, rule ids, report fields or configuration keys.
- [ ] If the cache format or analysis semantics changed, `cache.FormatVersion` was bumped (old caches are then ignored, not misread).
- [ ] The README's [results on real applications](../README.md#results-on-real-applications) are still true, or rerun and updated for an analysis change.

## Tagging

```sh
git switch main && git pull
git tag -a v0.2.0 -m v0.2.0
git push origin v0.2.0
```

Watch **Actions → release**. When it finishes:

- [ ] The release page lists five archives and `checksums.txt`.
- [ ] The install snippet from the README works against it.
- [ ] `docker run --rm ghcr.io/gonettools/datawarden:0.2.0 version` prints the version.
- [ ] A workflow using `GoNetTools/datawarden@v0` picks up the new version (the job log prints it).

If the major tag could not be moved (the job summary warns; `GITHUB_TOKEN` cannot move a tag across commits that change workflow files), move it by hand: `git tag -f v0 v0.2.0^{} && git push -f origin v0`. Setting a `RELEASE_TAG_TOKEN` secret (a fine-grained token with contents and workflows write) avoids that.

A broken release is fixed with a new patch release. Don't move or delete a published version tag: users pin versions and the Action verifies archives against `checksums.txt`.

## One-time setup for a public repository

These are repository settings, not code, so they are done once by an admin:

- [ ] **Settings → General**: make the repository public; allow forking; enable **Discussions** (the README and the issue template point questions there).
- [ ] **Settings → Code security**: enable **Private vulnerability reporting** (SECURITY.md and the Code of Conduct rely on it), Dependabot alerts and secret scanning.
- [ ] **Settings → Branches**: protect `main`, require the `ci` checks and a review from a code owner.
- [ ] **Packages**: after the first release, set the `datawarden` container package's visibility to public and link it to the repository.
- [ ] Optionally add the `RELEASE_TAG_TOKEN` secret described above.
- [ ] Optionally list the Action on the GitHub Marketplace from the release page (the `action.yml` metadata is ready).
