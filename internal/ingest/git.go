// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Runner runs git with args in dir and returns its standard output. The
// production implementation (platform.ExecGit) shells out to the git
// binary; tests pass a fake.
type Runner func(ctx context.Context, dir string, args ...string) ([]byte, error)

// Git answers version-control questions for a working tree.
type Git struct {
	Dir string
	Run Runner
}

func (g Git) git(ctx context.Context, args ...string) (string, error) {
	if g.Run == nil {
		return "", errors.New("git: no runner configured")
	}
	out, err := g.Run(ctx, g.Dir, args...)
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func splitZ(out string) []string {
	var files []string
	for _, s := range strings.Split(out, "\x00") {
		if s = strings.TrimSpace(s); s != "" {
			files = append(files, s)
		}
	}
	return files
}

// ChangedFiles returns files (relative to Dir) that differ between the
// merge base of base and HEAD and the working tree, plus untracked files.
// Deleted files are not returned.
func (g Git) ChangedFiles(ctx context.Context, base string) ([]string, error) {
	mb, err := g.git(ctx, "merge-base", base, "HEAD")
	if err != nil {
		return nil, fmt.Errorf("resolving diff base %q (in CI, fetch it first, e.g. `git fetch origin main`): %w", base, err)
	}
	diff, err := g.git(ctx, "diff", "--name-only", "--relative", "-z", "--diff-filter=ACMRT", strings.TrimSpace(mb))
	if err != nil {
		return nil, err
	}
	untracked, err := g.git(ctx, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range append(splitZ(diff), splitZ(untracked)...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// StagedFiles lists files added, copied, modified or renamed in the index.
func (g Git) StagedFiles(ctx context.Context) ([]string, error) {
	out, err := g.git(ctx, "diff", "--cached", "--name-only", "--relative", "-z", "--diff-filter=ACMR")
	if err != nil {
		return nil, err
	}
	return splitZ(out), nil
}

// StagedContent returns the staged (index) version of a file.
func (g Git) StagedContent(ctx context.Context, rel string) ([]byte, error) {
	out, err := g.git(ctx, "show", ":./"+rel)
	return []byte(out), err
}

// HeadCommit returns the current commit, or "" outside a repository.
func (g Git) HeadCommit(ctx context.Context) string {
	s, err := g.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// ErrNoVCS is returned by NoVCS for operations that need version control.
var ErrNoVCS = errors.New("not a git repository")

// NoVCS is used outside version control: full scans work, --diff and
// --staged report ErrNoVCS.
type NoVCS struct{}

// ChangedFiles implements scan.VCS.
func (NoVCS) ChangedFiles(context.Context, string) ([]string, error) { return nil, ErrNoVCS }

// StagedFiles implements scan.VCS.
func (NoVCS) StagedFiles(context.Context) ([]string, error) { return nil, ErrNoVCS }

// StagedContent implements scan.VCS.
func (NoVCS) StagedContent(context.Context, string) ([]byte, error) { return nil, ErrNoVCS }

// HeadCommit implements scan.VCS.
func (NoVCS) HeadCommit(context.Context) string { return "" }
