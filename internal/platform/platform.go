// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package platform holds the production adapters that touch the operating
// system: the local file system, the git binary and cache files. Domain
// packages depend on interfaces and fs.FS; only internal/app wires these.
package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/ingest"
	"github.com/GoNetTools/pii-scanner/internal/scan"
)

// ExecGit runs the git binary (an ingest.Runner).
func ExecGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// OS is the cli.Workspace on the local machine.
type OS struct {
	// Git runs git commands; ExecGit in production.
	Git ingest.Runner
}

// Getwd implements cli.Workspace.
func (OS) Getwd() (string, error) { return os.Getwd() }

// Abs implements cli.Workspace.
func (OS) Abs(p string) (string, error) { return filepath.Abs(p) }

// IsDir implements cli.Workspace.
func (OS) IsDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// FindRoot implements cli.Workspace: the nearest directory with .git or
// .datawarden.yaml, or dir itself.
func (OS) FindRoot(dir string) string {
	d := dir
	for {
		for _, marker := range []string{".git", ".datawarden.yaml"} {
			if _, err := os.Stat(filepath.Join(d, marker)); err == nil {
				return d
			}
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir
		}
		d = parent
	}
}

// Open implements cli.Workspace.
func (o OS) Open(root string) scan.Repo {
	return scan.Repo{Root: root, FS: os.DirFS(root), VCS: ingest.Git{Dir: root, Run: o.Git}}
}

// ReadFile implements cli.Workspace.
func (OS) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

// WriteFile implements cli.Workspace.
func (OS) WriteFile(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// FileBlob stores the analysis cache in a file (a cache.Persister). The
// directory gets a .gitignore so the cache is never committed.
type FileBlob struct{ Path string }

// Load implements cache.Persister.
func (f FileBlob) Load() ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Save implements cache.Persister (atomic rename).
func (f FileBlob) Save(data []byte) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	gi := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gi); os.IsNotExist(err) {
		_ = os.WriteFile(gi, []byte("*\n"), 0o644)
	}
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}
