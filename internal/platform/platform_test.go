// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/GoNetTools/datawarden/internal/scan"
)

// These are adapter tests: they touch the real file system on purpose.

func TestFileBlob(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cache", "c.json")
	b := FileBlob{Path: p}
	if data, err := b.Load(); err != nil || data != nil {
		t.Fatalf("missing file: %v %v", data, err)
	}
	if err := b.Save([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if data, _ := b.Load(); string(data) != "{}" {
		t.Errorf("round trip: %q", data)
	}
	if gi, _ := os.ReadFile(filepath.Join(filepath.Dir(p), ".gitignore")); string(gi) != "*\n" {
		t.Error("cache directory should be git-ignored")
	}
}

func TestOSWorkspace(t *testing.T) {
	root := t.TempDir()
	o := OS{Git: ExecGit}
	if err := o.WriteFile(filepath.Join(root, ".datawarden.yaml"), []byte("version: 1\n")); err != nil {
		t.Fatal(err)
	}
	if err := o.WriteFile(filepath.Join(root, "src", "a.go"), []byte("package a")); err != nil {
		t.Fatal(err)
	}
	if got := o.FindRoot(filepath.Join(root, "src")); got != root {
		t.Errorf("FindRoot = %s, want %s", got, root)
	}
	repo := o.Open(root)
	if b, err := readFS(repo, "src/a.go"); err != nil || b != "package a" {
		t.Errorf("repo FS: %q %v", b, err)
	}
	if _, err := exec.LookPath("git"); err == nil && repo.VCS.HeadCommit(context.Background()) != "" {
		t.Error("HeadCommit outside a git repository should be empty")
	}
}

func readFS(r scan.Repo, name string) (string, error) {
	b, err := fs.ReadFile(r.FS, name)
	return string(b), err
}

func TestOSGetwdAndIsDir(t *testing.T) {
	var o OS
	wd, err := o.Getwd()
	if err != nil || wd == "" {
		t.Fatalf("Getwd: %q %v", wd, err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := o.WriteFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !o.IsDir(dir) || o.IsDir(file) || o.IsDir(filepath.Join(dir, "missing")) {
		t.Error("IsDir")
	}
	if abs, err := o.Abs("rel"); err != nil || !filepath.IsAbs(abs) {
		t.Errorf("Abs: %q %v", abs, err)
	}
	if b, err := o.ReadFile(file); err != nil || string(b) != "x" {
		t.Errorf("ReadFile: %q %v", b, err)
	}
	if got := o.FindRoot(dir); got != dir {
		t.Errorf("FindRoot without markers returns the directory itself: %s", got)
	}
}
