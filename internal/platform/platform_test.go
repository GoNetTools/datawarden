// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// TestHelperProcess is the program TestExecCommand runs: it copies its
// standard input to its standard output upper-cased, or fails when told to.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("DATAWARDEN_HELPER") != "1" {
		return
	}
	in, _ := io.ReadAll(os.Stdin)
	if os.Getenv("DATAWARDEN_HELPER_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "boom:", string(in))
		os.Exit(3)
	}
	fmt.Print(strings.ToUpper(string(in)))
	os.Exit(0)
}

func TestExecCommand(t *testing.T) {
	t.Setenv("DATAWARDEN_HELPER", "1")
	argv := []string{os.Args[0], "-test.run=^TestHelperProcess$"}
	out, err := ExecCommand(context.Background(), t.TempDir(), argv, []byte("hello"))
	if err != nil || string(out) != "HELLO" {
		t.Errorf("out = %q, err = %v", out, err)
	}
	t.Setenv("DATAWARDEN_HELPER_FAIL", "1")
	_, err = ExecCommand(context.Background(), t.TempDir(), argv, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "boom: x") {
		t.Errorf("failure: %v", err)
	}
	if _, err := ExecCommand(context.Background(), "", nil, nil); err == nil {
		t.Error("empty command accepted")
	}
}
