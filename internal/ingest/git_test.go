// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// scripted answers git commands from a table keyed by the joined arguments.
func scripted(answers map[string]string) Runner {
	return func(_ context.Context, dir string, args ...string) ([]byte, error) {
		out, ok := answers[strings.Join(args, " ")]
		if !ok {
			return nil, errors.New("unexpected: git " + strings.Join(args, " "))
		}
		return []byte(out), nil
	}
}

func TestGitStagedAndHead(t *testing.T) {
	ctx := context.Background()
	g := Git{Dir: "/repo", Run: scripted(map[string]string{
		"diff --cached --name-only --relative -z --diff-filter=ACMR": "a.go\x00b/c.kt\x00",
		"show :./a.go":   "package a\n",
		"rev-parse HEAD": "abc123\n",
	})}
	files, err := g.StagedFiles(ctx)
	if err != nil || !reflect.DeepEqual(files, []string{"a.go", "b/c.kt"}) {
		t.Errorf("StagedFiles = %v, %v", files, err)
	}
	if b, err := g.StagedContent(ctx, "a.go"); err != nil || string(b) != "package a\n" {
		t.Errorf("StagedContent = %q, %v", b, err)
	}
	if h := g.HeadCommit(ctx); h != "abc123" {
		t.Errorf("HeadCommit = %q", h)
	}

	broken := Git{Dir: "/repo", Run: scripted(nil)}
	if _, err := broken.StagedFiles(ctx); err == nil || !strings.Contains(err.Error(), "git diff --cached") {
		t.Errorf("errors name the command: %v", err)
	}
	if broken.HeadCommit(ctx) != "" {
		t.Error("HeadCommit outside a repository")
	}
	if _, err := (Git{}).StagedFiles(ctx); err == nil {
		t.Error("missing runner accepted")
	}
}

func TestNoVCS(t *testing.T) {
	ctx := context.Background()
	var v NoVCS
	if _, err := v.ChangedFiles(ctx, "main"); !errors.Is(err, ErrNoVCS) {
		t.Error("ChangedFiles")
	}
	if _, err := v.StagedFiles(ctx); !errors.Is(err, ErrNoVCS) {
		t.Error("StagedFiles")
	}
	if _, err := v.StagedContent(ctx, "a"); !errors.Is(err, ErrNoVCS) {
		t.Error("StagedContent")
	}
	if v.HeadCommit(ctx) != "" {
		t.Error("HeadCommit")
	}
}
