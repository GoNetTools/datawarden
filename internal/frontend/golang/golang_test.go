// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package golang

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/tools/go/packages"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
)

func TestModulesAreLoadedThroughTheInjectedLoader(t *testing.T) {
	fsys := fstest.MapFS{
		"svc/go.mod":          {Data: []byte("module example.com/svc\n")},
		"svc/api/handler.go":  {Data: []byte("package api")},
		"svc/store/db.go":     {Data: []byte("package store")},
		"tools/gen/main.go":   {Data: []byte("package main")}, // no go.mod above
		"other/go.mod":        {Data: []byte("module example.com/other\n")},
		"other/cmd/x/main.go": {Data: []byte("package main")},
	}
	type call struct {
		dir      string
		patterns []string
	}
	var calls []call
	load := func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		calls = append(calls, call{cfg.Dir, patterns})
		if strings.HasSuffix(cfg.Dir, "other") {
			return nil, errors.New("go list failed")
		}
		return nil, nil
	}
	// Lower resolves Root with filepath.Abs; on Windows `\repo` gains a drive letter.
	root, err := filepath.Abs(filepath.Join(string(filepath.Separator), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	fe := New(frontend.Options{Root: root, FS: fsys}, load)
	mod, err := fe.Lower(context.Background(), []string{"svc/api/handler.go", "svc/store/db.go", "tools/gen/main.go", "other/cmd/x/main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[1].dir != filepath.Join(root, "svc") || strings.Join(calls[1].patterns, " ") != "./api ./store" {
		t.Errorf("svc load: %+v", calls[1])
	}
	warn := strings.Join(mod.Warnings, "\n")
	if !strings.Contains(warn, "tools/gen/main.go is not inside a Go module") || !strings.Contains(warn, "go list failed") {
		t.Errorf("warnings: %s", warn)
	}
	if modulePath(fsys, "svc") != "example.com/svc" {
		t.Error("module path")
	}
}
