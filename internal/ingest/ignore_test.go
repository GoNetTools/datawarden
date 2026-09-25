// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/datawarden/internal/lang"
)

func TestMatcher(t *testing.T) {
	m := NewMatcher(append(DefaultIgnore,
		"# comment",
		"*.generated.ts",
		"/docs/",
		"fixtures/**/fake-*.json",
		"!build/",
		"secret?.txt",
		"src/**/legacy/",
	))
	cases := []struct {
		path string
		dir  bool
		want bool
	}{
		{"node_modules/x/index.js", false, true},
		{"app/node_modules", true, true},
		{"src/api.generated.ts", false, true},
		{"src/api.ts", false, false},
		{"docs/readme.md", false, true},
		{"src/docs/readme.md", false, false},
		{"fixtures/a/b/fake-users.json", false, true},
		{"fixtures/real-users.json", false, false},
		{"build/out.kt", false, false}, // re-included by !build/
		{"secret1.txt", false, true},
		{"secret12.txt", false, false},
		{"src/main/legacy/Old.java", false, true},
		{"logo.png", false, true},
		{"go.sum", false, true},
		{".datawarden/cache/datawarden-cache.json", false, true},
		{".datawarden/rules/examples/src/telemetry.ts", false, true},
		{".datawarden/rules/acme.yaml", false, false},
	}
	for _, c := range cases {
		if got := m.Ignored(c.path, c.dir); got != c.want {
			t.Errorf("Ignored(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	for p, want := range map[string]bool{
		"app/src/test/java/Foo.java": true, "pkg/x_test.go": true, "app/FooTest.kt": true, "web/app.spec.ts": true,
		"web/__tests__/a.ts": true, "src/main/Foo.kt": false, "pkg/x.go": false,
	} {
		if got := IsTestPath(p); got != want {
			t.Errorf("IsTestPath(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestWalkSelectAndHash(t *testing.T) {
	fsys := fstest.MapFS{
		"main.go":                     {Data: []byte("package main")},
		"app/src/main/A.kt":           {Data: []byte("class A")},
		"app/build/gen/B.kt":          {Data: []byte("class B")},
		"web/node_modules/x/index.js": {Data: []byte("x")},
		"web/src/app.test.ts":         {Data: []byte("t")},
		"docs/logo.png":               {Data: []byte{0x89}},
		".datawardenignore":           {Data: []byte("docs/\n")},
	}
	m, err := LoadMatcher(fsys)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Walk(fsys, m)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Rel)
	}
	want := []string{".datawardenignore", "app/src/main/A.kt", "main.go", "web/src/app.test.ts"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("walk = %v, want %v", got, want)
	}
	if !files[3].Test || files[1].Lang != lang.Kotlin {
		t.Errorf("classification: %+v", files)
	}
	if sel := Select(fsys, files, []string{"app", "./main.go"}); len(sel) != 2 {
		t.Errorf("select: %+v", sel)
	}
	h := NewHasher(fsys)
	a := h.Hash("main.go")
	if a == "" || h.Hash("missing.go") != "" {
		t.Errorf("hash: %q", a)
	}
}

func TestGitWithFakeRunner(t *testing.T) {
	var calls []string
	run := func(_ context.Context, dir string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "merge-base":
			return []byte("abc123\n"), nil
		case "diff":
			return []byte("src/a.ts\x00src/b.ts\x00"), nil
		case "ls-files":
			return []byte("new.ts\x00src/a.ts\x00"), nil
		}
		return nil, errors.New("unexpected")
	}
	g := Git{Dir: "/repo", Run: run}
	files, err := g.ChangedFiles(context.Background(), "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(files, ",") != "new.ts,src/a.ts,src/b.ts" {
		t.Errorf("changed = %v", files)
	}
	if calls[1] != "diff --name-only --relative -z --diff-filter=ACMRT abc123" {
		t.Errorf("diff call: %q", calls[1])
	}
	if _, err := (NoVCS{}).ChangedFiles(context.Background(), "main"); !errors.Is(err, ErrNoVCS) {
		t.Error("NoVCS")
	}
}
