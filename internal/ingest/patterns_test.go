// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import "testing"

// Ignore patterns follow .gitignore: a pattern without a slash matches at
// any depth, a leading or middle slash anchors it to the root, a trailing
// slash matches directories only, and "!" re-includes.
func TestIgnorePatternSyntax(t *testing.T) {
	m := NewMatcher([]string{
		"*.pb.go",
		"/root-only.txt",
		"docs/*.md",
		"**/gen/**",
		"logs/",
		"file?.txt",
		"[ab].kt",
		"[!x]y.ts",
		`\#notes.txt`,
		"broken[",
		"secrets/**",
		"!secrets/public.txt",
	})
	for _, c := range []struct {
		path string
		dir  bool
		want bool
	}{
		{"api/user.pb.go", false, true},
		{"root-only.txt", false, true},
		{"sub/root-only.txt", false, false},
		{"docs/a.md", false, true},
		{"docs/deep/a.md", false, false},
		{"x/gen/y/z.go", false, true},
		{"gen/z.go", false, true},
		{"logs", true, true},
		{"logs", false, false},
		{"app/logs/today.txt", false, true},
		{"file1.txt", false, true},
		{"file12.txt", false, false},
		{"a.kt", false, true},
		{"c.kt", false, false},
		{"zy.ts", false, true},
		{"xy.ts", false, false},
		{"#notes.txt", false, true},
		{"broken[", false, true},
		{"secrets/key.pem", false, true},
		{"secrets/public.txt", false, false},
	} {
		if got := m.Ignored(c.path, c.dir); got != c.want {
			t.Errorf("Ignored(%q, dir=%v) = %v, want %v", c.path, c.dir, got, c.want)
		}
	}
}
