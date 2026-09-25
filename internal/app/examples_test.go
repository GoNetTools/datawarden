// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/lang"
	"github.com/GoNetTools/pii-scanner/internal/rules"
	"github.com/GoNetTools/pii-scanner/internal/ruletest"
)

// TestRuleExamples scans the annotated examples of every built-in rule
// (internal/rules/testdata/examples/<language>/) and checks each `ruleid:`
// and `ok:` annotation. A built-in rule without an example fails the test.
func TestRuleExamples(t *testing.T) {
	set, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	covered, ran := runAnnotated(t, set, "../rules/testdata/examples")
	for _, id := range ruletest.Missing(set, covered, ran) {
		t.Errorf("rule %s has no example: add a `ruleid: %s` annotation under internal/rules/testdata/examples/<language>/", id, id)
	}
}

// runAnnotated scans each language directory under root as a repository
// and checks its annotations against the findings. It returns the rule ids
// the examples cover and the languages it could run.
func runAnnotated(t *testing.T, set *rules.Set, root string) (covered, ran map[string]bool) {
	t.Helper()
	covered, ran = map[string]bool{}, map[string]bool{}
	available := NewComponents(time.Now).Frontends.Languages()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		l, ok := lang.Lookup(e.Name())
		if !ok || l.Kind != lang.Code || l.Name != e.Name() {
			t.Errorf("%s/%s: name each directory after a code language in internal/lang (%v)", root, e.Name(), lang.CodeNames())
			continue
		}
		dir := filepath.Join(root, e.Name())
		t.Run(l.Name, func(t *testing.T) {
			if !slices.Contains(available, l.Name) {
				t.Skipf("no %s frontend in this build", l.Name)
			}
			if l.Name == lang.Go {
				if _, err := exec.LookPath("go"); err != nil {
					t.Skip("go toolchain not available")
				}
			}
			ran[l.Name] = true
			_, r := scanJSON(t, dir)
			for _, w := range r.Warnings {
				t.Logf("scan warning: %s", w)
			}
			anns, err := ruletest.Parse(os.DirFS(dir), ".")
			if err != nil {
				t.Fatal(err)
			}
			if len(anns) == 0 {
				t.Fatalf("%s has no annotations", dir)
			}
			res := ruletest.Check(set, anns, r.Flows)
			for _, f := range res.Failures {
				t.Errorf("%s/%s", dir, f)
			}
			for _, k := range res.Known {
				t.Logf("%s/%s", dir, k)
			}
			for id := range res.Covered {
				covered[id] = true
			}
		})
	}
	return covered, ran
}
