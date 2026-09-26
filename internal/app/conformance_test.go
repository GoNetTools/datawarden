// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/GoNetTools/datawarden/internal/lang"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// conformanceScenarios are the constructs every frontend must lower so the
// taint engine can follow personal data through them. Each language's
// directory under internal/frontend/testdata/conformance implements all of
// them, marked with a `scenario: <name>` comment and annotated with the
// language's logging sink. A new frontend starts by porting these programs.
var conformanceScenarios = map[string]string{
	"param":                "a parameter with a PII name reaches a sink",
	"local":                "through a local variable",
	"concat":               "through string concatenation or interpolation",
	"field":                "a field with a PII name, read from an object",
	"getter":               "a method that returns a PII field",
	"key":                  "an unnamed value stored under a PII key (map, object literal)",
	"call-arg":             "into a helper that logs its argument (reported in the helper)",
	"call-return":          "out of a helper's return value",
	"closure":              "inside a closure or lambda",
	"field-store":          "stored into a field, then read back",
	"collection":           "added to a collection that is then logged",
	"object":               "a whole object whose type has PII fields",
	"masked":               "a masking function makes the flow acceptable (ok)",
	"not-pii":              "identifiers and counts are not personal data (ok)",
	"negative-context":     "names like phoneCount or emailTemplate are not personal data (ok)",
	"overwritten":          "a variable overwritten with a non-personal value no longer carries the data (ok)",
	"remasked":             "a variable reassigned to its own masked value (ok)",
	"branch-merge":         "assigned on one branch of an if, the data reaches a sink after the if",
	"loop-carried":         "assigned late in a loop body, the data reaches a sink early in the next iteration",
	"mutated-later":        "an object logged before personal data is added to it (ok)",
	"early-return":         "a value assigned on a path that returns does not reach the code after it (ok)",
	"break-exit":           "a value assigned before a break reaches the code after the loop",
	"continue-skip":        "a value assigned before a continue does not reach the rest of the body (ok)",
	"snapshot":             "a string built from an object before data is added to it (ok)",
	"constant-condition":   "code under a condition that is a declared false constant never runs (ok)",
	"field-across-methods": "stored in a field by the constructor, logged by another method",
	"dynamic-dispatch":     "through an interface or protocol call into an implementation",
	"exception":            "thrown inside an exception, caught and logged",
	"lambda-variable":      "a lambda stored in a variable and called with the data",
}

var scenarioRe = regexp.MustCompile(`(?m)^\s*(?://+|#+)\s*scenario:\s*([a-z-]+)\s*$`)

// TestFrontendConformance runs the conformance programs of every language
// through the full scan. Each language must implement every scenario;
// constructs a frontend cannot follow yet are marked todoruleid.
func TestFrontendConformance(t *testing.T) {
	root := "../frontend/testdata/conformance"
	set, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, ran := runAnnotated(t, set, root)

	available := NewComponents(time.Now).Frontends.Languages()
	for _, l := range lang.CodeNames() {
		if !slices.Contains(available, l) {
			continue
		}
		dir := filepath.Join(root, l)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("%s has no conformance programs: port %s/go to %s", l, root, dir)
			continue
		}
		if !ran[l] {
			continue // skipped (no go toolchain)
		}
		found := map[string]bool{}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range scenarioRe.FindAllStringSubmatch(string(b), -1) {
				if _, ok := conformanceScenarios[m[1]]; !ok {
					t.Errorf("%s: unknown scenario %q", p, m[1])
				}
				found[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var missing []string
		for s := range conformanceScenarios {
			if !found[s] {
				missing = append(missing, s)
			}
		}
		sort.Strings(missing)
		for _, s := range missing {
			t.Errorf("%s: scenario %q is missing (%s)", dir, s, conformanceScenarios[s])
		}
	}
}
