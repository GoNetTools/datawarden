// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GoNetTools/datawarden/internal/rules"
)

// TestScenarios runs the scenario programs under testdata/scenarios: the
// same leaks written in every supported language, annotated with
// `ruleid:` and `ok:` like the rule examples (see testdata/scenarios/README.md).
func TestScenarios(t *testing.T) {
	set, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	runAnnotated(t, set, filepath.Join("..", "..", "testdata", "scenarios"))
}

// TestScenarioLiterals checks the committed values under
// testdata/scenarios/literals against literals/expected.yaml: every
// listed value is reported at its line, and no look-alike is.
func TestScenarioLiterals(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "scenarios", "literals")
	type at struct {
		File     string
		Line     int
		DataType string `yaml:"data_type"`
	}
	var want struct {
		Findings    []at
		NotReported []at `yaml:"not_reported"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	_, r := scanJSON(t, dir, "--literals-only", "--no-baseline")
	got := map[string]int{}
	for _, l := range r.Literals {
		got[l.Pos.File+":"+l.DataType] |= 1 << uint(l.Pos.Line%60)
		got[l.Pos.File] |= 1 << uint(l.Pos.Line%60)
	}
	for _, f := range want.Findings {
		if got[f.File+":"+f.DataType]&(1<<uint(f.Line%60)) == 0 {
			t.Errorf("%s:%d: %s not reported", f.File, f.Line, f.DataType)
		}
	}
	for _, n := range want.NotReported {
		if got[n.File]&(1<<uint(n.Line%60)) != 0 {
			t.Errorf("%s:%d: look-alike reported", n.File, n.Line)
		}
	}
}
