// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestLoad(t *testing.T) {
	fsys := fstest.MapFS{
		".datawarden.yaml": {Data: []byte("first_party_domains: [api.acme.vn]\npolicy:\n  fail_on: [third_party]\n")},
		"bad.yaml":         {Data: []byte("policy:\n  fail_on: [moon]\n")},
	}
	c, err := Load(fsys, FileName, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.FirstPartyDomains) != 1 || len(c.Policy.FailOn) != 1 || *c.Literals.Enabled != true || c.Baseline != ".datawarden/baseline.json" {
		t.Errorf("merged config: %+v", c)
	}
	if c, err := Load(fstest.MapFS{}, FileName, false); err != nil || c.Path != "" {
		t.Errorf("missing optional config: %v", err)
	}
	if _, err := Load(fstest.MapFS{}, "custom.yaml", true); err == nil {
		t.Error("missing required config accepted")
	}
	if _, err := Load(fsys, "bad.yaml", true); err == nil {
		t.Error("invalid destination kind accepted")
	}
}

func TestAbsAndLoader(t *testing.T) {
	// \repo is not absolute on Windows; the temp directory's volume makes it so.
	root := filepath.Join(filepath.VolumeName(os.TempDir())+string(filepath.Separator), "repo")
	if Abs(root, "") != "" || Abs(root, root) != root || Abs(root, "a/b") != filepath.Join(root, "a", "b") {
		t.Error("Abs")
	}
	var l Loader
	c, err := l.Parse([]byte("languages: [kt, golang]\npolicy:\n  min_confidence: 0.7\n"), "x.yaml")
	if err != nil || c.Policy.MinConfidence != 0.7 || len(c.Languages) != 2 {
		t.Fatalf("Parse: %+v %v", c, err)
	}
	for name, doc := range map[string]string{
		"unknown language": "languages: [cobol]\n",
		"bad kind":         "policy:\n  fail_on: [nowhere]\n",
		"bad class kind":   "policy:\n  classes:\n    phi:\n      fail_on: [nowhere]\n",
		"bad guarded kind": "policy:\n  consent_guarded: [nowhere]\n",
		"bad class guard":  "policy:\n  classes:\n    phi:\n      consent_guarded: [nowhere]\n",
		"not yaml":         "policy: [\n",
	} {
		if _, err := l.Parse([]byte(doc), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if c, err := l.Load(fstest.MapFS{}, FileName, false); err != nil || c.Policy.MinConfidence == 0 {
		t.Errorf("missing optional file gives defaults: %+v %v", c, err)
	}
	if _, err := l.Load(fstest.MapFS{}, FileName, true); err == nil {
		t.Error("missing required file accepted")
	}
}
