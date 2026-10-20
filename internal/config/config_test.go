// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
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

func TestLoader(t *testing.T) {
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

func TestSensitiveMarkers(t *testing.T) {
	c, err := Parse([]byte("schema:\n  sensitive_markers: [mask, \"@Masked\"]\n"), ".datawarden.yaml")
	if err != nil || len(c.Schema.SensitiveMarkers) != 2 || c.Schema.SensitiveMarkers[1] != "@Masked" {
		t.Fatalf("markers: %+v %v", c.Schema, err)
	}
	for _, bad := range []string{"schema:\n  sensitive_markers: [\"@\"]\n", "schema:\n  sensitive_markers: [\"pii:email\"]\n", "schema:\n  sensitive_markers: [\" \"]\n"} {
		if _, err := Parse([]byte(bad), ".datawarden.yaml"); err == nil || !strings.Contains(err.Error(), "sensitive_markers") {
			t.Errorf("%q: accepted (%v)", bad, err)
		}
	}
	if _, err := Parse([]byte(Template), ".datawarden.yaml"); err != nil {
		t.Errorf("template: %v", err)
	}
}

func TestFrontends(t *testing.T) {
	c, err := Parse([]byte("frontends:\n  - {lang: Ruby, extensions: [.RB, .rake], command: [ruby, tools/dw.rb]}\n  - {lang: java, command: [./dw-java]}\nlanguages: [ruby, go]\n"), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Frontends) != 2 || c.Frontends[0].Lang != "ruby" || c.Frontends[0].Extensions[0] != ".rb" || c.Frontends[1].Lang != "java" {
		t.Errorf("frontends: %+v", c.Frontends)
	}
	if got := strings.Join(c.CodeLanguages(), ","); got != "go,java,kotlin,python,ruby,swift,typescript" {
		t.Errorf("code languages = %s", got)
	}
	bad := map[string]string{
		"no command":           "frontends:\n  - {lang: ruby, extensions: [.rb]}\n",
		"no lang":              "frontends:\n  - {extensions: [.rb], command: [ruby]}\n",
		"no extensions":        "frontends:\n  - {lang: ruby, command: [ruby]}\n",
		"bad extension":        "frontends:\n  - {lang: ruby, extensions: [rb], command: [ruby]}\n",
		"twice":                "frontends:\n  - {lang: ruby, extensions: [.rb], command: [ruby]}\n  - {lang: ruby, extensions: [.rbx], command: [ruby]}\n",
		"unknown in languages": "languages: [ruby]\n",
	}
	for name, doc := range bad {
		if _, err := Parse([]byte(doc), "x.yaml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
