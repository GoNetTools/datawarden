// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"testing/fstest"
)

func TestLoad(t *testing.T) {
	fsys := fstest.MapFS{
		".piiflow.yaml": {Data: []byte("first_party_domains: [api.acme.vn]\npolicy:\n  fail_on: [third_party]\n")},
		"bad.yaml":      {Data: []byte("policy:\n  fail_on: [moon]\n")},
	}
	c, err := Load(fsys, FileName, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.FirstPartyDomains) != 1 || len(c.Policy.FailOn) != 1 || *c.Literals.Enabled != true || c.Baseline != ".piiflow/baseline.json" {
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
