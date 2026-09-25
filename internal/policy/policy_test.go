// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/config"
	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

func TestApply(t *testing.T) {
	c := config.Default()
	c.Policy.Allow = []config.Allow{{Sink: "sdk.sentry.*", DataTypes: []string{"email"}, Reason: "DPA"}, {Path: "legacy/**"}}
	mk := func(dt, rule, kind string, xf ...string) *finding.Flow {
		return &finding.Flow{DataType: dt, SinkRule: rule, Dest: finding.Destination{Kind: kind, FirstParty: kind == "first_party"}, Confidence: 0.9, Transforms: xf, Sink: ir.Pos{File: "app/a.kt"}}
	}
	legacy := mk("phone", "log.android.logcat", "log")
	legacy.Sink.File = "legacy/old/x.kt"
	flows := []*finding.Flow{
		mk("email", "sdk.sentry.set_user", "third_party"),  // allowed by rule
		mk("phone", "sdk.sentry.set_user", "third_party"),  // violation, high
		mk("phone", "log.android.logcat", "log", "masked"), // safe transform
		mk("phone", "log.android.logcat", "log", "sha256"), // hashes are not safe by default
		mk("email", "storage.go.gorm", "first_party"),      // first party
		mk("health", "log.android.logcat", "log"),          // sensitive -> high
		legacy, // path allow
	}
	got, _ := Evaluator{Config: c, Catalog: detect.NewClassifier(detect.DefaultTaxonomy())}.Apply(flows, nil)
	want := []struct {
		violation bool
		sev       string
	}{{false, High}, {true, High}, {false, Medium}, {true, Medium}, {false, Low}, {true, High}, {false, Medium}}
	for i, w := range want {
		if got[i].Violation != w.violation || got[i].Severity != w.sev {
			t.Errorf("flow %d (%s %s %v): violation=%v sev=%s allowed=%q, want %v %s", i, got[i].DataType, got[i].SinkRule, got[i].Transforms, got[i].Violation, got[i].Severity, got[i].Allowed, w.violation, w.sev)
		}
	}
}

type fakeCatalog map[string]bool

func (f fakeCatalog) Lookup(id string) detect.DataType {
	return detect.DataType{ID: id, Sensitive: f[id]}
}

func TestSeverityComesFromCatalog(t *testing.T) {
	f := &finding.Flow{DataType: "loyalty_card", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Confidence: 0.9}
	got, _ := Evaluator{Config: config.Default(), Catalog: fakeCatalog{"loyalty_card": true}}.Apply([]*finding.Flow{f}, nil)
	if got[0].Severity != High {
		t.Errorf("sensitive custom type should be high, got %s", got[0].Severity)
	}
}
