// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
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
	return detect.DataType{ID: id, Class: "pii", Sensitive: f[id]}
}

func (fakeCatalog) Class(id string) detect.Class { return detect.Class{ID: id} }

// classCatalog puts every data type in the class named by its prefix
// ("credential.password" is a credential).
type classCatalog struct{}

func (classCatalog) Lookup(id string) detect.DataType {
	class, _, _ := strings.Cut(id, ".")
	return detect.DataType{ID: id, Class: class}
}

func (classCatalog) Class(id string) detect.Class {
	if id == "credential" {
		return detect.Class{ID: id, Severity: High}
	}
	return detect.Class{ID: id}
}

func TestClassPolicies(t *testing.T) {
	c := config.Default()
	c.Policy.IgnoreClasses = []string{"internal"}
	c.Policy.Classes["pii"] = config.ClassPolicy{FailOn: []string{"third_party"}}
	mk := func(dt, kind string, xf ...string) *finding.Flow {
		return &finding.Flow{DataType: dt, SinkRule: "r", Dest: finding.Destination{Kind: kind}, Confidence: 0.9, Transforms: xf}
	}
	flows := []*finding.Flow{
		mk("credential.password", "log", "sha256"), // hashing a credential is safe
		mk("pii.phone", "network", "sha256"),       // not a pii fail_on kind
		mk("pii.phone", "third_party", "sha256"),   // hashing pii is not safe
		mk("credential.token", "log"),              // credential class is high
		mk("internal.id", "third_party"),           // ignored class
	}
	lits := []*finding.Literal{{DataType: "credential.key"}, {DataType: "internal.id"}, {DataType: "pii.email"}}
	got, gotL := Evaluator{Config: c, Catalog: classCatalog{}}.Apply(flows, lits)
	if len(got) != 4 || len(gotL) != 2 {
		t.Fatalf("ignore_classes: %d flows, %d literals", len(got), len(gotL))
	}
	want := []struct {
		violation bool
		sev       string
		allowed   string
	}{{false, High, "transform: sha256"}, {false, Medium, ""}, {true, High, ""}, {true, High, ""}}
	for i, w := range want {
		f := got[i]
		if f.Violation != w.violation || f.Severity != w.sev || f.Allowed != w.allowed || f.Class != strings.SplitN(f.DataType, ".", 2)[0] {
			t.Errorf("flow %d (%s): violation=%v sev=%s allowed=%q class=%s", i, f.DataType, f.Violation, f.Severity, f.Allowed, f.Class)
		}
	}
	if gotL[0].Class != "credential" || gotL[0].Severity != High || gotL[1].Severity != Medium {
		t.Errorf("literals: %+v %+v", gotL[0], gotL[1])
	}
}

// consent_guarded accepts flows to those destinations that run only
// after a consent check; a class can opt out.
func TestConsentGuardedFlows(t *testing.T) {
	c := config.Default()
	c.Policy.ConsentGuarded = []string{"third_party"}
	c.Policy.Classes["phi"] = config.ClassPolicy{ConsentGuarded: []string{}}
	mk := func(dt, kind string, guards ...string) *finding.Flow {
		return &finding.Flow{DataType: dt, SinkRule: "r", Dest: finding.Destination{Kind: kind}, Confidence: 0.9, Guards: guards}
	}
	got, _ := Evaluator{Config: c, Catalog: classCatalog{}}.Apply([]*finding.Flow{
		mk("pii.email", "third_party", "consent check hasConsent() at a.kt:3"),
		mk("pii.email", "third_party"),
		mk("pii.email", "log", "consent check hasConsent() at a.kt:3"),
		mk("phi.diagnosis", "third_party", "consent check hasConsent() at a.kt:3"),
	}, nil)
	want := []string{"consent: consent check hasConsent() at a.kt:3", "", "", ""}
	for i, f := range got {
		if f.Allowed != want[i] || f.Violation != (want[i] == "") {
			t.Errorf("flow %d (%s to %s): allowed %q violation %v", i, f.DataType, f.Dest.Kind, f.Allowed, f.Violation)
		}
	}
}

func TestSeverityComesFromCatalog(t *testing.T) {
	f := &finding.Flow{DataType: "loyalty_card", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Confidence: 0.9}
	got, _ := Evaluator{Config: config.Default(), Catalog: fakeCatalog{"loyalty_card": true}}.Apply([]*finding.Flow{f}, nil)
	if got[0].Severity != High {
		t.Errorf("sensitive custom type should be high, got %s", got[0].Severity)
	}
}

// Decide says why the policy treats a flow as it does and what would
// change it, and agrees with Apply on every flow.
func TestDecide(t *testing.T) {
	c := config.Default()
	c.Policy.Allow = []config.Allow{{Sink: "log.partner", Reason: "DPA"}}
	c.Policy.IgnoreDataTypes = []string{"pii.gender"}
	c.FirstPartyDomains = []string{"api.example.com"}
	flow := func(dt, rule, kind, host string, conf float64) *finding.Flow {
		return &finding.Flow{DataType: dt, SinkRule: rule, Dest: finding.Destination{Kind: kind, Host: host}, Confidence: conf}
	}
	own := flow("pii.email", "net.http", "network", "api.example.com", 0.9)
	own.Dest.FirstParty = true
	hashed := flow("credential.password", "log.x", "log", "", 0.9)
	hashed.Transforms = []string{"sha256"}
	for _, tc := range []struct {
		f       *finding.Flow
		status  string
		reason  string
		changes []string
	}{
		{flow("pii.email", "net.http", "network", "tracker.example", 0.9), StatusViolation, "network is in policy.fail_on",
			[]string{"`first_party_domains: [tracker.example]`", "removing network from `policy.fail_on`"}},
		{flow("pii.email", "log.x", "log", "", 0.6), StatusViolation, "confidence 0.60 is at least", []string{"`policy.min_confidence` above 0.60"}},
		{flow("pii.email", "log.x", "log", "", 0.5), StatusInfo, "below policy.min_confidence 0.55", []string{"`policy.min_confidence: 0.50` or lower"}},
		{flow("pii.email", "x.ipc", "first_party", "", 0.9), StatusInfo, "first_party is not in policy.fail_on", []string{"adding first_party to `policy.fail_on`"}},
		{own, StatusInfo, "api.example.com is a first-party host", []string{"removing api.example.com from `first_party_domains`"}},
		{flow("pii.email", "log.partner", "log", "", 0.9), StatusAllowed, "a `policy.allow` entry matches it: {sink: log.partner, reason: \"DPA\"}", []string{"removing that `policy.allow` entry"}},
		{hashed, StatusAllowed, "transformed (sha256)", []string{"removing sha256 from `policy.classes.credential.safe_transforms`"}},
		{flow("pii.gender", "log.x", "log", "", 0.9), StatusDropped, "policy.ignore_data_types lists pii.gender", nil},
		{flow("pii.email", "log.x", "log", "", 0.1), StatusDropped, "below min_confidence", nil},
	} {
		e := Evaluator{Config: c, Catalog: classCatalog{}}
		d := e.Decide(tc.f)
		if d.Status != tc.status || !strings.Contains(d.Reason, tc.reason) {
			t.Errorf("%s → %s: got %s %q, want %s containing %q", tc.f.DataType, tc.f.SinkRule, d.Status, d.Reason, tc.status, tc.reason)
		}
		for _, want := range tc.changes {
			if !slices.ContainsFunc(d.Changes, func(c string) bool { return strings.Contains(c, want) }) {
				t.Errorf("%s → %s: changes %q lack %q", tc.f.DataType, tc.f.SinkRule, d.Changes, want)
			}
		}
		kept, _ := e.Apply([]*finding.Flow{tc.f}, nil)
		switch {
		case d.Status == StatusDropped && len(kept) != 0, d.Status != StatusDropped && len(kept) != 1:
			t.Errorf("%s: Apply kept %d flows, Decide says %s", tc.f.DataType, len(kept), d.Status)
		case len(kept) == 1 && (kept[0].Violation != (d.Status == StatusViolation) || kept[0].Allowed != d.Allowed):
			t.Errorf("%s: Apply says violation=%v allowed=%q, Decide says %s %q", tc.f.DataType, kept[0].Violation, kept[0].Allowed, d.Status, d.Allowed)
		}
	}
}
