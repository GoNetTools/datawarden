// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/ir"
)

func TestBuiltinRulesLoad(t *testing.T) {
	s, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) < 50 {
		t.Fatalf("only %d rules", len(s.Rules))
	}
	r := s.ByID("sdk.sentry.set_user")
	if r == nil || r.Dest.Host != "sentry.io" || !r.Arg.Selects(0) || r.Arg.Selects(1) {
		t.Fatalf("sentry rule: %+v", r)
	}
}

// TestBuiltinRuleConventions keeps the built-in rule set consistent as it
// grows. Ids are part of baseline fingerprints and name the sink category
// in reports, so they follow one scheme.
func TestBuiltinRuleConventions(t *testing.T) {
	raw, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	idRe := regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	prefixes := map[string]map[string]bool{ // kind -> allowed first segment
		KindSink:      {"log": true, "sdk": true, "net": true, "storage": true, "ipc": true},
		KindSource:    {"src": true},
		KindTransform: {"xform": true},
	}
	destFor := map[string]map[string]bool{ // sink category -> allowed dest.kind
		"log": {DestLog: true}, "sdk": {DestThirdParty: true}, "net": {DestNetwork: true},
		"storage": {DestStorage: true, DestFirstParty: true}, "ipc": {DestIPC: true},
	}
	taxonomy := map[string]bool{}
	for _, dt := range detect.DefaultTaxonomy() {
		taxonomy[dt.ID] = true
	}
	seen := map[string]string{}
	for _, r := range raw {
		if other, ok := seen[r.ID]; ok {
			t.Errorf("%s: id %s is already defined in %s; a duplicate id silently replaces the earlier rule", r.Origin, r.ID, other)
		}
		seen[r.ID] = r.Origin
		kind := r.Kind
		if kind == "" {
			kind = KindSink
		}
		first, _, _ := strings.Cut(r.ID, ".")
		switch {
		case !idRe.MatchString(r.ID):
			t.Errorf("%s: id %q must be lower-case dotted segments", r.Origin, r.ID)
		case !prefixes[kind][first]:
			t.Errorf("%s: %s rule %s must start with one of %v", r.Origin, kind, r.ID, keys(prefixes[kind]))
		case kind == KindSink && !destFor[first][r.Dest.Kind]:
			t.Errorf("%s: %s sends to dest.kind %q, which does not fit its %q category", r.Origin, r.ID, r.Dest.Kind, first)
		case kind == KindSource && !taxonomy[r.DataType]:
			t.Errorf("%s: source %s produces data_type %q, which is not in the taxonomy (internal/detect/taxonomy.go)", r.Origin, r.ID, r.DataType)
		}
		if kind == KindSink && r.Category == "" {
			t.Errorf("%s: sink %s needs a category (logging, crash_reporting, analytics, ...)", r.Origin, r.ID)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRuleFilesAreStrict(t *testing.T) {
	for name, body := range map[string]string{
		"misspelt key":        "- id: sdk.x.y\n  lang: go\n  call: a.b\n  recevier: x\n  dest: {kind: log}\n",
		"misspelt dest key":   "- id: sdk.x.y\n  lang: go\n  call: a.b\n  dest: {kind: log, hots: x}\n",
		"wrapped misspelt":    "rules:\n  - id: sdk.x.y\n    lang: go\n    call: a.b\n    dest: {kind: log}\n    data-type: email\n",
		"unknown language":    "- id: sdk.x.y\n  lang: kotln\n  call: a.b\n  dest: {kind: log}\n",
		"negative arg":        "- id: sdk.x.y\n  lang: go\n  call: a.b\n  arg: -2\n  dest: {kind: log}\n",
		"negative host_arg":   "- id: sdk.x.y\n  lang: go\n  call: a.b\n  host_arg: -1\n  dest: {kind: log}\n",
		"duplicate in file":   "- id: sdk.x.y\n  lang: go\n  call: a.b\n  dest: {kind: log}\n- id: sdk.x.y\n  lang: go\n  call: a.c\n  dest: {kind: log}\n",
		"source without type": "- id: src.x\n  kind: source\n  lang: go\n  call: a.b\n",
	} {
		repo := fstest.MapFS{"rules.yaml": {Data: []byte(body)}}
		if _, err := Load(repo, "rules.yaml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, body := range map[string]string{
		"empty file":    "",
		"comments only": "# nothing yet\n",
		"wrapped":       "rules:\n  - id: sdk.x.y\n    lang: [golang, kt]\n    call: a.b\n    dest: {kind: log}\n",
		"custom type":   "- id: src.acme.loyalty\n  kind: source\n  lang: java\n  call: com.acme.Loyalty.card\n  data_type: loyalty_card\n",
		"disable by id": "- id: log.go.fmt_print\n  disabled: true\n",
	} {
		repo := fstest.MapFS{"rules.yaml": {Data: []byte(body)}}
		if _, err := Load(repo, "rules.yaml"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOverrides(t *testing.T) {
	repo := fstest.MapFS{".datawarden/rules/repo.yaml": {Data: []byte(`
- id: log.go.fmt_print
  disabled: true
- id: sdk.acme.telemetry
  lang: kotlin
  call: com.acme.Telemetry.send
  arg: 0
  dest: { host: telemetry.acme.vn, kind: third_party }
`)}}
	s, err := Load(repo, ".datawarden/rules", "missing/dir")
	if err != nil {
		t.Fatal(err)
	}
	if s.ByID("log.go.fmt_print") != nil {
		t.Error("rule not disabled")
	}
	if s.ByID("sdk.acme.telemetry") == nil {
		t.Error("repo rule missing")
	}
	base, _ := Load(nil)
	if s.Hash() == base.Hash() {
		t.Error("hash should change with overrides")
	}
	repo[".datawarden/rules/bad.yaml"] = &fstest.MapFile{Data: []byte("- id: x\n  lang: go\n  call: a.b\n  dest: {kind: nowhere}\n")}
	if _, err := Load(repo, ".datawarden/rules"); err == nil {
		t.Error("invalid dest kind accepted")
	}
}

func TestMatch(t *testing.T) {
	s, _ := Load(nil)
	hit := func(lang string, c *ir.Call) (string, float64) {
		hs := s.Match(lang, KindSink, c)
		if len(hs) == 0 {
			return "", 0
		}
		return hs[0].Rule.ID, hs[0].Conf
	}
	if id, conf := hit("kotlin", &ir.Call{Callee: "io.sentry.Sentry.setUser", Name: "setUser"}); id != "sdk.sentry.set_user" || conf != 1 {
		t.Errorf("resolved: %s %v", id, conf)
	}
	if id, conf := hit("kotlin", &ir.Call{Name: "setUser", RecvType: "Sentry"}); id != "sdk.sentry.set_user" || conf != 0.8 {
		t.Errorf("unqualified receiver type: %s %v", id, conf)
	}
	if id, _ := hit("kotlin", &ir.Call{Name: "info", HasRecv: true, RecvText: "logger"}); id != "log.jvm.logger" {
		t.Errorf("receiver regex: %s", id)
	}
	if id, _ := hit("kotlin", &ir.Call{Name: "putString", HasRecv: true, RecvText: "this"}); id != "storage.android.shared_prefs" {
		t.Errorf("bare call: %s", id)
	}
	if id, _ := hit("kotlin", &ir.Call{Callee: "com.acme.Sentry.setUser", Name: "setUser"}); id != "" {
		t.Errorf("resolved to another class must not match: %s", id)
	}
	if id, _ := hit("go", &ir.Call{Callee: "log/slog.Logger.Info", Name: "Info"}); id != "log.go.slog" {
		t.Errorf("go slog: %s", id)
	}
	if id, _ := hit("typescript", &ir.Call{Callee: "@react-native-firebase/analytics().logEvent", Name: "logEvent"}); id != "sdk.ts.firebase.analytics" {
		t.Errorf("rn firebase: %s", id)
	}
	if got := splitCallee("github.com/getsentry/sentry-go.Scope.SetUser"); len(got) != 3 || got[0] != "github.com/getsentry/sentry-go" {
		t.Errorf("splitCallee: %v", got)
	}
}
