// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/pii-scanner/internal/ir"
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

func TestOverrides(t *testing.T) {
	repo := fstest.MapFS{".piiflow/rules/repo.yaml": {Data: []byte(`
- id: log.go.fmt_print
  disabled: true
- id: sdk.acme.telemetry
  lang: kotlin
  call: com.acme.Telemetry.send
  arg: 0
  dest: { host: telemetry.acme.vn, kind: third_party }
`)}}
	s, err := Load(repo, ".piiflow/rules", "missing/dir")
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
	repo[".piiflow/rules/bad.yaml"] = &fstest.MapFile{Data: []byte("- id: x\n  lang: go\n  call: a.b\n  dest: {kind: nowhere}\n")}
	if _, err := Load(repo, ".piiflow/rules"); err == nil {
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
