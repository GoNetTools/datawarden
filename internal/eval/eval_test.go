// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

const manifest = `
thresholds: [0.5, 0.8]
cases:
  - name: app
    dir: app
    min_precision: 0.9
    min_recall: 0.5
    flows:
      - {data_type: phone, sink_rule: log.go.stdlib, function: svc.Register}
      - {data_type: email, sink_rule: sdk.sentry.set_user, function: svc.Register}
      - {data_type: dob, sink_rule: log.go.stdlib, function: svc.Track, note: "via helper"}
    literals:
      - {data_type: phone, file: fixtures/a.json, line: 2}
    ambiguous:
      - {data_type: email, sink_rule: net.go.http_body, function: svc.Sync}
  - name: kotlin
    dir: /abs/kotlin
    langs: [kotlin]
`

func flow(dt, rule, fn string, conf float64, violation bool) *finding.Flow {
	return &finding.Flow{DataType: dt, SinkRule: rule, Function: fn, Confidence: conf, Violation: violation,
		Sink: ir.Pos{File: "svc/a.go", Line: 7}}
}

func appFindings() ([]*finding.Flow, []*finding.Literal) {
	flows := []*finding.Flow{
		flow("phone", "log.go.stdlib", "example.com/app/svc.Register", 0.9, true),
		flow("phone", "log.go.stdlib", "example.com/app/svc.Register", 0.7, true), // second path: still one TP
		flow("email", "sdk.sentry.set_user", "example.com/app/svc.Register", 0.6, true),
		flow("email", "net.go.http_body", "example.com/app/svc.Sync", 0.9, true),     // ambiguous
		flow("phone", "log.go.stdlib", "example.com/app/svc.PreRegister", 0.9, true), // not svc.Register: FP
		flow("phone", "log.go.stdlib", "example.com/app/svc.Safe", 0.9, false),       // not a violation
	}
	lits := []*finding.Literal{
		{DataType: "phone", Pos: ir.Pos{File: "fixtures/a.json", Line: 2}, Confidence: 0.9, Violation: true},
		{DataType: "email", Pos: ir.Pos{File: "fixtures/a.json", Line: 3}, Confidence: 0.9, Violation: true, Detector: "email-format"},
	}
	return flows, lits
}

func TestParseValidates(t *testing.T) {
	m, err := Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != 2 || m.Cases[0].Flows[2].Note != "via helper" {
		t.Errorf("parsed: %+v", m)
	}
	m, err = Parse([]byte("cases: [{name: a, dir: a}]"))
	if err != nil || len(m.Thresholds) != len(DefaultThresholds) {
		t.Errorf("default thresholds: %v %v", m, err)
	}
	for name, bad := range map[string]string{
		"unknown key":      "cases: [{name: a, dir: a, flow: []}]",
		"no cases":         "thresholds: [0.5]",
		"missing dir":      "cases: [{name: a}]",
		"duplicate":        "cases: [{name: a, dir: a}, {name: a, dir: b}]",
		"threshold order":  "thresholds: [0.8, 0.5]\ncases: [{name: a, dir: a}]",
		"threshold range":  "thresholds: [0, 0.5]\ncases: [{name: a, dir: a}]",
		"incomplete flow":  "cases: [{name: a, dir: a, flows: [{data_type: phone, sink_rule: x}]}]",
		"literal no line":  "cases: [{name: a, dir: a, literals: [{data_type: phone, file: x}]}]",
		"literal win path": `cases: [{name: a, dir: a, literals: [{data_type: phone, file: 'a\b', line: 1}]}]`,
		"min out of range": "cases: [{name: a, dir: a, min_recall: 2}]",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScore(t *testing.T) {
	m, _ := Parse([]byte(manifest))
	flows, lits := appFindings()
	o := Score(&m.Cases[0], flows, lits, 0)
	if o.Counts != (Counts{TP: 3, FP: 2, FN: 1}) || o.Ambiguous != 1 {
		t.Fatalf("counts = %+v ambiguous=%d", o.Counts, o.Ambiguous)
	}
	if len(o.Missed) != 1 || !strings.Contains(o.Missed[0], "dob → log.go.stdlib in svc.Track — via helper") {
		t.Errorf("missed: %q", o.Missed)
	}
	if len(o.FalsePositives) != 2 || !strings.Contains(strings.Join(o.FalsePositives, "\n"), "svc.PreRegister") {
		t.Errorf("false positives: %q", o.FalsePositives)
	}
	if o.ByDataType["phone"] != (Counts{TP: 2, FP: 1}) || o.BySink["literal"] != (Counts{TP: 1, FP: 1}) || o.BySink["log"] != (Counts{TP: 1, FP: 1, FN: 1}) {
		t.Errorf("breakdown: %+v %+v", o.ByDataType, o.BySink)
	}

	// At 0.8 the email flow (0.6) is no longer reported.
	o = Score(&m.Cases[0], flows, lits, 0.8)
	if o.Counts != (Counts{TP: 2, FP: 2, FN: 2}) {
		t.Errorf("at 0.8: %+v", o.Counts)
	}
}

func TestMetrics(t *testing.T) {
	c := Counts{TP: 3, FP: 1, FN: 3}
	if c.Precision() != 0.75 || c.Recall() != 0.5 || math.Abs(c.F1()-0.6) > 1e-9 {
		t.Errorf("p=%v r=%v f1=%v", c.Precision(), c.Recall(), c.F1())
	}
	if (Counts{}).Precision() != 1 || (Counts{}).Recall() != 1 || (Counts{FP: 1, FN: 1}).F1() != 0 {
		t.Error("empty counts")
	}
	b, _ := json.Marshal(Counts{TP: 2, FP: 1})
	if string(b) != `{"tp":2,"fp":1,"fn":0,"precision":0.667,"recall":1,"f1":0.8}` {
		t.Errorf("json: %s", b)
	}
}

func TestNameSuffix(t *testing.T) {
	for _, c := range []struct {
		name, suffix string
		want         bool
	}{
		{"example.com/app/svc.Register", "svc.Register", true},
		{"svc.Register", "svc.Register", true},
		{"src/api/user:UserService.register", "UserService.register", true},
		{"com.example.CustomerRepo.save", "CustomerRepo.save", true},
		{"example.com/app/svc.PreRegister", "Register", false},
		{"example.com/app/svc.Register$1", "svc.Register", false},
	} {
		if got := nameSuffix(c.name, c.suffix); got != c.want {
			t.Errorf("nameSuffix(%q, %q) = %v", c.name, c.suffix, got)
		}
	}
}

func TestRun(t *testing.T) {
	m, _ := Parse([]byte(manifest))
	var calls []string
	scan := func(_ context.Context, dir string, minConf float64) (*Scan, error) {
		calls = append(calls, filepath.ToSlash(dir))
		flows, lits := appFindings()
		ms := time.Duration(len(calls)) * 10 * time.Millisecond
		return &Scan{Flows: flows, Literals: lits, Wall: ms, AllocBytes: 2 << 20, Files: 4, Functions: 9}, nil
	}
	base := filepath.Join(string(filepath.Separator), "corpus")
	r, err := Run(context.Background(), Options{Manifest: m, BaseDir: base, Scan: scan, Runs: 3,
		Available: func(l string) bool { return l != "kotlin" }})
	if err != nil {
		t.Fatal(err)
	}
	// Three timing runs plus one sweep scan; the kotlin case is skipped.
	if len(calls) != 4 || calls[0] != filepath.ToSlash(filepath.Join(base, "app")) {
		t.Errorf("calls: %v", calls)
	}
	app, kt := r.Cases[0], r.Cases[1]
	if kt.Skipped != "no frontend for kotlin in this build" {
		t.Errorf("skipped: %q", kt.Skipped)
	}
	if app.Timing != (Timing{Runs: 3, MedianMS: 20, MinMS: 10, MaxMS: 30, AllocMB: 2, Files: 4, Functions: 9}) {
		t.Errorf("timing: %+v", app.Timing)
	}
	if r.Total.Counts != (Counts{TP: 3, FP: 2, FN: 1}) || len(r.Total.Missed) != 1 || !strings.HasPrefix(r.Total.Missed[0], "app: ") {
		t.Errorf("total: %+v", r.Total)
	}
	if len(r.Sweep) != 2 || r.Sweep[1].Counts != (Counts{TP: 2, FP: 2, FN: 2}) {
		t.Errorf("sweep: %+v", r.Sweep)
	}
	// precision 3/5 < 0.9; recall 3/4 >= 0.5.
	if fails := r.Check(m); len(fails) != 1 || !strings.Contains(fails[0], "app: precision 0.600 < min_precision 0.900") {
		t.Errorf("check: %q", fails)
	}

	for name, w := range map[string]func(*bytes.Buffer, *Result) error{
		"text":     func(b *bytes.Buffer, r *Result) error { return WriteText(b, r) },
		"markdown": func(b *bytes.Buffer, r *Result) error { return WriteMarkdown(b, r) },
		"json":     func(b *bytes.Buffer, r *Result) error { return WriteJSON(b, r) },
	} {
		var b bytes.Buffer
		if err := w(&b, r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, s := range []string{"0.6", "svc.PreRegister", "svc.Track", "kotlin"} {
			if !strings.Contains(b.String(), s) {
				t.Errorf("%s output lacks %q:\n%s", name, s, b.String())
			}
		}
	}

	boom := errors.New("go list failed")
	if _, err := Run(context.Background(), Options{Manifest: m, Scan: func(context.Context, string, float64) (*Scan, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Errorf("scan error: %v", err)
	}
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Error("missing options accepted")
	}
}

func TestCheckTolerance(t *testing.T) {
	m, _ := Parse([]byte("cases: [{name: a, dir: a, min_recall: 0.9}]"))
	r := &Result{Cases: []CaseResult{{Name: "a", Outcome: Outcome{Counts: Counts{TP: 9, FN: 1}}}}}
	if fails := r.Check(m); len(fails) != 0 {
		t.Errorf("9/10 against 0.9: %q", fails)
	}
}
