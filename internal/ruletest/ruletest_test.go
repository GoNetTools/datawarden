// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ruletest

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

const example = `package demo

// ruleid: log.go.stdlib
log.Printf("%s", email)
# ruleid: log.go.stdlib, log.go.fmt_print
both(email)
/* ok: log.go.stdlib */
log.Printf("%d", id)
// todoruleid: log.go.slog
// todook: log.go.stdlib
slog.Info("x", masked)
// ok: this is a sentence, not an annotation
x := 1
`

func TestParseFile(t *testing.T) {
	anns, err := ParseFile("a.go", []byte(example))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range anns {
		got = append(got, a.String())
	}
	want := []string{
		"a.go:4: ruleid: log.go.stdlib",
		"a.go:6: ruleid: log.go.stdlib",
		"a.go:6: ruleid: log.go.fmt_print",
		"a.go:8: ok: log.go.stdlib",
		"a.go:11: todoruleid: log.go.slog",
		"a.go:11: todook: log.go.stdlib",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("annotations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := ParseFile("b.go", []byte("x()\n// ruleid: log.go.stdlib\n")); err == nil {
		t.Error("annotation at the end of the file accepted")
	}
	anns, err = Parse(fstest.MapFS{"ex/go/a.go": {Data: []byte(example)}, "ex/go/go.mod": {Data: []byte("module x\n")}}, "ex/go")
	if err != nil || len(anns) != 6 || anns[0].File != "a.go" {
		t.Errorf("Parse: %v %+v", err, anns)
	}
}

func flow(rule, dt string, line int, violation bool, xf ...string) *finding.Flow {
	return &finding.Flow{SinkRule: rule, DataType: dt, Violation: violation, Transforms: xf, Function: "demo.f",
		Source: ir.Pos{File: "a.go", Line: 1}, Sink: ir.Pos{File: "a.go", Line: line},
		Path: []ir.Pos{{File: "a.go", Line: 1}, {File: "a.go", Line: 2}, {File: "a.go", Line: line}}}
}

func TestCheck(t *testing.T) {
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	ann := func(m Mark, id string, line int) Annotation {
		return Annotation{Mark: m, RuleID: id, File: "a.go", Line: line}
	}

	good := []Annotation{
		ann(RuleID, "log.go.stdlib", 4),
		ann(OK, "log.go.stdlib", 8),         // only a non-violation there
		ann(TodoRuleID, "log.go.slog", 9),   // still missed
		ann(TodoOK, "log.go.fmt_print", 10), // still reported
		ann(RuleID, "xform.go.sha256", 2),   // the flow through line 2 is hashed
	}
	flows := []*finding.Flow{
		flow("log.go.stdlib", "email", 4, true, "sha256"),
		flow("log.go.stdlib", "email", 8, false, "masked"),
		flow("log.go.fmt_print", "phone", 10, true),
	}
	res := Check(rs, good, flows)
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %q", res.Failures)
	}
	if len(res.Known) != 2 || !res.Covered["log.go.stdlib"] || !res.Covered["log.go.slog"] || res.Covered["log.go.fmt_print"] {
		t.Errorf("known=%q covered=%v", res.Known, res.Covered)
	}

	bad := []Annotation{
		ann(RuleID, "log.go.slog", 4),              // nothing reported for slog
		ann(OK, "log.go.stdlib", 4),                // but there is a violation
		ann(TodoRuleID, "log.go.stdlib", 4),        // it is reported now
		ann(TodoOK, "log.go.stdlib", 8),            // no longer a violation
		ann(RuleID, "src.android.phone_number", 5), // no phone flow starts on line 5
		ann(RuleID, "log.go.nope", 3),              // typo
	}
	res = Check(rs, bad, append(flows, flow("log.go.zap", "email", 12, true)))
	for _, want := range []string{
		"a.go:4: ruleid: log.go.slog: no finding",
		"a.go:4: ok: log.go.stdlib: unexpected violation",
		"a.go:4: todoruleid: log.go.stdlib: now reported",
		"a.go:8: todook: log.go.stdlib: no longer reported",
		"a.go:5: ruleid: src.android.phone_number: no finding (expected a phone flow starting here)",
		"a.go:3: ruleid: log.go.nope: unknown rule id",
		"a.go:10: unannotated violation phone → log.go.fmt_print",
		"a.go:12: unannotated violation email → log.go.zap",
	} {
		found := false
		for _, f := range res.Failures {
			found = found || strings.HasPrefix(f, want)
		}
		if !found {
			t.Errorf("missing failure %q in:\n%s", want, strings.Join(res.Failures, "\n"))
		}
	}
	if len(res.Failures) != 8 {
		t.Errorf("%d failures, want 8:\n%s", len(res.Failures), strings.Join(res.Failures, "\n"))
	}
}

func TestMissing(t *testing.T) {
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, r := range rs.Rules {
		covered[r.ID] = r.ID != "log.go.zap" && r.ID != "log.android.timber"
	}
	if got := Missing(rs, covered, map[string]bool{"go": true}); !reflect.DeepEqual(got, []string{"log.go.zap"}) {
		t.Errorf("go only: %v", got)
	}
	if got := Missing(rs, covered, map[string]bool{"go": true, "java": true}); !reflect.DeepEqual(got, []string{"log.android.timber", "log.go.zap"}) {
		t.Errorf("go and java: %v", got)
	}
}
