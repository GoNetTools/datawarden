// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/policy"
	"github.com/GoNetTools/datawarden/internal/rules"
)

func at(line, col int) ir.Pos { return ir.Pos{File: "app/Signup.kt", Line: line, Col: col} }

//	fun signup(tm: TelephonyManager) {
//	  val line = tm.getLine1Number()      // 2: source rule
//	  val msg = "otp to " + line          // 3: compute
//	  audit(msg)                          // 4: analysed helper
//	  Log.d(TAG, mask(msg))               // 5: transform, then the sink
//	}
func signup() (*ir.Func, *finding.Flow) {
	f := &ir.Func{ID: "app.Signup.signup", Lang: "kotlin", File: "app/Signup.kt"}
	f.NewBlock()
	tm := f.AddParam("tm", "android.telephony.TelephonyManager", at(1, 12))
	line := f.Named("line", "", at(2, 9))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: line, Args: []ir.VarID{tm}, Pos: at(2, 16),
		Call: &ir.Call{Callee: "android.telephony.TelephonyManager.getLine1Number", Name: "getLine1Number", HasRecv: true}})
	msg := f.Named("msg", "", at(3, 9))
	f.Emit(ir.Instr{Op: ir.OpCompute, Operator: "+", Dst: msg, Args: []ir.VarID{f.ConstVar("otp to ", at(3, 15)), line}, Pos: at(3, 15)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(at(4, 5)), Args: []ir.VarID{msg}, Pos: at(4, 5), Call: &ir.Call{Name: "audit", Target: "app.Signup.audit"}})
	masked := f.Temp(at(5, 16))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: masked, Args: []ir.VarID{msg}, Pos: at(5, 16), Call: &ir.Call{Name: "mask"}})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(at(5, 5)), Args: []ir.VarID{f.ConstVar("TAG", at(5, 11)), masked}, Pos: at(5, 5),
		Call: &ir.Call{Callee: "android.util.Log.d", Name: "d"}})
	fl := &finding.Flow{
		DataType: "phone", Class: "pii", Severity: "medium", SinkRule: "log.android.logcat", Dest: finding.Destination{Kind: "log", Host: "logcat"},
		Source: at(2, 16), Sink: at(5, 5), Path: []ir.Pos{at(2, 16), at(3, 15), at(4, 5), at(5, 16), at(5, 5)},
		Function: f.ID, Lang: "kotlin", SourceDesc: "call android.telephony.TelephonyManager.getLine1Number", SinkCall: "android.util.Log.d",
		Confidence: 0.81, Fingerprint: "0123456789abcdef01234567",
	}
	return f, fl
}

func TestExplainFlow(t *testing.T) {
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	fn, fl := signup()
	src := []string{"fun signup(tm: TelephonyManager) {", "    val line = tm.getLine1Number()", `    val msg = "otp to " + line`, "    audit(msg)", "    Log.d(TAG, mask(msg))", "}"}
	x := Explainer{Names: detect.NewClassifier(detect.DefaultTaxonomy())}
	e := x.Explain(Input{Flow: fl, Decision: policy.Decision{Status: policy.StatusViolation, Reason: "log is in policy.fail_on"},
		Funcs: []*ir.Func{fn}, Rules: rs, Lines: func(string) []string { return src }})

	if e.Status != StatusNew || e.Source.Code != "val line = tm.getLine1Number()" {
		t.Errorf("status %s, source code %q", e.Status, e.Source.Code)
	}
	if len(e.Source.Why) == 0 || !strings.Contains(e.Source.Why[0], "source rule `src.android.phone_number` (resolved callee)") {
		t.Errorf("source why: %q", e.Source.Why)
	}
	wantSteps := []string{
		"source: call android.telephony.TelephonyManager.getLine1Number",
		"part of a value computed with `+`",
		"passed to `app.Signup.audit`, which is analysed",
		"transformed by `mask` (masked: its name says so)",
		"sink: sent by `android.util.Log.d`",
	}
	if len(e.Steps) != len(wantSteps) {
		t.Fatalf("steps:\n%+v", e.Steps)
	}
	for i, w := range wantSteps {
		if !strings.Contains(e.Steps[i].What, w) || e.Steps[i].Func != fn.ID || e.Steps[i].IR == "" {
			t.Errorf("step %d = %+v, want %q", i+1, e.Steps[i], w)
		}
	}
	if !strings.Contains(e.Sink.Why, "the callee `android.util.Log.d` matches the rule's call patterns") {
		t.Errorf("sink why: %q", e.Sink.Why)
	}
	if len(e.Silence) == 0 || !strings.Contains(e.Silence[0].Do, "{sink: log.android.logcat, data_types: [phone], path: \"app/Signup.kt\"") ||
		e.Silence[len(e.Silence)-1].Do != "datawarden baseline" {
		t.Errorf("silence: %+v", e.Silence)
	}

	var text, js bytes.Buffer
	if err := x.Write(&text, "text", []*Explanation{e, e}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NEW  phone → log, host logcat  [log.android.logcat]", "fingerprint 0123456789abcdef01234567",
		"in app.Signup.signup", "2 │ val line = tm.getLine1Number()", "Policy: NEW", "To silence it", strings.Repeat("─", 72)} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
	if err := x.Write(&js, "json", []*Explanation{e}); err != nil {
		t.Fatal(err)
	}
	var back []Explanation
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back) != 1 || len(back[0].Steps) != 5 {
		t.Errorf("json: %v\n%s", err, js.String())
	}
	if err := x.Write(&js, "xml", nil); err == nil {
		t.Error("unknown format accepted")
	}
}

// Without the IR (a file changed since the scan) the explanation still
// says what the report knows, and a flow that is not a new violation has
// nothing to silence.
func TestExplainWithoutIR(t *testing.T) {
	_, fl := signup()
	fl.SourceDesc = `identifier "phoneNumber"`
	fl.Baselined = true
	e := Explainer{Names: detect.NewClassifier(detect.DefaultTaxonomy())}.Explain(Input{Flow: fl, Decision: policy.Decision{Status: policy.StatusViolation}})
	if e.Status != StatusBaseline || len(e.Silence) != 0 {
		t.Errorf("status %s, silence %v", e.Status, e.Silence)
	}
	if len(e.Source.Why) != 1 || !strings.Contains(e.Source.Why[0], "the name `phoneNumber` matches") {
		t.Errorf("source why: %q", e.Source.Why)
	}
	if len(e.Steps) != 5 || !strings.Contains(e.Steps[1].What, "no instruction here") {
		t.Errorf("steps: %+v", e.Steps)
	}
	for _, tc := range []struct {
		d    policy.Decision
		want string
	}{{policy.Decision{Status: policy.StatusAllowed}, StatusAllowed}, {policy.Decision{Status: policy.StatusInfo}, StatusInfo}, {policy.Decision{Status: policy.StatusDropped}, StatusDropped}} {
		if got := status(fl, tc.d); got != tc.want {
			t.Errorf("status(%s) = %s", tc.d.Status, got)
		}
	}
}

// Each kind of step is described, and parameter and field sources name
// the rule that matched.
func TestStepsAndSources(t *testing.T) {
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := func(line int) ir.Pos { return ir.Pos{File: "src/signup.ts", Line: line, Col: 3} }
	f := &ir.Func{ID: "src/signup:SignupController.create", Lang: "typescript", File: "src/signup.ts"}
	f.NewBlock()
	dto := f.AddParam("dto", "any", p(1))
	f.Vars[dto].Annotations = []string{"Body"}
	req := f.AddParam("req", "", p(1))
	body := f.Temp(p(2))
	f.Emit(ir.Instr{Op: ir.OpLoad, Dst: body, Args: []ir.VarID{req}, Field: "body", Pos: p(2)})
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{req, body}, Field: "saved", Pos: p(3)})
	copyV := f.Named("copy", "", p(4))
	f.Emit(ir.Instr{Op: ir.OpAssign, Dst: copyV, Args: []ir.VarID{body}, Pos: p(4)})
	obj := f.Temp(p(5))
	f.Emit(ir.Instr{Op: ir.OpNew, Dst: obj, Args: []ir.VarID{copyV}, Call: &ir.Call{Callee: "app.Event", Name: "Event"}, Pos: p(5)})
	cl := f.Temp(p(6))
	f.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Args: []ir.VarID{copyV}, Func: "src/signup:SignupController.create$1", Pos: p(6)})
	ext := f.Temp(p(7))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: ext, Args: []ir.VarID{copyV}, Call: &ir.Call{Callee: "lodash.cloneDeep", Name: "cloneDeep"}, Pos: p(7)})
	f.Emit(ir.Instr{Op: ir.OpThrow, Dst: ir.NoVar, Args: []ir.VarID{ext}, Pos: p(8)})

	x := Explainer{Names: detect.NewClassifier(detect.DefaultTaxonomy())}
	in := Input{Rules: rs, Funcs: []*ir.Func{f}, Decision: policy.Decision{Status: policy.StatusInfo}}
	in.Flow = &finding.Flow{DataType: "request_data", Source: p(1), Sink: p(9), SinkRule: "log.ts.console", SinkCall: "console.log", Lang: "typescript",
		SourceDesc: "parameter dto", Path: []ir.Pos{p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8)}}
	e := x.Explain(in)
	if len(e.Source.Why) == 0 || !strings.Contains(e.Source.Why[0], "parameter `dto` is annotated @Body: source rule `src.ts.nest_body`") {
		t.Errorf("parameter source: %q", e.Source.Why)
	}
	want := []string{"source: parameter dto", "read `body` of `req`", "stored in `saved` of `req`", "assigned to `copy`",
		"put into a new `app.Event`", "captured by the closure", "through `lodash.cloneDeep`, code datawarden does not see into", "thrown", "sink: sent by `console.log`"}
	if len(e.Steps) != len(want) {
		t.Fatalf("steps: %+v", e.Steps)
	}
	for i, w := range want {
		if !strings.Contains(e.Steps[i].What, w) {
			t.Errorf("step %d = %q, want %q", i+1, e.Steps[i].What, w)
		}
	}
	if e.Silence != nil {
		t.Errorf("an informational flow has silencing options: %+v", e.Silence)
	}

	in.Flow = &finding.Flow{DataType: "request_data", Source: p(2), Sink: p(9), SourceDesc: "field body (field of req)", Lang: "typescript"}
	if why := x.Explain(in).Source.Why; len(why) == 0 || !strings.Contains(why[0], "reading `body` (field of req) matches source rule `src.ts.express_request`") {
		t.Errorf("field source: %q", why)
	}
	in.Flow = &finding.Flow{DataType: "email", Source: p(20), Sink: p(21), SourceDesc: `key "email"`, Lang: "go", Dest: finding.Destination{Kind: "network", Host: "api.partner.example"}}
	e = x.Explain(Input{Flow: in.Flow, Decision: policy.Decision{Status: policy.StatusViolation}})
	if len(e.Source.Why) == 0 || !strings.Contains(e.Source.Why[0], `the key "email" next to the value matches`) {
		t.Errorf("key source: %q", e.Source.Why)
	}
	if !slices.ContainsFunc(e.Silence, func(o Option) bool { return o.Do == "first_party_domains: [api.partner.example]" }) {
		t.Errorf("no first_party_domains option: %+v", e.Silence)
	}
	in.Flow = &finding.Flow{DataType: "national_id", Source: p(20), Sink: p(21), SourceDesc: `field model.Customer.NationalID (json:"national_id")`, Lang: "kotlin"}
	e = x.Explain(Input{Flow: in.Flow, Decision: policy.Decision{Status: policy.StatusViolation}})
	if len(e.Source.Why) == 0 || e.Source.Why[0] != `the schema hint json:"national_id" says it is national_id` || !strings.Contains(e.Silence[0].Do, `@PII("-") on model.Customer.NationalID`) {
		t.Errorf("schema hint: %q %+v", e.Source.Why, e.Silence)
	}
}

// A value that comes out of a function the call does not name is said to
// come from a function the call runs (#32): a closure the call is assumed
// to run, or an implementation of the interface method it calls.
func TestStepFromAFunctionTheCallRuns(t *testing.T) {
	pos := func(line int) ir.Pos { return ir.Pos{File: "main.go", Line: line, Col: 3} }
	handler := &ir.Func{ID: "app.API.login", Lang: "go", File: "main.go"}
	handler.NewBlock()
	p := handler.Temp(pos(2))
	handler.Emit(ir.Instr{Op: ir.OpNew, Dst: p, Pos: pos(2), Call: &ir.Call{Callee: "app.profile", Name: "profile"}})
	handler.Emit(ir.Instr{Op: ir.OpReturn, Args: []ir.VarID{p}, Pos: pos(3)})

	caller := &ir.Func{ID: "app.report", Lang: "go", File: "main.go"}
	caller.NewBlock()
	db := caller.AddParam("db", "gorm.io/gorm.DB", pos(5))
	res := caller.Temp(pos(6))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: res, Args: []ir.VarID{db}, Pos: pos(6), Call: &ir.Call{Callee: "gorm.io/gorm.DB.Where", Name: "Where", HasRecv: true}})
	got := caller.Temp(pos(7))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: got, Args: []ir.VarID{db}, Pos: pos(7), Call: &ir.Call{Callee: "app.Store.login", Name: "login", HasRecv: true}})
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: caller.Temp(pos(8)), Args: []ir.VarID{res}, Pos: pos(8), Call: &ir.Call{Callee: "log.Println", Name: "Println"}})

	for _, tc := range []struct {
		at   int
		want string
	}{
		{6, "runs `app.API.login`, a function value the analysis assumes `gorm.DB.Where` may call"},
		{7, "calls `app.API.login`, which implements `app.Store.login`"},
	} {
		fl := &finding.Flow{DataType: "person_name", SinkRule: "log.go.stdlib", Source: pos(2), Sink: pos(8),
			Path: []ir.Pos{pos(2), pos(tc.at), pos(8)}, Function: caller.ID, Lang: "go", SourceDesc: "value of type app.profile", SinkCall: "log.Println"}
		e := Explainer{}.Explain(Input{Flow: fl, Funcs: []*ir.Func{handler, caller}, Lines: func(string) []string { return nil }})
		if len(e.Steps) < 2 || !strings.Contains(e.Steps[1].What, tc.want) {
			t.Errorf("line %d: steps %+v, want %q", tc.at, e.Steps, tc.want)
		}
	}

	// A function the caller calls by name before the step returned the
	// value there, even when the path goes on at another call; one it calls
	// after the step did not.
	for _, before := range []bool{true, false} {
		c2 := &ir.Func{ID: "app.report2", Lang: "go", File: "main.go"}
		c2.NewBlock()
		db := c2.AddParam("db", "gorm.io/gorm.DB", pos(5))
		login := func() {
			c2.Emit(ir.Instr{Op: ir.OpCall, Dst: c2.Temp(pos(9)), Pos: pos(9), Call: &ir.Call{Name: "login", Target: handler.ID}})
		}
		if before {
			login()
		}
		res := c2.Temp(pos(6))
		c2.Emit(ir.Instr{Op: ir.OpCall, Dst: res, Args: []ir.VarID{db}, Pos: pos(6), Call: &ir.Call{Callee: "gorm.io/gorm.DB.Where", Name: "Where", HasRecv: true}})
		if !before {
			login()
		}
		fl := &finding.Flow{DataType: "person_name", SinkRule: "log.go.stdlib", Source: pos(2), Sink: pos(6),
			Path: []ir.Pos{pos(2), pos(6)}, Function: c2.ID, Lang: "go", SourceDesc: "value of type app.profile", SinkCall: "log.Println"}
		e := Explainer{}.Explain(Input{Flow: fl, Funcs: []*ir.Func{handler, c2}, Lines: func(string) []string { return nil }})
		if len(e.Steps) < 2 || strings.Contains(e.Steps[1].What, "runs") == before {
			t.Errorf("login called by name before the step: %v; steps %+v", before, e.Steps)
		}
	}
}
