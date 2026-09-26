// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// logTo emits Log.d(TAG, arg).
func logTo(f *ir.Func, arg ir.VarID, line int) {
	tag := f.ConstVar("TAG", pos(line))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(line)), Args: []ir.VarID{tag, arg},
		Call: &ir.Call{Callee: "android.util.Log.d", Name: "d"}, Pos: pos(line)})
}

func newFunc(id string) *ir.Func {
	f := &ir.Func{ID: id, Name: id[strings.LastIndexByte(id, '.')+1:], Lang: "kotlin", File: "a.kt"}
	f.NewBlock()
	return f
}

func analyze(t *testing.T, classes []*ir.Class, funcs ...*ir.Func) *Result {
	return analyzeTyped(t, classes, nil, funcs...)
}

func analyzeTyped(t *testing.T, classes []*ir.Class, types []*ir.TypeDecl, funcs ...*ir.Func) *Result {
	t.Helper()
	for _, f := range funcs {
		if err := ir.Verify(f); err != nil {
			t.Fatalf("test IR does not verify: %v\n%s", err, ir.Format(f))
		}
	}
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	res, err := Engine{Names: names}.Analyze(context.Background(), funcs, Input{Rules: rs, Schema: detect.BuildSchema(names, types), Classes: classes})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func flowAt(res *Result, line int) *finding.Flow {
	for _, f := range res.Flows {
		if f.Sink.Line == line {
			return f
		}
	}
	return nil
}

// A call on an interface runs the implementations the class table lists.
func TestClassTableDispatch(t *testing.T) {
	impl := newFunc("p.Sms.deliver")
	impl.AddParam("this", "p.Sms", pos(1))
	to := impl.AddParam("to", "", pos(1))
	logTo(impl, to, 2)

	caller := newFunc("p.send")
	ch := caller.AddParam("ch", "p.Channel", pos(10))
	email := caller.AddParam("email", "String", pos(10))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: caller.Temp(pos(11)), Args: []ir.VarID{ch, email},
		Call: &ir.Call{Name: "deliver", HasRecv: true, RecvType: "p.Channel"}, Pos: pos(11)})

	classes := []*ir.Class{
		{Name: "p.Channel"},
		{Name: "p.Sms", Supers: []string{"Channel"}, Methods: map[string]string{"deliver": "p.Sms.deliver"}},
	}
	res := analyze(t, classes, caller, impl)
	if f := flowAt(res, 2); f == nil || f.Function != "p.Sms.deliver" {
		t.Fatalf("interface call did not reach the implementation: %+v", res.Flows)
	}
	if got := res.CallGraph["p.send"]; len(got) != 1 || got[0] != "p.Sms.deliver" {
		t.Errorf("call graph: %v", got)
	}
	if analyze(t, nil, caller, impl).Flows != nil {
		t.Error("without the class table the call has no target")
	}
}

// Closures: called through a variable, and passed as a callback that may
// run later with the call's other arguments.
func TestClosures(t *testing.T) {
	// val show = { v -> Log.d(TAG, v) }; show(email)
	show := newFunc("p.f$1")
	show.Parent = "p.f"
	v := show.AddParam("v", "", pos(2))
	logTo(show, v, 3)

	// items.forEach { Log.d(TAG, xs) }, xs captured; xs.add(email) after.
	later := newFunc("p.f$2")
	later.Parent = "p.f"
	it := later.AddParam("it", "", pos(5))
	_ = it
	xs := later.AddCapture("xs", "", pos(5))
	logTo(later, xs, 6)

	f := newFunc("p.f")
	email := f.AddParam("email", "String", pos(1))
	items := f.AddParam("items", "List", pos(1))
	cl := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Func: "p.f$1", Pos: pos(2)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(4)), Args: []ir.VarID{cl, email}, Call: &ir.Call{Name: "show", Indirect: true}, Pos: pos(4)})
	list := f.Named("xs", "", pos(5))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: list, Call: &ir.Call{Name: "mutableListOf"}, Pos: pos(5)})
	cl2 := f.Temp(pos(5))
	f.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl2, Args: []ir.VarID{list}, Func: "p.f$2", Pos: pos(5)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(7)), Args: []ir.VarID{items, cl2}, Call: &ir.Call{Name: "forEach", HasRecv: true}, Pos: pos(7)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(8)), Args: []ir.VarID{list, email}, Call: &ir.Call{Name: "add", HasRecv: true}, Pos: pos(8)})

	res := analyze(t, nil, f, show, later)
	if fl := flowAt(res, 3); fl == nil || fl.Function != "p.f" {
		t.Errorf("closure called through a variable: %+v (reported in the enclosing function)", fl)
	}
	if fl := flowAt(res, 6); fl == nil {
		t.Errorf("a callback sees what its capture is given after it is passed: %+v", res.Flows)
	}
}

// A closure assigning a captured cell writes the enclosing variable.
func TestClosureWritesCapture(t *testing.T) {
	set := newFunc("p.g$1")
	set.Parent = "p.g"
	found := set.AddCapture("found", "", pos(2))
	e := set.AddCapture("email", "", pos(2))
	set.Vars[found].Cell = true
	set.Assign(found, pos(2), e)

	g := newFunc("p.g")
	email := g.AddParam("email", "String", pos(1))
	fv := g.Named("found", "", pos(1))
	g.Assign(fv, pos(1), g.ConstVar("", pos(1)))
	cl := g.Temp(pos(2))
	g.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Args: []ir.VarID{fv, email}, Func: "p.g$1", Pos: pos(2)})
	g.Emit(ir.Instr{Op: ir.OpCall, Dst: g.Temp(pos(3)), Args: []ir.VarID{cl}, Call: &ir.Call{Name: "run", Indirect: true}, Pos: pos(3)})
	logTo(g, fv, 4)

	if res := analyze(t, nil, g, set); flowAt(res, 4) == nil {
		t.Errorf("assignment to a captured variable is lost: %+v", res.Flows)
	}
}

// What a callee throws reaches the handler its call's block leads to, or
// leaves the caller.
func TestExceptionEdges(t *testing.T) {
	thrower := newFunc("p.fail")
	x := thrower.AddParam("x", "", pos(1))
	thrower.Throw(pos(2), x)

	h := newFunc("p.h")
	email := h.AddParam("email", "String", pos(10))
	h.NewBlock(0)
	h.Emit(ir.Instr{Op: ir.OpCall, Dst: h.Temp(pos(11)), Args: []ir.VarID{email}, Call: &ir.Call{Name: "fail", Target: "p.fail"}, Pos: pos(11)})
	body := h.CurBlock()
	h.NewBlock(body)
	after := h.CurBlock()
	handler := h.NewBlock()
	h.ExcEdge(body, handler)
	caught := h.Temp(pos(12))
	h.Emit(ir.Instr{Op: ir.OpCatch, Dst: caught, Pos: pos(12)})
	logTo(h, caught, 13)
	h.NewBlock(after, handler)
	// Outside the try: what fail throws escapes h.
	h.Emit(ir.Instr{Op: ir.OpCall, Dst: h.Temp(pos(14)), Args: []ir.VarID{email}, Call: &ir.Call{Name: "fail", Target: "p.fail"}, Pos: pos(14)})

	res := analyze(t, nil, h, thrower)
	if flowAt(res, 13) == nil {
		t.Errorf("thrown value does not reach the handler: %+v", res.Flows)
	}
	if s := res.Summaries["p.fail"]; s == nil || len(s.ParamThrow[0]) == 0 {
		t.Errorf("thrower summary: %+v", s)
	}
	if s := res.Summaries["p.h"]; s == nil || len(s.ParamThrow[0]) != 1 {
		t.Errorf("only the call outside the try escapes: %+v", s)
	}
}

// A sink dominated by the "consent given" edge of a consent check is
// reported with the check; one reachable without it is not.
func TestConsentGuardsInEngine(t *testing.T) {
	f := newFunc("p.track")
	email := f.AddParam("email", "String", pos(1))
	ok := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: ok, Call: &ir.Call{Name: "hasConsent"}, Pos: pos(2)})
	not := f.Temp(pos(2))
	f.Compute(not, pos(2), "!", ok)
	ret := f.NewBlock()
	f.Return(pos(3))
	rest := f.NewBlock()
	f.Branch(0, not, ret, rest)
	logTo(f, email, 4) // only when consent was given

	g := newFunc("p.maybe")
	e2 := g.AddParam("email", "String", pos(10))
	c := g.Temp(pos(11))
	g.Emit(ir.Instr{Op: ir.OpCall, Dst: c, Call: &ir.Call{Name: "isOptedIn"}, Pos: pos(11)})
	then := g.NewBlock()
	logTo(g, e2, 12)
	join := g.NewBlock(then)
	g.Branch(0, c, then, join)
	logTo(g, e2, 13) // reached either way

	res := analyze(t, nil, f, g)
	if fl := flowAt(res, 4); fl == nil || len(fl.Guards) != 1 || !strings.Contains(fl.Guards[0], "hasConsent()") {
		t.Errorf("negated early-return guard: %+v", fl)
	}
	if fl := flowAt(res, 12); fl == nil || len(fl.Guards) != 1 || !strings.Contains(fl.Guards[0], "isOptedIn()") {
		t.Errorf("then-branch guard: %+v", fl)
	}
	if fl := flowAt(res, 13); fl == nil || len(fl.Guards) != 0 {
		t.Errorf("join after the if is not guarded: %+v", fl)
	}
}

// Access paths: a.b.c is tracked through loads, stores and summaries.
func TestAccessPaths(t *testing.T) {
	// fun fill(u, v) { u.profile.note = v }
	fill := newFunc("p.fill")
	u := fill.AddParam("u", "", pos(1))
	v := fill.AddParam("v", "", pos(1))
	t1 := fill.Temp(pos(2))
	fill.Emit(ir.Instr{Op: ir.OpLoad, Dst: t1, Args: []ir.VarID{u}, Field: "profile", Pos: pos(2)})
	fill.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{t1, v}, Field: "note", Pos: pos(2)})

	// fun show(u) { Log.d(TAG, u.profile.note) }
	show := newFunc("p.show")
	su := show.AddParam("u", "p.User", pos(5))
	s1 := show.Named("", "p.Profile", pos(6))
	show.Emit(ir.Instr{Op: ir.OpLoad, Dst: s1, Args: []ir.VarID{su}, Field: "profile", Pos: pos(6)})
	s2 := show.Temp(pos(6))
	show.Emit(ir.Instr{Op: ir.OpLoad, Dst: s2, Args: []ir.VarID{s1}, Field: "note", Pos: pos(6)})
	logTo(show, s2, 6)

	// fun main(email) { val u = User(); fill(u, email); Log.d(TAG, u.profile.note); show(u); Log.d(TAG, u.profile.other) }
	m := newFunc("p.main")
	email := m.AddParam("email", "String", pos(10))
	obj := m.Named("u", "", pos(11))
	m.Emit(ir.Instr{Op: ir.OpNew, Dst: obj, Call: &ir.Call{Name: "User"}, Pos: pos(11)})
	m.Emit(ir.Instr{Op: ir.OpCall, Dst: m.Temp(pos(12)), Args: []ir.VarID{obj, email}, Call: &ir.Call{Name: "fill", Target: "p.fill"}, Pos: pos(12)})
	a1 := m.Temp(pos(13))
	m.Emit(ir.Instr{Op: ir.OpLoad, Dst: a1, Args: []ir.VarID{obj}, Field: "profile", Pos: pos(13)})
	a2 := m.Temp(pos(13))
	m.Emit(ir.Instr{Op: ir.OpLoad, Dst: a2, Args: []ir.VarID{a1}, Field: "note", Pos: pos(13)})
	logTo(m, a2, 13)
	m.Emit(ir.Instr{Op: ir.OpCall, Dst: m.Temp(pos(14)), Args: []ir.VarID{obj}, Call: &ir.Call{Name: "show", Target: "p.show"}, Pos: pos(14)})

	types := []*ir.TypeDecl{
		{Name: "p.User", Kind: "class", Fields: []ir.Field{{Name: "profile", Type: "p.Profile"}}},
		{Name: "p.Profile", Kind: "class", Fields: []ir.Field{{Name: "note", Type: "String"}}},
	}
	res := analyzeTyped(t, nil, types, m, fill, show)
	stored := false
	for _, tr := range res.Summaries["p.fill"].ParamParam[0][1] {
		stored = stored || tr.DstField == "profile.note"
	}
	if !stored {
		t.Errorf("fill summary: %+v", res.Summaries["p.fill"])
	}
	sunk := false
	for _, h := range res.Summaries["p.show"].ParamSink[0] {
		sunk = sunk || h.Field == "profile.note"
	}
	if !sunk {
		t.Errorf("show summary: %+v", res.Summaries["p.show"])
	}
	if flowAt(res, 13) == nil {
		t.Errorf("u.profile.note read back after fill: %+v", res.Flows)
	}
	if fl := flowAt(res, 6); fl == nil || fl.Function != "p.show" {
		t.Errorf("show logs u.profile.note: %+v", res.Flows)
	}
	for _, path := range []struct {
		in, add, want string
	}{{"", "a", "a"}, {"a", "b", "a.b"}, {"a.b", "c", "a.b.c"}, {"a.b.c", "d", "a.b.c"}} {
		if got := joinField(path.in, path.add); got != path.want {
			t.Errorf("joinField(%q, %q) = %q", path.in, path.add, got)
		}
	}
}
