// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"slices"
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
		{Name: "p.Sms", Supers: []string{"p.Channel"}, Methods: map[string]string{"deliver": "p.Sms.deliver"}},
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
	// The interface itself may be missing from the table (declared in a
	// file not scanned this run): its implementations are still found.
	if res := analyze(t, classes[1:], caller, impl); flowAt(res, 2) == nil {
		t.Errorf("implementation of an interface missing from the table: %+v", res.Flows)
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

	// listeners.add { Log.d(TAG, xs) } and items.forEach { Log.d(TAG, xs) },
	// xs captured; xs.add(email) after both.
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
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(7)), Args: []ir.VarID{items, cl2}, Call: &ir.Call{Name: "add", HasRecv: true}, Pos: pos(7)})
	now := newFunc("p.f$3")
	now.Parent = "p.f"
	now.AddParam("it", "", pos(9))
	nxs := now.AddCapture("xs", "", pos(9))
	logTo(now, nxs, 10)
	cl3 := f.Temp(pos(9))
	f.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl3, Args: []ir.VarID{list}, Func: "p.f$3", Pos: pos(9)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(11)), Args: []ir.VarID{items, cl3}, Call: &ir.Call{Name: "forEach", HasRecv: true}, Pos: pos(11)})
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(12)), Args: []ir.VarID{list, email}, Call: &ir.Call{Name: "add", HasRecv: true}, Pos: pos(12)})

	res := analyze(t, nil, f, show, later, now)
	if fl := flowAt(res, 3); fl == nil || fl.Function != "p.f" {
		t.Errorf("closure called through a variable: %+v (reported in the enclosing function)", fl)
	}
	if fl := flowAt(res, 6); fl == nil {
		t.Errorf("a stored callback sees what its capture is given after it is passed: %+v", res.Flows)
	}
	if fl := flowAt(res, 10); fl != nil {
		t.Errorf("forEach runs its callback before the capture is given data: %+v", fl)
	}
	if !runsCallbackNow(&ir.Call{Name: "ForEach"}) || runsCallbackNow(&ir.Call{Name: "addListener"}) || runsCallbackNow(nil) {
		t.Error("runsCallbackNow")
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

// Closures travel through fields, parameters and returns (closureFlow).
func TestClosureFlow(t *testing.T) {
	// class Box(val cb) { fun fire(x) = cb(x) }; Box { v -> log(v) }.fire(email)
	handler := newFunc("p.register$1")
	handler.Parent = "p.register"
	logTo(handler, handler.AddParam("v", "", pos(3)), 3)
	ctor := newFunc("p.Box.<init>")
	this := ctor.AddParam("this", "p.Box", pos(5))
	cb := ctor.AddParam("cb", "", pos(5))
	ctor.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{this, cb}, Field: "cb", Pos: pos(5)})
	fire := newFunc("p.Box.fire")
	fthis := fire.AddParam("this", "p.Box", pos(6))
	x := fire.AddParam("x", "", pos(6))
	fire.Emit(ir.Instr{Op: ir.OpCall, Dst: fire.Temp(pos(6)), Args: []ir.VarID{fthis, x}, Call: &ir.Call{Name: "cb", HasRecv: true, RecvType: "p.Box"}, Pos: pos(6)})
	register := newFunc("p.register")
	email := register.AddParam("email", "String", pos(2))
	cl := register.Temp(pos(3))
	register.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Func: "p.register$1", Pos: pos(3)})
	box := register.Temp(pos(4))
	register.Emit(ir.Instr{Op: ir.OpNew, Dst: box, Args: []ir.VarID{cl}, Call: &ir.Call{Callee: "p.Box", Name: "Box", Target: "p.Box.<init>"}, Pos: pos(4)})
	register.Emit(ir.Instr{Op: ir.OpCall, Dst: register.Temp(pos(4)), Args: []ir.VarID{box, email}, Call: &ir.Call{Name: "fire", HasRecv: true, RecvType: "p.Box", Target: "p.Box.fire"}, Pos: pos(4)})

	// fun each(items, action) = action(items): a() passes a logging
	// closure, b() passes personal data with a closure that does nothing.
	each := newFunc("p.each")
	items := each.AddParam("items", "", pos(20))
	action := each.AddParam("action", "", pos(20))
	each.Emit(ir.Instr{Op: ir.OpCall, Dst: each.Temp(pos(20)), Args: []ir.VarID{action, items}, Call: &ir.Call{Name: "action", Indirect: true}, Pos: pos(20)})
	aLog := newFunc("p.a$1")
	aLog.Parent = "p.a"
	logTo(aLog, aLog.AddParam("v", "", pos(22)), 22)
	fa := newFunc("p.a")
	ids := fa.AddParam("ids", "", pos(21))
	acl := fa.Temp(pos(22))
	fa.Emit(ir.Instr{Op: ir.OpClosure, Dst: acl, Func: "p.a$1", Pos: pos(22)})
	fa.Emit(ir.Instr{Op: ir.OpCall, Dst: fa.Temp(pos(22)), Args: []ir.VarID{ids, acl}, Call: &ir.Call{Name: "each", Target: "p.each"}, Pos: pos(22)})
	bNop := newFunc("p.b$1")
	bNop.Parent = "p.b"
	bNop.AddParam("v", "", pos(24))
	fb := newFunc("p.b")
	emails := fb.AddParam("email", "String", pos(23))
	bcl := fb.Temp(pos(24))
	fb.Emit(ir.Instr{Op: ir.OpClosure, Dst: bcl, Func: "p.b$1", Pos: pos(24)})
	fb.Emit(ir.Instr{Op: ir.OpCall, Dst: fb.Temp(pos(24)), Args: []ir.VarID{emails, bcl}, Call: &ir.Call{Name: "each", Target: "p.each"}, Pos: pos(24)})

	// fun mk() = { v -> log(v) }; mk()(email)
	mkLog := newFunc("p.mk$1")
	mkLog.Parent = "p.mk"
	logTo(mkLog, mkLog.AddParam("v", "", pos(31)), 31)
	mk := newFunc("p.mk")
	mcl := mk.Temp(pos(30))
	mk.Emit(ir.Instr{Op: ir.OpClosure, Dst: mcl, Func: "p.mk$1", Pos: pos(30)})
	mk.Return(pos(30), mcl)
	useMk := newFunc("p.useMk")
	uemail := useMk.AddParam("email", "String", pos(32))
	r := useMk.Temp(pos(33))
	useMk.Emit(ir.Instr{Op: ir.OpCall, Dst: r, Call: &ir.Call{Name: "mk", Target: "p.mk"}, Pos: pos(33)})
	useMk.Emit(ir.Instr{Op: ir.OpCall, Dst: useMk.Temp(pos(34)), Args: []ir.VarID{r, uemail}, Call: &ir.Call{Name: "r", Indirect: true}, Pos: pos(34)})

	// fun capture(x) = { log(x) }; capture(email): the returned closure
	// reads its capture wherever it is called.
	capLog := newFunc("p.capture$1")
	capLog.Parent = "p.capture"
	logTo(capLog, capLog.AddCapture("c", "", pos(41)), 41)
	capture := newFunc("p.capture")
	cx := capture.AddParam("x", "", pos(40))
	ccl := capture.Temp(pos(41))
	capture.Emit(ir.Instr{Op: ir.OpClosure, Dst: ccl, Args: []ir.VarID{cx}, Func: "p.capture$1", Pos: pos(41)})
	capture.Return(pos(41), ccl)
	useCap := newFunc("p.useCap")
	cemail := useCap.AddParam("email", "String", pos(42))
	useCap.Emit(ir.Instr{Op: ir.OpCall, Dst: useCap.Temp(pos(43)), Args: []ir.VarID{cemail}, Call: &ir.Call{Name: "capture", Target: "p.capture"}, Pos: pos(43)})

	classes := []*ir.Class{{Name: "p.Box", Methods: map[string]string{"fire": "p.Box.fire", "<init>": "p.Box.<init>"}}}
	res := analyze(t, classes, handler, ctor, fire, register, each, aLog, fa, bNop, fb, mkLog, mk, useMk, capLog, capture, useCap)
	if fl := flowAt(res, 3); fl == nil || fl.Function != "p.register" {
		t.Errorf("closure kept in a field and called by another method: %+v", fl)
	}
	if fl := flowAt(res, 22); fl != nil {
		t.Errorf("a closure passed to a function is run with what other callers pass: %+v", fl)
	}
	if fl := flowAt(res, 31); fl == nil {
		t.Errorf("returned closure called by the caller: %+v", res.Flows)
	}
	if fl := flowAt(res, 41); fl == nil {
		t.Errorf("returned closure reading its capture: %+v", res.Flows)
	}
}

func TestRunsReceiver(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nargs      int
		closureArg bool
		want       bool
	}{
		{"accept", 1, false, true},
		{"invoke", 1, false, true},
		{"run", 0, false, true},
		{"get", 0, false, true},
		{"get", 1, false, false},
		{"add", 1, false, false},
		{"forEach", 1, true, false},
		{"apply", 1, false, true},
		{"apply", 1, true, false},
	} {
		if got := runsReceiver(&ir.Call{Name: tc.name}, tc.nargs, tc.closureArg); got != tc.want {
			t.Errorf("runsReceiver(%s, %d, %v) = %v", tc.name, tc.nargs, tc.closureArg, got)
		}
	}
	if ownerKey("*app.List<T>?") != "List" || ownerKey("") != "" {
		t.Error("ownerKey")
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

// A helper returning a consent check guards like the check, and a function
// only called after a check inherits it, unless a caller outside the run
// may call it without one.
func TestHelperAndCallerGuards(t *testing.T) {
	// fun mayContact(c) = c.hasConsent()
	helper := newFunc("p.mayContact")
	hc := helper.AddParam("c", "", pos(1))
	r := helper.Temp(pos(1))
	helper.Emit(ir.Instr{Op: ir.OpCall, Dst: r, Args: []ir.VarID{hc}, Call: &ir.Call{Name: "hasConsent", HasRecv: true}, Pos: pos(1)})
	helper.Return(pos(1), r)
	// fun send(email) = log(email)
	send := newFunc("p.send")
	logTo(send, send.AddParam("email", "String", pos(5)), 6)
	// fun caller(email, c) { if (mayContact(c)) send(email) }
	caller := newFunc("p.caller")
	email := caller.AddParam("email", "String", pos(10))
	c := caller.AddParam("c", "", pos(10))
	ok := caller.Temp(pos(11))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: ok, Args: []ir.VarID{c}, Call: &ir.Call{Name: "mayContact", Target: "p.mayContact"}, Pos: pos(11)})
	then := caller.NewBlock()
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: caller.Temp(pos(12)), Args: []ir.VarID{email}, Call: &ir.Call{Name: "send", Target: "p.send"}, Pos: pos(12)})
	join := caller.NewBlock(then)
	caller.Branch(0, ok, then, join)

	run := func(callers func(string) []string) *Result {
		rs, err := rules.Load(nil)
		if err != nil {
			t.Fatal(err)
		}
		names := detect.NewClassifier(detect.DefaultTaxonomy())
		res, err := Analyze(context.Background(), []*ir.Func{helper, send, caller}, Options{Rules: rs, Schema: detect.BuildSchema(names, nil), Names: names, Callers: callers})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := run(nil)
	if len(res.Flows) == 0 {
		t.Fatal("no flows")
	}
	for _, fl := range res.Flows {
		if len(fl.Guards) != 1 || !strings.Contains(fl.Guards[0], "mayContact() (hasConsent())") {
			t.Errorf("flow from %s at %s: guards %v", fl.Source, fl.Sink, fl.Guards)
		}
	}
	res = run(func(id string) []string {
		if id == "p.send" {
			return []string{"p.caller", "p.elsewhere"}
		}
		return nil
	})
	if fl := flowAt(res, 6); fl == nil {
		t.Fatal("no flow")
	}
	for _, fl := range res.Flows {
		if fl.Source.Line == 5 && len(fl.Guards) != 0 {
			t.Errorf("a caller outside the run may call send unguarded: %v", fl.Guards)
		}
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

// Branches on checks refine the checked value where they pass.
func TestChecks(t *testing.T) {
	// fun f(email, q, msg) {
	//   if (isMasked(email)) log(email)       // line 3, masked
	//   if (!containsPii(msg)) log(msg)       // line 5, pii-checked
	//   if (isValidEmail(q)) log(q)           // line 7, an email
	//   log(q)                                // line 8, nothing
	// }
	f := newFunc("p.f")
	email := f.AddParam("email", "String", pos(1))
	q := f.AddParam("q", "String", pos(1))
	msg := f.AddParam("msg", "String", pos(1))
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{msg, email}, Field: "body", Pos: pos(1)})
	branch := func(line int, name string, arg ir.VarID, negate bool, then func()) {
		c := f.Temp(pos(line))
		f.Emit(ir.Instr{Op: ir.OpCall, Dst: c, Args: []ir.VarID{arg}, Call: &ir.Call{Name: name}, Pos: pos(line)})
		if negate {
			n := f.Temp(pos(line))
			f.Compute(n, pos(line), "!", c)
			c = n
		}
		from := f.CurBlock()
		body := f.NewBlock(from)
		then()
		join := f.NewBlock(body, from)
		f.Branch(from, c, body, join)
	}
	branch(2, "isMasked", email, false, func() { logTo(f, email, 3) })
	branch(4, "containsPii", msg, true, func() { logTo(f, msg, 5) })
	branch(6, "isValidEmail", q, false, func() { logTo(f, q, 7) })
	logTo(f, q, 8)

	a := &analyzer{opts: Options{Names: detect.NewClassifier(detect.DefaultTaxonomy())}}
	rf, cks := a.refineChecks(f)
	if len(cks) != 3 || rf == f {
		t.Fatalf("checks: %v", cks)
	}
	if err := ir.Verify(rf); err != nil {
		t.Fatalf("refined IR does not verify: %v\n%s", err, ir.Format(rf))
	}
	if err := ir.Verify(f); err != nil || len(f.Instrs) == len(rf.Instrs) {
		t.Fatalf("the original function was changed: %v", err)
	}

	res := analyze(t, nil, f)
	if fl := flowAt(res, 3); fl == nil || !slices.Contains(fl.Transforms, "masked") {
		t.Errorf("isMasked: %+v", fl)
	}
	if fl := flowAt(res, 5); fl == nil || !slices.Contains(fl.Transforms, "pii-checked") {
		t.Errorf("!containsPii: %+v", fl)
	}
	if fl := flowAt(res, 7); fl == nil || fl.DataType != "email" || !strings.Contains(fl.SourceDesc, "isValidEmail") {
		t.Errorf("isValidEmail: %+v", fl)
	}
	if fl := flowAt(res, 8); fl != nil {
		t.Errorf("after the if, q is not known to be an email: %+v", fl)
	}

	for name, want := range map[string]string{"wasAnonymised": "anonymized", "is_redacted": "redacted", "hasPii": "pii-checked", "isEmpty": "", "isValid": "", "validatePhoneNumber": "phone"} {
		ck, _, ok := a.checkKind(name, pos(1))
		got := ck.xf + strings.TrimPrefix(ck.dt, "pii.")
		if ck.dt != "" {
			got = ck.dt
		}
		if (want == "") == ok || (ok && !strings.Contains(got, want)) {
			t.Errorf("checkKind(%s) = %+v %v, want %q", name, ck, ok, want)
		}
	}
}

// Points-to: a mutation through one variable is seen through every
// variable that may refer to the same object, and only there; a field
// store stays in its field.
func TestPointsTo(t *testing.T) {
	f := newFunc("p.f")
	email := f.AddParam("email", "String", pos(1))
	c := f.AddParam("c", "Boolean", pos(1))
	alloc := func(line int) ir.VarID {
		v := f.Temp(pos(line))
		f.Emit(ir.Instr{Op: ir.OpNew, Dst: v, Call: &ir.Call{Callee: "p.Box", Name: "Box"}, Pos: pos(line)})
		return v
	}
	load := func(obj ir.VarID, field string, line int) ir.VarID {
		v := f.Temp(pos(line))
		f.Emit(ir.Instr{Op: ir.OpLoad, Dst: v, Args: []ir.VarID{obj}, Field: field, Pos: pos(line)})
		return v
	}
	a, b, other := alloc(2), alloc(2), alloc(2)
	x := f.Temp(pos(3))
	f.Emit(ir.Instr{Op: ir.OpAssign, Dst: x, Args: []ir.VarID{a}, Pos: pos(3)})
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{x, email}, Field: "f", Pos: pos(4)})
	logTo(f, load(a, "f", 5), 5)     // through the alias: reported
	logTo(f, load(b, "f", 6), 6)     // another object: not reported
	logTo(f, load(a, "g", 7), 7)     // another field: not reported
	logTo(f, load(other, "f", 8), 8) // not reported
	// y = c ? b : other; y.f = email; log(b.f) at 12
	then := f.NewBlock(0)
	join := f.NewBlock(0, then)
	f.Branch(0, c, then, join)
	y := f.Temp(pos(10))
	f.Emit(ir.Instr{Op: ir.OpPhi, Dst: y, Args: []ir.VarID{b, other}, From: []int32{0, then}, Pos: pos(10)})
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{y, email}, Field: "h", Pos: pos(11)})
	logTo(f, load(b, "h", 12), 12)

	res := analyze(t, nil, f)
	if flowAt(res, 5) == nil || flowAt(res, 12) == nil {
		t.Errorf("alias or phi alias missed: %+v", res.Flows)
	}
	for _, line := range []int{6, 7, 8} {
		if fl := flowAt(res, line); fl != nil {
			t.Errorf("line %d: %+v", line, fl)
		}
	}
	pt := newPointsTo(f, nil, nil, newOrder(f))
	if !slices.Contains(pt.mutated(x), a) || slices.Contains(pt.mutated(a), b) || !slices.Contains(pt.mutated(y), other) {
		t.Errorf("aliases: x %v, a %v, y %v", pt.mutated(x), pt.mutated(a), pt.mutated(y))
	}
	if got := (*pointsTo)(nil).mutated(a); len(got) != 1 {
		t.Errorf("nil points-to: %v", got)
	}
}

// A store into the same field of the same single object overwrites what
// was stored before (a strong update); summaries see only what is left
// when the function returns.
func TestStrongUpdates(t *testing.T) {
	// fun f(u, email) { u.name = email; u.name = "x" }
	f := newFunc("p.f")
	u := f.AddParam("u", "", pos(1))
	email := f.AddParam("email", "String", pos(1))
	x := f.ConstVar("x", pos(3))
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{u, email}, Field: "name", Pos: pos(2)})
	f.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{u, x}, Field: "name", Pos: pos(3)})
	f.Return(pos(3))

	// fun g(email, c) {
	//   val a = Box(); a.f = email; a.f = "x"; log(a.f)          // 12: overwritten
	//   val b = Box(); b.f = email; if (c) b.f = "x"; log(b.f)    // 16: not on every path
	// }
	g := newFunc("p.g")
	ge := g.AddParam("email", "String", pos(10))
	c := g.AddParam("c", "Boolean", pos(10))
	gx := g.ConstVar("x", pos(10))
	box := func(line int) ir.VarID {
		v := g.Temp(pos(line))
		g.Emit(ir.Instr{Op: ir.OpNew, Dst: v, Call: &ir.Call{Callee: "p.Box", Name: "Box"}, Pos: pos(line)})
		return v
	}
	read := func(obj ir.VarID, line int) {
		v := g.Temp(pos(line))
		g.Emit(ir.Instr{Op: ir.OpLoad, Dst: v, Args: []ir.VarID{obj}, Field: "f", Pos: pos(line)})
		logTo(g, v, line)
	}
	store := func(obj, v ir.VarID, line int) {
		g.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{obj, v}, Field: "f", Pos: pos(line)})
	}
	a := box(11)
	store(a, ge, 11)
	store(a, gx, 11)
	read(a, 12)
	b := box(13)
	store(b, ge, 13)
	then := g.NewBlock(0)
	store(b, gx, 14)
	join := g.NewBlock(0, then)
	g.Branch(0, c, then, join)
	read(b, 16)

	res := analyze(t, nil, f, g)
	if s := res.Summaries["p.f"]; s != nil && len(s.ParamParam[0]) > 0 {
		t.Errorf("an overwritten field is in the summary: %+v", s.ParamParam)
	}
	if fl := flowAt(res, 12); fl != nil {
		t.Errorf("overwritten field reported: %+v", fl)
	}
	if fl := flowAt(res, 16); fl == nil {
		t.Errorf("a field overwritten on one path only is lost: %+v", res.Flows)
	}
}

// Text before a value names it; names and definitions refine what a value
// is.
func TestLabelsAndNames(t *testing.T) {
	f := newFunc("p.f")
	cc := f.AddParam("cctxt", "String", pos(1))
	n := f.AddParam("n", "Int", pos(1))
	pw := f.AddParam("pw", "String", pos(1))
	// "Error with credit card: " + cctxt → a card number (line 2).
	msg := f.Temp(pos(2))
	f.Compute(msg, pos(2), "+", f.ConstVar("Error with credit card: ", pos(2)), cc)
	logTo(f, msg, 2)
	// "count: " + n → nothing (line 3).
	cnt := f.Temp(pos(3))
	f.Compute(cnt, pos(3), "+", f.ConstVar("count: ", pos(3)), n)
	logTo(f, cnt, 3)
	// Log.d(TAG, "user email=%s", cctxt): a format string (line 4).
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(4)), Args: []ir.VarID{f.ConstVar("TAG", pos(4)), f.ConstVar("user email=%s", pos(4)), cc},
		Call: &ir.Call{Callee: "android.util.Log.d", Name: "d"}, Pos: pos(4)})
	// val password = encryptString(pw); prefs.putString("password", password)
	// is encrypted, key or no key (line 5).
	enc := f.Named("password", "String", pos(5))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: enc, Args: []ir.VarID{pw}, Call: &ir.Call{Name: "encryptString"}, Pos: pos(5)})
	editor := f.Named("editor", "android.content.SharedPreferences.Editor", pos(5))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(5)), Args: []ir.VarID{editor, f.ConstVar("password", pos(5)), enc},
		Call: &ir.Call{Callee: "android.content.SharedPreferences.Editor.putString", Name: "putString", HasRecv: true}, Pos: pos(5)})
	// val derivationStatus = derive(pw): a status, not the password (line 6).
	st := f.Temp(pos(6))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: st, Args: []ir.VarID{f.Named("password", "String", pos(6))}, Call: &ir.Call{Name: "derive"}, Pos: pos(6)})
	status := f.Named("derivationStatus", "", pos(6))
	f.Assign(status, pos(6), st)
	logTo(f, status, 6)

	res := analyze(t, nil, f)
	if fl := flowAt(res, 2); fl == nil || fl.DataType != "credit_card" {
		t.Errorf("labelled concatenation: %+v", fl)
	}
	if fl := flowAt(res, 3); fl != nil {
		t.Errorf("count: %+v", fl)
	}
	if fl := flowAt(res, 4); fl == nil || fl.DataType != "email" {
		t.Errorf("format string: %+v", fl)
	}
	for _, fl := range res.Flows {
		if fl.Sink.Line == 5 && !slices.Contains(fl.Transforms, "encrypted") {
			t.Errorf("an encrypted value stored under a password key: %+v", fl)
		}
	}
	if fl := flowAt(res, 6); fl != nil {
		t.Errorf("status: %+v", fl)
	}
	for name, want := range map[string]bool{"derivationStatus": true, "rowCount": true, "count": true, "discount": false, "status": true, "is_ok": true, "token": false} {
		if dataFreeName(name) != want {
			t.Errorf("dataFreeName(%s) = %v", name, !want)
		}
	}
}

// Dispatch stays within the caller's language.
func TestDispatchStaysInLanguage(t *testing.T) {
	h := newHierarchy([]*ir.Class{
		{Name: "error", Lang: "go"},
		{Name: "jsError", Lang: "typescript", Supers: []string{"error"}, Methods: map[string]string{"Error": "js.Error"}},
		{Name: "myErr", Lang: "go", Supers: []string{"error"}, Methods: map[string]string{"Error": "p.myErr.Error"}},
	})
	c := &ir.Call{Name: "Error", HasRecv: true, RecvType: "error"}
	if got := h.targets(c, "go"); len(got) != 1 || got[0] != "p.myErr.Error" {
		t.Errorf("go targets: %v", got)
	}
	if got := h.targets(c, ""); len(got) != 2 {
		t.Errorf("any language: %v", got)
	}
}
