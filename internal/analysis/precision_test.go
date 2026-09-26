// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"slices"
	"testing"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// Precision regressions found scanning real applications: constructs that
// made unrelated values look like personal data.

func call(f *ir.Func, line int, c *ir.Call, args ...ir.VarID) ir.VarID {
	dst := f.Temp(pos(line))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: dst, Args: args, Call: c, Pos: pos(line)})
	return dst
}

// ctx.set("user", email) stores the email under "user": ctx.fullPath()
// does not return it, ctx.get("user") does.
func TestKeyedPut(t *testing.T) {
	f := newFunc("p.handle")
	ctx := f.AddParam("ctx", "", pos(1))
	email := f.AddParam("email", "String", pos(1))
	call(f, 2, &ir.Call{Name: "set", HasRecv: true}, ctx, f.ConstVar("user", pos(2)), email)
	path := call(f, 3, &ir.Call{Name: "fullPath", HasRecv: true}, ctx)
	logTo(f, path, 4)
	u := call(f, 5, &ir.Call{Name: "get", HasRecv: true}, ctx, f.ConstVar("user", pos(5)))
	logTo(f, u, 6)
	logTo(f, ctx, 7)
	other := call(f, 8, &ir.Call{Name: "get", HasRecv: true}, ctx, f.ConstVar("requestId", pos(8)))
	logTo(f, other, 9)

	res := analyze(t, nil, f)
	for _, line := range []int{4, 9} {
		if fl := flowAt(res, line); fl != nil {
			t.Errorf("line %d: a read of another part of ctx reported as carrying the email: %+v", line, fl)
		}
	}
	for _, line := range []int{6, 7} {
		if flowAt(res, line) == nil {
			t.Errorf("line %d: the email put under \"user\" is not reported", line)
		}
	}
}

// log.Info().Str("ip", ip).Str("method", m).Msg("") logs the IP once, at
// the call given it, not again at every later call of the chain.
func TestChainedLoggerReportsOnce(t *testing.T) {
	f := newFunc("p.access")
	f.Lang = "go"
	ip := f.AddParam("clientIP", "string", pos(1))
	ev := call(f, 2, &ir.Call{Callee: "github.com/rs/zerolog/log.Info", Name: "Info"})
	ev = call(f, 3, &ir.Call{Callee: "github.com/rs/zerolog.Event.Str", Name: "Str", HasRecv: true}, ev, f.ConstVar("ip", pos(3)), ip)
	ev = call(f, 4, &ir.Call{Callee: "github.com/rs/zerolog.Event.Str", Name: "Str", HasRecv: true}, ev, f.ConstVar("method", pos(4)), f.ConstVar("GET", pos(4)))
	call(f, 5, &ir.Call{Callee: "github.com/rs/zerolog.Event.Msg", Name: "Msg", HasRecv: true}, ev, f.ConstVar("HTTP", pos(5)))

	res := analyze(t, nil, f)
	var lines []int
	for _, fl := range res.Flows {
		lines = append(lines, fl.Sink.Line)
	}
	if !slices.Equal(lines, []int{3}) {
		t.Errorf("sinks at lines %v, want [3]", lines)
	}
}

// A query built with personal data does not put it into the database
// handle: later uses of the handle do not carry it.
func TestHandleNotMutated(t *testing.T) {
	f := newFunc("p.save")
	db := f.AddParam("db", "*gorm.io/gorm.DB", pos(1))
	email := f.AddParam("email", "String", pos(1))
	call(f, 2, &ir.Call{Callee: "gorm.io/gorm.DB.Save", Name: "Save", HasRecv: true, RecvType: "*gorm.io/gorm.DB"}, db, email)
	logTo(f, db, 3)

	if fl := flowAt(analyze(t, nil, f), 3); fl != nil {
		t.Errorf("the database handle reported as holding the email: %+v", fl)
	}
}

// A callback registered with unknown code (a middleware) writes into the
// arguments it is later called with, not into the registration's.
func TestKeptCallbackOutputs(t *testing.T) {
	mw := newFunc("p.setup$1")
	mw.Parent = "p.setup"
	ctx := mw.AddParam("ctx", "", pos(2))
	email := mw.Named("email", "", pos(3))
	mw.Assign(email, pos(3), mw.ConstVar("a@example.com", pos(3)))
	mw.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{ctx, email}, Field: "user", Pos: pos(3)})

	f := newFunc("p.setup")
	router := f.AddParam("router", "", pos(1))
	cl := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Func: "p.setup$1", Pos: pos(2)})
	call(f, 4, &ir.Call{Name: "middleware", HasRecv: true}, router, cl)
	logTo(f, router, 5)

	if fl := flowAt(analyze(t, nil, f, mw), 5); fl != nil {
		t.Errorf("the router reported as holding what the middleware stores in its context: %+v", fl)
	}
}

// A closure stored in a field in one language is not run by a call of a
// method of that name in another.
func TestClosureFieldsStayInLanguage(t *testing.T) {
	render := newFunc("web.render$1")
	render.Lang = "typescript"
	render.Parent = "web.render"
	v := render.AddParam("v", "", pos(2))
	render.Emit(ir.Instr{Op: ir.OpCall, Dst: render.Temp(pos(3)), Args: []ir.VarID{v},
		Call: &ir.Call{Callee: "console.log", Name: "log", RecvText: "console"}, Pos: pos(3)})
	holder := newFunc("web.render")
	holder.Lang = "typescript"
	obj := holder.Temp(pos(1))
	holder.Assign(obj, pos(1))
	cl := holder.Temp(pos(2))
	holder.Emit(ir.Instr{Op: ir.OpClosure, Dst: cl, Func: "web.render$1", Pos: pos(2)})
	holder.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{obj, cl}, Field: "build", Pos: pos(2)})

	kt := newFunc("app.send")
	req := kt.AddParam("req", "", pos(10))
	email := kt.AddParam("email", "String", pos(10))
	call(kt, 11, &ir.Call{Name: "build", HasRecv: true}, req, email)

	for _, fl := range analyze(t, nil, render, holder, kt).Flows {
		t.Errorf("a Kotlin call ran a TypeScript closure: %s at %v", fl.DataType, fl.Sink)
	}
}

// A path going round a loop keeps one pass of it.
func TestAppendPathDropsLoops(t *testing.T) {
	a, b, c, d := pos(1), pos(2), pos(3), pos(4)
	got := appendPath([]ir.Pos{a, b, c}, b, c, b, d)
	if want := []ir.Pos{a, b, d}; !slices.Equal(got, want) {
		t.Errorf("appendPath = %v, want %v", got, want)
	}
}
