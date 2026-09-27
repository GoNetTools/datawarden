// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// tsFunc is a TypeScript function in file.
func tsFunc(id, file string) *ir.Func {
	f := newFunc(id)
	f.Lang, f.File = "typescript", file
	return f
}

// keepsLogger stores, in field of an object of type owner, a closure that
// logs its argument: three.js's obj.render = function (v) {...}, or a
// handler kept on a bus.
func keepsLogger(id, file, owner, field string) []*ir.Func {
	cl := tsFunc(id+"$1", file)
	cl.Parent = id
	v := cl.AddParam("v", "", pos(2))
	cl.Emit(ir.Instr{Op: ir.OpCall, Dst: cl.Temp(pos(3)), Args: []ir.VarID{v},
		Call: &ir.Call{Callee: "console.log", Name: "log", RecvText: "console"}, Pos: pos(3)})
	holder := tsFunc(id, file)
	obj := holder.Named("obj", owner, pos(1))
	holder.Assign(obj, pos(1))
	c := holder.Temp(pos(2))
	holder.Emit(ir.Instr{Op: ir.OpClosure, Dst: c, Func: cl.ID, Pos: pos(2)})
	holder.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{obj, c}, Field: field, Owner: owner, Pos: pos(2)})
	return []*ir.Func{cl, holder}
}

// A method call on a receiver of unknown type runs the closures kept in a
// field of its name only when the code calling it and the code holding
// the closure are part of one program (#55): a server's res.render(...)
// does not run the render closures of a copy of three.js shipped to
// browsers, but one that uses that code does.
func TestClosureFieldsStayInProgram(t *testing.T) {
	render := func(uses bool) []*ir.Func {
		srv := tsFunc("routes/erase:handler", "routes/erase.ts")
		res := srv.AddParam("res", "", pos(10))
		email := srv.AddParam("email", "string", pos(10))
		if uses {
			call(srv, 11, &ir.Call{Callee: "assets/three:setup", Name: "setup"})
		}
		call(srv, 12, &ir.Call{Name: "render", HasRecv: true}, res, email)
		setup := tsFunc("assets/three:setup", "assets/three.js")
		return append(keepsLogger("assets/three:<init>", "assets/three.js", "", "render"), srv, setup)
	}
	if fl := analyze(t, nil, render(false)...).Flows; len(fl) != 0 {
		t.Errorf("the server ran a closure of a file it does not use: %s at %v", fl[0].DataType, fl[0].Sink)
	}
	if fl := analyze(t, nil, render(true)...).Flows; len(fl) != 1 {
		t.Errorf("a closure of a file the caller uses: %d flows, want 1", len(fl))
	}

	// Two files that only share the type of the object holding the
	// closure: a handler kept on a Bus runs when another file calls it.
	bus := &ir.Class{Name: "lib/bus:Bus", Lang: "typescript", File: "lib/bus.ts"}
	run := tsFunc("app/run:send", "app/run.ts")
	b := run.AddParam("bus", "lib/bus:Bus", pos(10))
	email := run.AddParam("email", "string", pos(10))
	call(run, 11, &ir.Call{Name: "notify", HasRecv: true, RecvType: "lib/bus:Bus"}, b, email)
	funcs := append(keepsLogger("app/wire:init", "app/wire.ts", "lib/bus:Bus", "notify"), run)
	if fl := analyze(t, []*ir.Class{bus}, funcs...).Flows; len(fl) != 1 {
		t.Errorf("a handler kept on a shared type: %d flows, want 1", len(fl))
	}
}
