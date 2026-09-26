// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"slices"
	"strings"
	"testing"
)

var at = Pos{File: "a.kt", Line: 1}

// diamond builds
//
//	b0: c = call check(); if c -> b1, b2
//	b1: x1 = "a"            b2: x2 = p
//	b3: x3 = phi(b1: x1, b2: x2); return x3
func diamond() (*Func, VarID) {
	f := &Func{ID: "p.f"}
	p := f.AddParam("p", "", at)
	f.NewBlock()
	c := f.Temp(at)
	f.Emit(Instr{Op: OpCall, Dst: c, Call: &Call{Name: "check"}, Pos: at})
	b1 := f.NewBlock()
	x1 := f.Named("x", "", at)
	f.Assign(x1, at, f.ConstVar("a", at))
	b2 := f.NewBlock()
	x2 := f.Named("x", "", at)
	f.Assign(x2, at, p)
	f.Branch(0, c, b1, b2)
	f.NewBlock(b1, b2)
	x3 := f.Named("x", "", at)
	f.Phi(x3, at, []VarID{x1, x2}, []int32{b1, b2})
	f.Return(at, x3)
	return f, x3
}

func TestVerifyAcceptsWellFormedIR(t *testing.T) {
	f, _ := diamond()
	if err := Verify(f); err != nil {
		t.Fatalf("%v\n%s", err, Format(f))
	}
	// Exceptional edges, catch, throw, closures and cells.
	g := &Func{ID: "p.g"}
	cap := g.AddCapture("email", "", at)
	g.Vars[cap].Cell = true
	g.NewBlock()
	g.Emit(Instr{Op: OpCall, Dst: g.Temp(at), Args: []VarID{cap}, Call: &Call{Name: "risky"}, Pos: at})
	g.NewBlock(0)
	g.Assign(cap, at, g.ConstVar("x", at))
	g.Assign(cap, at, g.ConstVar("y", at))
	h := g.NewBlock()
	g.ExcEdge(0, h)
	e := g.Temp(at)
	g.Emit(Instr{Op: OpCatch, Dst: e, Pos: at})
	cl := g.Temp(at)
	g.Emit(Instr{Op: OpClosure, Dst: cl, Args: []VarID{e}, Func: "p.g$1", Pos: at})
	g.Emit(Instr{Op: OpYield, Dst: NoVar, Args: []VarID{cl}, Pos: at})
	g.Throw(at, e)
	if err := Verify(g); err != nil {
		t.Fatalf("%v\n%s", err, Format(g))
	}
	if g.Captures != 1 || (&Module{Funcs: []*Func{f, g}}).Verify() != nil {
		t.Error("module verify")
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *Func, x3 VarID)
		want   string
	}{
		"double definition": {func(f *Func, x3 VarID) {
			f.Instrs = append(f.Instrs[:len(f.Instrs)-1], Instr{Op: OpAssign, Dst: x3, Args: []VarID{0}, Block: 3}, f.Instrs[len(f.Instrs)-1])
		}, "defined twice"},
		"use not dominated": {func(f *Func, _ VarID) {
			// b2 reads x1, defined in b1.
			f.Instrs[2].Args[0] = 2
		}, "not dominated"},
		"phi from a non-predecessor": {func(f *Func, _ VarID) { f.Instrs[3].From[0] = 0 }, "not a predecessor"},
		"phi argument count":         {func(f *Func, _ VarID) { f.Instrs[3].From = f.Instrs[3].From[:1] }, "predecessors for 2 arguments"},
		"return not last": {func(f *Func, _ VarID) {
			f.Instrs = append(f.Instrs, Instr{Op: OpAssign, Dst: f.Temp(at), Args: []VarID{0}, Block: 3})
		}, "does not end block"},
		"branch without a condition": {func(f *Func, _ VarID) { f.Blocks[0].Succs = f.Blocks[0].Succs[:1] }, "two successors"},
		"bad successor":              {func(f *Func, _ VarID) { f.Blocks[1].Succs = []int32{9} }, "out of range"},
		"argument out of range":      {func(f *Func, _ VarID) { f.Instrs[0].Args = []VarID{42} }, "argument 42 out of range"},
		"defines a parameter":        {func(f *Func, _ VarID) { f.Instrs[1].Dst = 0 }, "defines parameter"},
		"not contiguous": {func(f *Func, _ VarID) {
			f.Instrs = append(f.Instrs, Instr{Op: OpCall, Dst: NoVar, Call: &Call{Name: "x"}, Block: 0})
		}, "not contiguous"},
		"catch outside a handler": {func(f *Func, _ VarID) {
			f.Instrs[1] = Instr{Op: OpCatch, Dst: f.Instrs[1].Dst, Block: 1}
		}, "not a handler"},
		"call without callee": {func(f *Func, _ VarID) { f.Instrs[0].Call = nil }, "no callee"},
		"store shape":         {func(f *Func, _ VarID) { f.Instrs[1] = Instr{Op: OpStore, Dst: NoVar, Args: []VarID{0}, Block: 1} }, "want 2"},
		"closure without func": {func(f *Func, _ VarID) {
			f.Instrs[1] = Instr{Op: OpClosure, Dst: f.Instrs[1].Dst, Block: 1}
		}, "no function"},
		"too many captures":                {func(f *Func, _ VarID) { f.Captures = 5 }, "captures"},
		"return terminator without return": {func(f *Func, _ VarID) { f.Blocks[1].Term = TermReturn }, "without a final return"},
	}
	for name, c := range cases {
		f, x3 := diamond()
		c.mutate(f, x3)
		err := Verify(f)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q\n%s", name, err, c.want, Format(f))
		}
	}
}

func TestDominators(t *testing.T) {
	f, _ := diamond()
	idom := f.Dominators()
	if !slices.Equal(idom, []int32{-1, 0, 0, 0}) {
		t.Fatalf("idom = %v", idom)
	}
	if !Dominates(idom, 0, 3) || Dominates(idom, 1, 3) || !Dominates(idom, 2, 2) || Dominates(idom, 3, 9) {
		t.Error("Dominates")
	}
	preds := f.Preds()
	if !slices.Equal(preds[3], []int32{1, 2}) || len(preds[0]) != 0 {
		t.Errorf("preds = %v", preds)
	}
	// An unreachable block has no dominator.
	f.NewBlock()
	if idom := f.Dominators(); idom[4] != -1 {
		t.Errorf("unreachable: %v", idom)
	}
	if len((&Func{}).Dominators()) != 0 {
		t.Error("empty function")
	}
}

func TestFormat(t *testing.T) {
	f, _ := diamond()
	f.Instrs = append(f.Instrs[:1], append([]Instr{
		{Op: OpStore, Dst: NoVar, Args: []VarID{0, 0}, Field: "note", Block: 0},
		{Op: OpLoad, Dst: f.Temp(at), Args: []VarID{0}, Field: "note", Block: 0},
		{Op: OpCompute, Dst: f.Temp(at), Args: []VarID{0}, Operator: "!", Block: 0},
		{Op: OpNew, Dst: f.Temp(at), Call: &Call{Callee: "p.User", Target: "p.User.<init>"}, Block: 0},
		{Op: OpClosure, Dst: f.Temp(at), Func: "p.f$1", Block: 0},
	}, f.Instrs[1:]...)...)
	got := Format(f)
	for _, want := range []string{"func p.f(v0:p)", "b0:", `v1 = call check()`, "if v1 -> b1, b2", `v2:x = assign "a"`,
		"v5:x = phi b1: v2:x, b2: v4:x", "return v5:x", "v0:p.note = v0:p", "= v0:p.note", `compute "!"(v0:p)`,
		"new p.User [p.User.<init>]()", "closure p.f$1()", "jump b3"} {
		if !strings.Contains(got, want) {
			t.Errorf("Format lacks %q:\n%s", want, got)
		}
	}
}
