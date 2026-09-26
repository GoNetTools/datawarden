// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"reflect"
	"testing"
)

func TestPosAndOps(t *testing.T) {
	if (Pos{}).IsValid() || !(Pos{File: "a.go", Line: 1}).IsValid() {
		t.Error("IsValid")
	}
	if got := (Pos{File: "a.go", Line: 3, Col: 7}).String(); got != "a.go:3:7" {
		t.Errorf("with column: %s", got)
	}
	if got := (Pos{File: "a.go", Line: 3}).String(); got != "a.go:3" {
		t.Errorf("without column: %s", got)
	}
	for op, want := range map[Op]string{OpAssign: "assign", OpLoad: "load", OpStore: "store", OpCall: "call", OpReturn: "return", OpPhi: "phi",
		OpCompute: "compute", OpNew: "new", OpThrow: "throw", OpCatch: "catch", OpClosure: "closure", OpYield: "yield", Op(99): "op?"} {
		if got := op.String(); got != want {
			t.Errorf("Op(%d) = %q, want %q", op, got, want)
		}
	}
}

func TestFuncBuilders(t *testing.T) {
	f := &Func{ID: "p.f"}
	p := f.AddParam("email", "string", Pos{File: "a.go", Line: 1})
	c := f.ConstVar("phone", Pos{File: "a.go", Line: 2})
	tmp := f.Temp(Pos{File: "a.go", Line: 3})
	n := f.Named("msg", "string", Pos{File: "a.go", Line: 4})
	if f.Params[0] != p || f.Vars[p].Param != 0 || !f.Vars[c].IsConst() || *f.Vars[c].Const != "phone" || f.Vars[tmp].Name != "" || f.Vars[n].Name != "msg" {
		t.Fatalf("vars: %+v", f.Vars)
	}
	f.Assign(n, Pos{File: "a.go", Line: 5}, p, NoVar, c)
	if in := f.Instrs[0]; in.Op != OpAssign || in.Dst != n || !reflect.DeepEqual(in.Args, []VarID{p, c}) {
		t.Errorf("assign drops NoVar arguments: %+v", in)
	}
}

func TestModuleMergeAndSort(t *testing.T) {
	m := &Module{Funcs: []*Func{{ID: "b"}}, Types: []*TypeDecl{{Name: "Z"}}, Classes: []*Class{{Name: "Y"}}}
	m.Merge(&Module{Funcs: []*Func{{ID: "a"}}, Types: []*TypeDecl{{Name: "A"}}, Classes: []*Class{{Name: "B"}}, Warnings: []string{"w"}})
	m.Merge(nil)
	m.SortStable()
	if m.Funcs[0].ID != "a" || m.Types[0].Name != "A" || m.Classes[0].Name != "B" || len(m.Warnings) != 1 {
		t.Errorf("module: %+v", m)
	}
	for _, tm := range []Term{TermJump, TermIf, TermReturn, TermThrow} {
		if tm.String() == "term?" {
			t.Errorf("Term(%d) has no name", tm)
		}
	}
	if Term(9).String() != "term?" || !Logical("!") || !Logical("==") || Logical("+") || Logical("") {
		t.Error("Term names and Logical")
	}
}
