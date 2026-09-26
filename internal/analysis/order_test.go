// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// entry(0) -> loop header(1) <-> body(2); header -> exit(3); body -exc-> handler(4).
func TestOrder(t *testing.T) {
	f := &ir.Func{}
	emit := func() int {
		f.Emit(ir.Instr{Op: ir.OpAssign, Dst: ir.NoVar})
		return len(f.Instrs) - 1
	}
	f.NewBlock()
	e0, e1 := emit(), emit()
	f.NewBlock(0)
	h := emit()
	f.NewBlock(1)
	body := emit()
	f.Edge(2, 1)
	f.NewBlock(1)
	exit := emit()
	f.NewBlock()
	f.ExcEdge(2, 4)
	handler := emit()

	o := newOrder(f)
	cases := []struct {
		q, p int
		want bool
	}{
		{e0, e1, true}, {e1, e0, false}, // straight line
		{e0, exit, true}, {exit, e0, false},
		{body, h, true}, {body, body, true}, // around the loop
		{exit, body, false},
		{body, handler, true}, {e0, handler, true}, // exceptional edges
		{handler, e0, false}, {exit, handler, false},
	}
	for _, c := range cases {
		if got := o.before(c.q, c.p); got != c.want {
			t.Errorf("before(%d, %d) = %v, want %v", c.q, c.p, got, c.want)
		}
	}
	if newOrder(&ir.Func{}) != nil || !(*order)(nil).before(3, 1) {
		t.Error("a function without blocks must treat everything as ordered both ways")
	}
}

// entry(0) -> a(1) | b(2) -> join(3) -> loop(4) <-> 4, 4 -> exit(5).
func TestReachesAvoiding(t *testing.T) {
	f := &ir.Func{}
	emit := func() int {
		f.Emit(ir.Instr{Op: ir.OpAssign, Dst: ir.NoVar})
		return len(f.Instrs) - 1
	}
	f.NewBlock()
	s0, k0, u0 := emit(), emit(), emit()
	f.NewBlock(0)
	ka := emit()
	f.NewBlock(0)
	emit()
	f.NewBlock(1, 2)
	u3 := emit()
	f.NewBlock(3)
	l1, kl, l2 := emit(), emit(), emit()
	f.Edge(4, 4)
	f.NewBlock(4)
	f.NewBlock()

	o := newOrder(f)
	kills := func(ks ...int) func(int) bool {
		return func(i int) bool {
			for _, k := range ks {
				if k == i {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name string
		q, p int
		kill []int
		want bool
	}{
		{"straight line, killed", s0, u0, []int{k0}, false},
		{"killed on one branch only", s0, u3, []int{ka}, true},
		{"killed before the branch", s0, u3, []int{k0}, false},
		{"loop body: killed before the next iteration's read", l1, l1, []int{kl}, false},
		{"loop body: stored after the kill, read next iteration", l2, l1, []int{kl}, true},
		{"loop body: read after the kill", l1, l2, []int{kl}, false},
		{"no kill", l1, l1, nil, true},
		{"not reachable at all", u3, s0, nil, false},
	}
	for _, c := range cases {
		if got := o.reachesAvoiding(c.q, c.p, kills(c.kill...)); got != c.want {
			t.Errorf("%s: reachesAvoiding(%d, %d) = %v", c.name, c.q, c.p, got)
		}
	}
	if !o.reachesEnd(s0, 5, kills(ka)) || o.reachesEnd(s0, 5, kills(k0)) || !(*order)(nil).reachesEnd(0, 0, nil) {
		t.Error("reachesEnd")
	}
	if !o.inCycle(4) || o.inCycle(3) {
		t.Error("inCycle")
	}
}
