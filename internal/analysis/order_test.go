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
