// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import "github.com/GoNetTools/datawarden/internal/ir"

// order answers ordering questions over a function's control-flow graph:
// can one instruction run before another on some path? It is the control
// flow layer of the IR's code property graph; the def-use edges of the SSA
// variables are the data flow layer.
type order struct {
	fn *ir.Func
	// reach[b] is the set of blocks reachable from b by one or more edges.
	reach [][]uint64
}

// newOrder returns nil for a function without control-flow information:
// every instruction is then treated as possibly running before every other.
func newOrder(fn *ir.Func) *order {
	n := len(fn.Blocks)
	if n == 0 {
		return nil
	}
	words := (n + 63) / 64
	o := &order{fn: fn, reach: make([][]uint64, n)}
	for b := range fn.Blocks {
		seen := make([]uint64, words)
		work := append([]int32(nil), fn.Blocks[b].Succs...)
		for len(work) > 0 {
			s := work[len(work)-1]
			work = work[:len(work)-1]
			if s < 0 || int(s) >= n || seen[s/64]&(1<<(s%64)) != 0 {
				continue
			}
			seen[s/64] |= 1 << (s % 64)
			work = append(work, fn.Blocks[s].Succs...)
		}
		o.reach[b] = seen
	}
	return o
}

// before reports whether instruction q can run before instruction p, that
// is, whether some path leads from q to p. Floating blocks (lambda bodies)
// are unordered, so anything in them runs before and after everything.
func (o *order) before(q, p int) bool {
	if o == nil || q < 0 || p < 0 || q >= len(o.fn.Instrs) || p >= len(o.fn.Instrs) {
		return true
	}
	bq, bp := o.fn.Instrs[q].Block, o.fn.Instrs[p].Block
	if int(bq) >= len(o.reach) || int(bp) >= len(o.reach) || bq < 0 || bp < 0 {
		return true
	}
	if o.fn.Blocks[bq].Floating || o.fn.Blocks[bp].Floating {
		return true
	}
	if bq == bp && q < p {
		return true
	}
	return o.reach[bq][bp/64]&(1<<(bp%64)) != 0
}
