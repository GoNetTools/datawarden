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
	// instrs[b] are the indices of block b's instructions, in order.
	instrs [][]int
}

// newOrder returns nil for a function without control-flow information:
// every instruction is then treated as possibly running before every other.
func newOrder(fn *ir.Func) *order {
	n := len(fn.Blocks)
	if n == 0 {
		return nil
	}
	words := (n + 63) / 64
	o := &order{fn: fn, reach: make([][]uint64, n), instrs: make([][]int, n)}
	for i := range fn.Instrs {
		if b := fn.Instrs[i].Block; b >= 0 && int(b) < n {
			o.instrs[b] = append(o.instrs[b], i)
		}
	}
	for b := range fn.Blocks {
		seen := make([]uint64, words)
		work := append(append([]int32(nil), fn.Blocks[b].Succs...), fn.Blocks[b].Exc...)
		for len(work) > 0 {
			s := work[len(work)-1]
			work = work[:len(work)-1]
			if s < 0 || int(s) >= n || seen[s/64]&(1<<(s%64)) != 0 {
				continue
			}
			seen[s/64] |= 1 << (s % 64)
			work = append(work, fn.Blocks[s].Succs...)
			work = append(work, fn.Blocks[s].Exc...)
		}
		o.reach[b] = seen
	}
	return o
}

// before reports whether instruction q can run before instruction p, that
// is, whether some path leads from q to p, over normal and exceptional
// edges.
func (o *order) before(q, p int) bool {
	if o == nil || q < 0 || p < 0 || q >= len(o.fn.Instrs) || p >= len(o.fn.Instrs) {
		return true
	}
	bq, bp := o.fn.Instrs[q].Block, o.fn.Instrs[p].Block
	if int(bq) >= len(o.reach) || int(bp) >= len(o.reach) || bq < 0 || bp < 0 {
		return true
	}
	if bq == bp && q < p {
		return true
	}
	return o.reach[bq][bp/64]&(1<<(bp%64)) != 0
}

// inCycle reports whether block b can run more than once in a call: it is
// on a cycle of the control-flow graph.
func (o *order) inCycle(b int32) bool {
	if o == nil || b < 0 || int(b) >= len(o.reach) {
		return true
	}
	return o.reach[b][b/64]&(1<<(b%64)) != 0
}

// reachesAvoiding reports whether some path leads from instruction q to
// instruction p without running an instruction kill reports: the
// reaching-definitions question for a mutation at q that the kills
// overwrite. With no kill on any path it is before(q, p).
func (o *order) reachesAvoiding(q, p int, kill func(int) bool) bool {
	if !o.before(q, p) {
		return false
	}
	if o == nil || q < 0 || p < 0 || q >= len(o.fn.Instrs) || p >= len(o.fn.Instrs) {
		return true
	}
	return o.reachesPoint(q, o.fn.Instrs[p].Block, p, kill)
}

// reachesEnd reports whether some path leads from instruction q to the
// end of block b without running a kill.
func (o *order) reachesEnd(q int, b int32, kill func(int) bool) bool {
	if o == nil || q < 0 || q >= len(o.fn.Instrs) {
		return true
	}
	return o.reachesPoint(q, b, int(^uint(0)>>1), kill)
}

// reachesPoint reports whether some path leads from instruction q to
// block bp just before instruction index p (or its end) without a kill.
func (o *order) reachesPoint(q int, bp int32, p int, kill func(int) bool) bool {
	bq := o.fn.Instrs[q].Block
	if bq < 0 || bp < 0 || int(bq) >= len(o.instrs) || int(bp) >= len(o.instrs) {
		return true
	}
	// killedIn reports a kill among block b's instructions in (from, to).
	killedIn := func(b int32, from, to int) bool {
		for _, i := range o.instrs[b] {
			if i > from && i < to && kill(i) {
				return true
			}
		}
		return false
	}
	const end = int(^uint(0) >> 1)
	if bq == bp && q < p {
		return !killedIn(bq, q, p)
	}
	// Out of q's block, then block by block into p's.
	if killedIn(bq, q, end) {
		return false
	}
	seen := make([]bool, len(o.instrs))
	work := append(append([]int32(nil), o.fn.Blocks[bq].Succs...), o.fn.Blocks[bq].Exc...)
	for len(work) > 0 {
		b := work[len(work)-1]
		work = work[:len(work)-1]
		if b < 0 || int(b) >= len(seen) || seen[b] {
			continue
		}
		seen[b] = true
		if b == bp {
			if !killedIn(b, -1, p) {
				return true
			}
			continue
		}
		if killedIn(b, -1, end) {
			continue
		}
		work = append(work, o.fn.Blocks[b].Succs...)
		work = append(work, o.fn.Blocks[b].Exc...)
	}
	return false
}
