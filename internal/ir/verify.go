// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"errors"
	"fmt"
	"slices"
)

// Verify checks that a function is well formed IR as docs/IR.md specifies:
// operands in range, instructions shaped for their op, blocks contiguous
// and properly terminated, phis matching their block's predecessors, and
// SSA form: every variable but a Cell has at most one definition, and
// each definition dominates its uses.
func Verify(f *Func) error {
	v := verifier{f: f}
	v.run()
	return errors.Join(v.errs...)
}

// Verify checks every function of the module.
func (m *Module) Verify() error {
	var errs []error
	for _, f := range m.Funcs {
		if err := Verify(f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

const maxVerifyErrors = 20

type verifier struct {
	f    *Func
	errs []error
}

func (v *verifier) errorf(format string, args ...any) {
	if len(v.errs) < maxVerifyErrors {
		v.errs = append(v.errs, fmt.Errorf("%s: "+format, append([]any{v.f.ID}, args...)...))
	}
}

func (v *verifier) variable(v2 VarID) bool { return v2 >= 0 && int(v2) < len(v.f.Vars) }

func (v *verifier) run() {
	f := v.f
	if f.Captures < 0 || f.Captures > len(f.Params) {
		v.errorf("%d captures but %d parameters", f.Captures, len(f.Params))
	}
	for i, p := range f.Params {
		if !v.variable(p) || f.Vars[p].Param != i {
			v.errorf("parameter %d is not variable %d's parameter", i, p)
		}
	}
	v.instrs()
	if len(f.Blocks) > 0 {
		v.blocks()
	}
	v.ssa()
}

// instrs checks each instruction on its own.
func (v *verifier) instrs() {
	f := v.f
	for i := range f.Instrs {
		in := &f.Instrs[i]
		for _, a := range in.Args {
			if !v.variable(a) {
				v.errorf("instr %d (%s): argument %d out of range", i, in.Op, a)
			}
		}
		switch {
		case in.Op.defines() && in.Op != OpCall && !v.variable(in.Dst):
			v.errorf("instr %d (%s): no destination", i, in.Op)
		case !in.Op.defines() && in.Dst != NoVar:
			v.errorf("instr %d (%s): unexpected destination %d", i, in.Op, in.Dst)
		case in.Op == OpCall && in.Dst != NoVar && !v.variable(in.Dst):
			v.errorf("instr %d (call): destination %d out of range", i, in.Dst)
		}
		want := -1 // exact argument count, when fixed
		switch in.Op {
		case OpLoad, OpThrow, OpYield:
			want = 1
		case OpStore:
			want = 2
		case OpCatch:
			want = 0
		case OpAssign, OpPhi, OpCompute:
			if len(in.Args) == 0 {
				v.errorf("instr %d (%s): no arguments", i, in.Op)
			}
		case OpCall, OpNew:
			if in.Call == nil {
				v.errorf("instr %d (%s): no callee", i, in.Op)
			} else if (in.Call.HasRecv || in.Call.Indirect) && len(in.Args) == 0 {
				v.errorf("instr %d (%s): receiver or function value missing", i, in.Op)
			} else if in.Call.ArgNames != nil && len(in.Call.ArgNames) != len(in.Args) {
				v.errorf("instr %d (%s): %d argument names for %d arguments", i, in.Op, len(in.Call.ArgNames), len(in.Args))
			}
		case OpClosure:
			if in.Func == "" {
				v.errorf("instr %d (closure): no function", i)
			}
		case OpReturn:
		default:
			v.errorf("instr %d: unknown op %d", i, in.Op)
		}
		if want >= 0 && len(in.Args) != want {
			v.errorf("instr %d (%s): %d arguments, want %d", i, in.Op, len(in.Args), want)
		}
		if in.Op == OpPhi && len(in.From) != len(in.Args) {
			v.errorf("instr %d (phi): %d predecessors for %d arguments", i, len(in.From), len(in.Args))
		}
		if in.Op != OpPhi && len(in.From) > 0 {
			v.errorf("instr %d (%s): predecessor list on a non-phi", i, in.Op)
		}
	}
}

// blocks checks the control-flow graph and where instructions sit in it.
func (v *verifier) blocks() {
	f := v.f
	n := int32(len(f.Blocks))
	preds := f.Preds()
	excPreds := make([]bool, n)
	for b, blk := range f.Blocks {
		for _, s := range append(append([]int32(nil), blk.Succs...), blk.Exc...) {
			if s < 0 || s >= n {
				v.errorf("block %d: successor %d out of range", b, s)
			}
		}
		for _, s := range blk.Exc {
			if s >= 0 && s < n {
				excPreds[s] = true
			}
		}
		switch blk.Term {
		case TermIf:
			if len(blk.Succs) != 2 || !v.variable(blk.Cond) {
				v.errorf("block %d: branch needs a condition and two successors", b)
			}
		case TermReturn, TermThrow:
			if len(blk.Succs) > 0 {
				v.errorf("block %d: %s block has successors", b, blk.Term)
			}
		case TermJump:
		default:
			v.errorf("block %d: unknown terminator %d", b, blk.Term)
		}
	}
	// Instructions of a block are contiguous; phis first, then a catch;
	// a return or throw last.
	first := make([]int, n)
	last := make([]int, n)
	for b := range first {
		first[b], last[b] = -1, -1
	}
	prev := int32(-1)
	for i := range f.Instrs {
		b := f.Instrs[i].Block
		if b < 0 || b >= n {
			v.errorf("instr %d: block %d out of range", i, b)
			prev = -1
			continue
		}
		if b != prev && first[b] >= 0 {
			v.errorf("instr %d: block %d is not contiguous", i, b)
		}
		if first[b] < 0 {
			first[b] = i
		}
		last[b] = i
		prev = b
	}
	for i := range f.Instrs {
		in := &f.Instrs[i]
		b := in.Block
		if b < 0 || b >= n {
			continue
		}
		atStart := true // only phis before i in its block
		for j := first[b]; j < i; j++ {
			if f.Instrs[j].Op != OpPhi {
				atStart = false
				break
			}
		}
		switch in.Op {
		case OpPhi:
			if !atStart {
				v.errorf("instr %d (phi): not at the start of block %d", i, b)
			}
			for _, p := range in.From {
				if !slices.Contains(preds[b], p) {
					v.errorf("instr %d (phi): block %d is not a predecessor of block %d", i, p, b)
				}
			}
		case OpCatch:
			if !atStart || !excPreds[b] {
				v.errorf("instr %d (catch): block %d is not a handler entered by an exceptional edge", i, b)
			}
		case OpReturn, OpThrow:
			want := TermReturn
			if in.Op == OpThrow {
				want = TermThrow
			}
			if last[b] != i || f.Blocks[b].Term != want {
				v.errorf("instr %d (%s): does not end block %d", i, in.Op, b)
			}
		}
	}
	for b, blk := range f.Blocks {
		if blk.Term == TermReturn || blk.Term == TermThrow {
			want := OpReturn
			if blk.Term == TermThrow {
				want = OpThrow
			}
			if last[b] < 0 || f.Instrs[last[b]].Op != want {
				v.errorf("block %d: %s terminator without a final %s", b, blk.Term, want)
			}
		}
	}
}

// ssa checks single definitions and that definitions dominate uses.
func (v *verifier) ssa() {
	f := v.f
	def := make([]int, len(f.Vars)) // instruction defining each variable, or -1
	for i := range def {
		def[i] = -1
	}
	for i := range f.Instrs {
		d := f.Instrs[i].Dst
		if !f.Instrs[i].Op.defines() || !v.variable(d) || f.Vars[d].Cell {
			continue
		}
		switch {
		case f.Vars[d].Param >= 0:
			v.errorf("instr %d: defines parameter %d, which is not a cell", i, d)
		case f.Vars[d].IsConst():
			v.errorf("instr %d: defines constant %d", i, d)
		case def[d] >= 0:
			v.errorf("instr %d: variable %d (%s) is defined twice (also by instr %d) but is not a cell", i, d, f.Vars[d].Name, def[d])
		default:
			def[d] = i
		}
	}
	if len(f.Blocks) == 0 {
		return
	}
	idom := f.Dominators()
	reachable := func(b int32) bool { return b == 0 || (b > 0 && int(b) < len(idom) && idom[b] >= 0) }
	// dominated reports whether the definition of x is available at the
	// end of block b (at == -1) or before instruction at of block b.
	dominated := func(x VarID, b int32, at int) bool {
		if !v.variable(x) || def[x] < 0 {
			return true
		}
		d := &f.Instrs[def[x]]
		if d.Block == b {
			return at < 0 || def[x] < at
		}
		return Dominates(idom, d.Block, b)
	}
	for i := range f.Instrs {
		in := &f.Instrs[i]
		if !reachable(in.Block) {
			continue
		}
		for k, a := range in.Args {
			ok := true
			if in.Op == OpPhi {
				if k < len(in.From) && reachable(in.From[k]) {
					ok = dominated(a, in.From[k], -1)
				}
			} else {
				ok = dominated(a, in.Block, i)
			}
			if !ok {
				v.errorf("instr %d (%s): use of variable %d (%s) is not dominated by its definition (instr %d)", i, in.Op, a, f.Vars[a].Name, def[a])
			}
		}
	}
	for b, blk := range f.Blocks {
		if blk.Term == TermIf && reachable(int32(b)) && !dominated(blk.Cond, int32(b), -1) {
			v.errorf("block %d: condition %d is not dominated by its definition", b, blk.Cond)
		}
	}
}
