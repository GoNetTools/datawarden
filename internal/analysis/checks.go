// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// A check is a branch on a predicate about a value that changes what the
// value is known to be where the check passed:
//
//   - if (isMasked(v)) log(v): v was masked (a transform);
//   - if (!containsPii(v)) log(v): a detector found no personal data in v
//     (the "pii-checked" transform);
//   - if (isValidEmail(v)) log(v): v is an email address (a source).
//
// refineChecks gives the value a new SSA version at the start of the
// successor where the check passed (v' = v), used in every block that
// successor dominates, and the engine applies the check when it defines
// v' (checkedValue).
type check struct {
	xf   string // transform the check establishes, or ""
	dt   string // data type the check establishes, or ""
	conf float64
	desc string
	pos  ir.Pos
}

// transformChecks name predicates that a value was already made safe:
// isMasked, isRedacted, wasAnonymized, isEncrypted, isHashed.
var transformChecks = map[string]string{
	"masked": "masked", "redacted": "redacted", "anonymized": "anonymized", "anonymised": "anonymized",
	"encrypted": "encrypted", "hashed": "hashed", "tokenized": "tokenized", "tokenised": "tokenized",
	"pseudonymized": "tokenized", "pseudonymised": "tokenized", "sanitized": "redacted", "sanitised": "redacted",
}

// piiDetectors name predicates that a value contains personal data: the
// value is clean where they return false.
var piiDetectors = []string{"containspii", "haspii", "ispii", "lookslikepii", "detectpii", "containspersonaldata",
	"haspersonaldata", "containssensitivedata", "hassensitivedata", "issensitive", "containssensitive", "containsphi"}

// checkKind classifies a predicate by name. It returns the check and
// whether it holds when the predicate returns true.
func (a *analyzer) checkKind(name string, pos ir.Pos) (check, bool, bool) {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	for _, p := range []string{"is", "was", "hasbeen", "has"} {
		if rest, ok := strings.CutPrefix(n, p); ok {
			if xf, ok := transformChecks[rest]; ok {
				return check{xf: xf, desc: name + "()", pos: pos}, true, true
			}
		}
	}
	for _, d := range piiDetectors {
		if n == d {
			return check{xf: "pii-checked", desc: name + "()", pos: pos}, false, true
		}
	}
	// isValidEmail, validPhone, validateEmail, isEmail: the value is of
	// that data type where the check passed.
	rest := n
	for _, p := range []string{"is", "check", "validate", "valid"} {
		rest = strings.TrimPrefix(rest, p)
	}
	rest = strings.TrimSuffix(rest, "valid")
	if rest == n || rest == "" {
		return check{}, false, false
	}
	if m, ok := a.opts.Names.Ident(rest); ok {
		return check{dt: m.DataType, conf: m.Conf * 0.9, desc: fmt.Sprintf("value validated by %s()", name), pos: pos}, true, true
	}
	return check{}, false, false
}

// checkOf reads the condition v of a branch as checks on values: the
// variable checked, what holds where the condition is true, and what
// holds where it is false.
func (a *analyzer) checkOf(fn *ir.Func, defs []int, v ir.VarID, depth int) (onTrue, onFalse []checked) {
	if v < 0 || int(v) >= len(defs) || defs[v] < 0 || depth > 4 {
		return nil, nil
	}
	in := &fn.Instrs[defs[v]]
	switch in.Op {
	case ir.OpCompute:
		switch {
		case in.Operator == "!" && len(in.Args) == 1:
			t, f := a.checkOf(fn, defs, in.Args[0], depth+1)
			return f, t
		case in.Operator == "&&" || in.Operator == "and":
			// Both hold where the conjunction is true.
			for _, arg := range in.Args {
				t, _ := a.checkOf(fn, defs, arg, depth+1)
				onTrue = append(onTrue, t...)
			}
			return onTrue, nil
		}
	case ir.OpAssign:
		if len(in.Args) == 1 {
			return a.checkOf(fn, defs, in.Args[0], depth+1)
		}
	case ir.OpCall:
		c := in.Call
		if c == nil {
			return nil, nil
		}
		// The value checked: the first argument, or the receiver of an
		// extension or method without arguments (email.isValidEmail()).
		target := ir.NoVar
		switch {
		case c.HasRecv && len(in.Args) > 1:
			target = in.Args[1]
		case !c.HasRecv && !c.Indirect && len(in.Args) > 0:
			target = in.Args[0]
		case c.HasRecv && len(in.Args) == 1:
			target = in.Args[0]
		}
		if target < 0 || fn.Vars[target].IsConst() {
			return nil, nil
		}
		ck, whenTrue, ok := a.checkKind(c.Name, in.Pos)
		if !ok {
			return nil, nil
		}
		if whenTrue {
			return []checked{{target, ck}}, nil
		}
		return nil, []checked{{target, ck}}
	}
	return nil, nil
}

type checked struct {
	v  ir.VarID
	ck check
}

// refineChecks returns fn with a new version of each checked value where
// its check passed, and the check each new version stands for. fn itself
// is not changed; without checks it is returned as is.
func (a *analyzer) refineChecks(fn *ir.Func) (*ir.Func, map[ir.VarID]check) {
	if len(fn.Blocks) == 0 {
		return fn, nil
	}
	defs := definitions(fn)
	type site struct {
		block int32
		c     checked
	}
	var sites []site
	var preds [][]int32
	for b := range fn.Blocks {
		blk := &fn.Blocks[b]
		if blk.Term != ir.TermIf || len(blk.Succs) != 2 {
			continue
		}
		onTrue, onFalse := a.checkOf(fn, defs, blk.Cond, 0)
		if len(onTrue)+len(onFalse) == 0 {
			continue
		}
		if preds == nil {
			preds = fn.Preds()
		}
		for i, cs := range [][]checked{onTrue, onFalse} {
			s := blk.Succs[i]
			if int(s) >= len(preds) || len(preds[s]) != 1 {
				continue // also reached some other way
			}
			for _, c := range cs {
				sites = append(sites, site{s, c})
			}
		}
	}
	if len(sites) == 0 {
		return fn, nil
	}
	out := *fn
	out.Vars = slices.Clone(fn.Vars)
	out.Blocks = slices.Clone(fn.Blocks)
	out.Instrs = make([]ir.Instr, len(fn.Instrs))
	for i, in := range fn.Instrs {
		in.Args = slices.Clone(in.Args)
		in.From = slices.Clone(in.From)
		out.Instrs[i] = in
	}
	idom := out.Dominators()
	checks := map[ir.VarID]check{}
	inserts := map[int32][]ir.Instr{}
	for _, s := range sites {
		orig := out.Vars[s.c.v]
		nv := out.NewVar(ir.Var{Name: orig.Name, Type: orig.Type, Param: -1, Pos: s.c.ck.pos})
		checks[nv] = s.c.ck
		// Uses in the blocks the successor dominates read the new version.
		for i := range out.Instrs {
			in := &out.Instrs[i]
			for j, arg := range in.Args {
				if arg != s.c.v {
					continue
				}
				at := in.Block
				if in.Op == ir.OpPhi && j < len(in.From) {
					at = in.From[j]
				}
				if at >= 0 && ir.Dominates(idom, s.block, at) {
					in.Args[j] = nv
				}
			}
		}
		for b := range out.Blocks {
			if out.Blocks[b].Term == ir.TermIf && out.Blocks[b].Cond == s.c.v && ir.Dominates(idom, s.block, int32(b)) {
				out.Blocks[b].Cond = nv
			}
		}
		inserts[s.block] = append(inserts[s.block], ir.Instr{Op: ir.OpAssign, Dst: nv, Args: []ir.VarID{s.c.v}, Pos: s.c.ck.pos, Block: s.block})
	}
	// Each new version is defined first in its block, after the phis.
	instrs := make([]ir.Instr, 0, len(out.Instrs)+len(sites))
	placed := map[int32]bool{}
	for _, in := range out.Instrs {
		if ins, ok := inserts[in.Block]; ok && !placed[in.Block] && in.Op != ir.OpPhi {
			instrs = append(instrs, ins...)
			placed[in.Block] = true
		}
		instrs = append(instrs, in)
	}
	for b, ins := range inserts {
		if !placed[b] {
			// An empty block, or one with only phis.
			last := -1
			for i := range instrs {
				if instrs[i].Block == b {
					last = i
				}
			}
			if last < 0 {
				instrs = append(instrs, ins...)
			} else {
				instrs = slices.Insert(instrs, last+1, ins...)
			}
		}
	}
	out.Instrs = instrs
	return &out, checks
}

// checkedValue applies a check where its new version of the value is
// defined: the value's facts with the transform, or a fact of the data
// type the check establishes.
func (a *analyzer) checkedValue(st *state, in *ir.Instr, ck check) bool {
	changed := false
	for _, arg := range in.Args {
		for _, f := range st.all(arg) {
			d := derive(f, in.Pos, 1)
			if ck.xf != "" {
				d.xf = mergeXf(d.xf, ck.xf)
			}
			d.at = f.at
			changed = st.add(in.Dst, d) || changed
		}
		for field, m := range st.stores[arg] {
			for _, f := range m {
				d := derive(f, in.Pos, 1)
				if ck.xf != "" {
					d.xf = mergeXf(d.xf, ck.xf)
				}
				d.at = f.at
				changed = st.addStore(in.Dst, field, d) || changed
			}
		}
	}
	if ck.dt != "" {
		changed = st.add(in.Dst, &fact{dt: ck.dt, param: -1, src: ck.pos, desc: ck.desc, path: []ir.Pos{ck.pos}, conf: ck.conf}) || changed
	}
	return changed
}
