// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"slices"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// Points-to: the abstract objects each variable of a function may refer
// to, computed flow-insensitively over its SSA form (Andersen-style, one
// function at a time). An object is an allocation site (new), a parameter
// (whatever the caller passed), the result of any other call, or the
// object read from a field of another object (field-sensitive, so two
// reads of user.addr are the same object). Copies, merges and phis make a
// variable refer to what their arguments refer to, and a builder call's
// result (sb.append(x)) to its receiver.
//
// The engine uses it for aliasing: a mutation through one variable (a
// field store, list.add, a callee writing into an argument) is a mutation
// of every variable that may refer to the same object.

// objectID identifies an abstract object within one function.
type objectID int32

// pointsTo is the result for one function.
type pointsTo struct {
	// aliases lists, per variable, the other variables that may refer
	// to one of its objects.
	aliases map[ir.VarID][]ir.VarID
	pts     [][]objectID
	// single marks the objects that stand for one concrete object during
	// a call: a parameter, or an allocation or call result outside any
	// loop. A store into such an object through a variable that refers
	// to it alone overwrites the field (a strong update).
	single map[objectID]bool
}

// maxAliases bounds the aliases of one variable.
const maxAliases = 32

// A checked version of a value (checks.go) is an object of its own, so
// that what the check says about it is not undone by the facts of the
// unchecked value.
func newPointsTo(fn *ir.Func, fluent map[ir.VarID]ir.VarID, checked map[ir.VarID]check, ord *order) *pointsTo {
	n := len(fn.Vars)
	pts := make([][]objectID, n)
	next := objectID(0)
	fresh := func() objectID { next++; return next - 1 }
	single := map[objectID]bool{}
	add := func(v ir.VarID, os ...objectID) bool {
		if v < 0 || int(v) >= n || fn.Vars[v].IsConst() {
			return false
		}
		grew := false
		for _, o := range os {
			if !slices.Contains(pts[v], o) && len(pts[v]) < maxAliases {
				pts[v] = append(pts[v], o)
				grew = true
			}
		}
		return grew
	}
	// Parameters, and each allocation or call result: an object of its own.
	for _, p := range fn.Params {
		o := fresh()
		single[o] = true
		add(p, o)
	}
	site := map[int]objectID{}
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		switch in.Op {
		case ir.OpNew, ir.OpCatch, ir.OpClosure:
			site[i] = fresh()
		case ir.OpCall:
			if _, ok := fluent[in.Dst]; !ok {
				site[i] = fresh()
			}
		}
		if o, ok := site[i]; ok && in.Op != ir.OpCatch && ord != nil && !ord.inCycle(in.Block) {
			single[o] = true
		}
	}
	// Field reads: one object per (object, field).
	fields := map[objectID]map[string]objectID{}
	fieldObj := func(o objectID, field string) objectID {
		m := fields[o]
		if m == nil {
			m = map[string]objectID{}
			fields[o] = m
		}
		if f, ok := m[field]; ok {
			return f
		}
		f := fresh()
		m[field] = f
		return f
	}
	for round := 0; round < 16; round++ {
		grew := false
		for i := range fn.Instrs {
			in := &fn.Instrs[i]
			switch in.Op {
			case ir.OpNew, ir.OpCatch, ir.OpClosure:
				grew = add(in.Dst, site[i]) || grew
			case ir.OpCall:
				if r, ok := fluent[in.Dst]; ok {
					grew = add(in.Dst, pts[r]...) || grew
				} else {
					grew = add(in.Dst, site[i]) || grew
				}
			case ir.OpAssign, ir.OpPhi:
				if _, ok := checked[in.Dst]; ok {
					if _, ok := site[i]; !ok {
						site[i] = fresh()
					}
					grew = add(in.Dst, site[i]) || grew
					continue
				}
				for _, a := range in.Args {
					if a >= 0 && int(a) < n {
						grew = add(in.Dst, pts[a]...) || grew
					}
				}
			case ir.OpLoad:
				if len(in.Args) == 1 && in.Args[0] >= 0 {
					for _, o := range pts[in.Args[0]] {
						grew = add(in.Dst, fieldObj(o, in.Field)) || grew
					}
				}
			}
		}
		if !grew {
			break
		}
	}
	// A variable nothing defines (a Go value the frontend does not
	// lower) is an object of its own.
	for v := range pts {
		if len(pts[v]) == 0 && !fn.Vars[v].IsConst() {
			pts[v] = []objectID{fresh()}
		}
	}
	byObj := map[objectID][]ir.VarID{}
	for v, os := range pts {
		for _, o := range os {
			byObj[o] = append(byObj[o], ir.VarID(v))
		}
	}
	res := &pointsTo{aliases: map[ir.VarID][]ir.VarID{}, pts: pts, single: single}
	for v, os := range pts {
		var al []ir.VarID
		for _, o := range os {
			for _, w := range byObj[o] {
				if w != ir.VarID(v) && !slices.Contains(al, w) && len(al) < maxAliases {
					al = append(al, w)
				}
			}
		}
		if len(al) > 0 {
			slices.Sort(al)
			res.aliases[ir.VarID(v)] = al
		}
	}
	return res
}

// mutated returns v and the variables that may refer to the same object,
// which a mutation of v also changes.
func (p *pointsTo) mutated(v ir.VarID) []ir.VarID {
	if p == nil {
		return []ir.VarID{v}
	}
	return append([]ir.VarID{v}, p.aliases[v]...)
}

// only returns the object v refers to when it refers to exactly one that
// stands for one concrete object (see single).
func (p *pointsTo) only(v ir.VarID) (objectID, bool) {
	if p == nil || v < 0 || int(v) >= len(p.pts) || len(p.pts[v]) != 1 || !p.single[p.pts[v][0]] {
		return 0, false
	}
	return p.pts[v][0], true
}
