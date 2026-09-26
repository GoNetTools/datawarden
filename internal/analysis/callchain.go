// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"maps"
	"slices"
	"sort"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// A flow's path lists positions from the source to the sink, across the
// functions whose summaries carried the data. callChains turns it into
// the chain of those functions: each position is placed in the innermost
// function whose lines contain it, consecutive positions in the same
// function are one step, and the call graph says whether the next step is
// a call (one deeper) or a return (one shallower).

type funcSpan struct {
	id         string
	start, end int
}

// spanIndex finds the function enclosing a position.
type spanIndex map[string][]funcSpan

func newSpanIndex(funcs map[string]*ir.Func) spanIndex {
	idx := spanIndex{}
	for _, f := range funcs {
		if f.File == "" {
			continue
		}
		start, end := f.Pos.Line, f.Pos.Line
		note := func(p ir.Pos) {
			if p.File != f.File || p.Line <= 0 {
				return
			}
			if start <= 0 || p.Line < start {
				start = p.Line
			}
			end = max(end, p.Line)
		}
		for i := range f.Instrs {
			note(f.Instrs[i].Pos)
		}
		for i := range f.Vars {
			note(f.Vars[i].Pos)
		}
		if start > 0 {
			idx[f.File] = append(idx[f.File], funcSpan{f.ID, start, end})
		}
	}
	for _, spans := range idx {
		sort.Slice(spans, func(i, j int) bool {
			return spans[i].start < spans[j].start || spans[i].start == spans[j].start && spans[i].id < spans[j].id
		})
	}
	return idx
}

// at returns the innermost function containing p, or "".
func (idx spanIndex) at(p ir.Pos) string {
	best, bestLen := "", -1
	for _, s := range idx[p.File] {
		if s.start > p.Line {
			break
		}
		if p.Line <= s.end && (bestLen < 0 || s.end-s.start < bestLen) {
			best, bestLen = s.id, s.end-s.start
		}
	}
	return best
}

// maxCallers bounds Flow.CalledBy.
const maxCallers = 5

// callChains sets the Calls and CalledBy of every flow.
func (a *analyzer) callChains(flows []*finding.Flow, cg map[string][]string) {
	idx := newSpanIndex(a.funcs)
	calls := func(from, to string) bool { return slices.Contains(cg[from], to) }
	callers := map[string][]string{}
	for _, from := range slices.Sorted(maps.Keys(cg)) {
		for _, to := range cg[from] {
			callers[to] = append(callers[to], from)
		}
	}
	for _, fl := range flows {
		var ids []string
		var steps []finding.CallStep
		for _, p := range fl.Path {
			id := idx.at(p)
			name := id
			if f, ok := a.funcs[id]; ok {
				name = a.reportFunc(f)
			} else if name == "" {
				name = "?" // code not analysed in this run
			}
			if n := len(steps); n > 0 && steps[n-1].Function == name {
				continue
			}
			depth := 0
			if n := len(steps); n > 0 {
				prev := ids[n-1]
				depth = steps[n-1].Depth
				switch {
				case calls(prev, id) || a.inside(id, prev):
					depth++
				case calls(id, prev) || a.inside(prev, id):
					depth--
				}
			}
			ids = append(ids, id)
			steps = append(steps, finding.CallStep{Function: name, Pos: p, Depth: depth})
		}
		// Who calls the function where the data enters (for a closure,
		// its enclosing function).
		if len(ids) > 0 {
			entry := ids[0]
			for depth := 0; depth < 8; depth++ {
				f, ok := a.funcs[entry]
				if !ok || f.Parent == "" {
					break
				}
				entry = f.Parent
			}
			for _, c := range callers[entry] {
				name := c
				if f, ok := a.funcs[c]; ok {
					name = a.reportFunc(f)
				}
				if name != entry && !slices.Contains(fl.CalledBy, name) && len(fl.CalledBy) < maxCallers {
					fl.CalledBy = append(fl.CalledBy, name)
				}
			}
		}
		if len(steps) < 2 {
			continue // a flow within one function has no chain to show
		}
		low := steps[0].Depth
		for _, s := range steps {
			low = min(low, s.Depth)
		}
		for i := range steps {
			steps[i].Depth -= low
		}
		fl.Calls = steps
	}
}

// inside reports whether function id is a closure defined in parent.
func (a *analyzer) inside(id, parent string) bool {
	f, ok := a.funcs[id]
	return ok && f.Parent == parent
}
