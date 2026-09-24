// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import "github.com/GoNetTools/pii-scanner/internal/ir"

// tarjan returns the strongly connected components of the call graph in
// reverse topological order: callees before callers.
func tarjan(funcs []*ir.Func, cg map[string][]string, byID map[string]*ir.Func) [][]*ir.Func {
	index := 0
	idx := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]*ir.Func

	type frame struct {
		id   string
		next int
	}
	for _, root := range funcs {
		if _, seen := idx[root.ID]; seen {
			continue
		}
		// Iterative DFS to survive deep call chains.
		work := []frame{{id: root.ID}}
		idx[root.ID], low[root.ID] = index, index
		index++
		stack = append(stack, root.ID)
		onStack[root.ID] = true
		for len(work) > 0 {
			top := &work[len(work)-1]
			succ := cg[top.id]
			if top.next < len(succ) {
				w := succ[top.next]
				top.next++
				if _, ok := byID[w]; !ok {
					continue
				}
				if _, seen := idx[w]; !seen {
					idx[w], low[w] = index, index
					index++
					stack = append(stack, w)
					onStack[w] = true
					work = append(work, frame{id: w})
				} else if onStack[w] && idx[w] < low[top.id] {
					low[top.id] = idx[w]
				}
				continue
			}
			v := top.id
			work = work[:len(work)-1]
			if len(work) > 0 {
				p := work[len(work)-1].id
				if low[v] < low[p] {
					low[p] = low[v]
				}
			}
			if low[v] == idx[v] {
				var comp []*ir.Func
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp = append(comp, byID[w])
					if w == v {
						break
					}
				}
				out = append(out, comp)
			}
		}
	}
	return out
}
