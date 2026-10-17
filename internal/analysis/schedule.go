// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"runtime"
	"sync"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// runComponents analyzes the strongly connected components of the call
// graph, callees first, several at a time: a component starts once every
// component it calls is done, so the summaries a function applies are
// complete when it reads them. sccs are in the order tarjan gives
// (callees before callers); workers is the number of goroutines (0: one
// per CPU; 1: in order, on the calling goroutine).
func (a *analyzer) runComponents(ctx context.Context, sccs [][]*ir.Func, cg map[string][]string, workers int) error {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers == 1 || len(sccs) < 2 {
		for _, scc := range sccs {
			if err := ctx.Err(); err != nil {
				return err
			}
			a.analyzeComponent(scc, cg)
		}
		return nil
	}

	// The condensation of the call graph: which components each one
	// waits for, and which ones wait for it.
	comp := make(map[string]int, len(a.funcs))
	for i, scc := range sccs {
		for _, f := range scc {
			comp[f.ID] = i
		}
	}
	waiting := make([]int, len(sccs))
	dependents := make([][]int, len(sccs))
	for i, scc := range sccs {
		seen := map[int]bool{}
		for _, f := range scc {
			for _, callee := range cg[f.ID] {
				if j, ok := comp[callee]; ok && j != i && !seen[j] {
					seen[j] = true
					waiting[i]++
					dependents[j] = append(dependents[j], i)
				}
			}
		}
	}

	ready := make(chan int, len(sccs))
	for i := range sccs {
		if waiting[i] == 0 {
			ready <- i
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu   sync.Mutex
		done int
		wg   sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case i, ok := <-ready:
					if !ok {
						return
					}
					a.analyzeComponent(sccs[i], cg)
					mu.Lock()
					done++
					for _, d := range dependents[i] {
						if waiting[d]--; waiting[d] == 0 {
							ready <- d // never blocks: each component is queued once
						}
					}
					if done == len(sccs) {
						close(ready)
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return context.Cause(ctx)
}

// analyzeComponent analyzes one component: a single pass for a function
// nothing it calls depends on, iterations to a fixed point for recursion.
func (a *analyzer) analyzeComponent(scc []*ir.Func, cg map[string][]string) {
	recursive := len(scc) > 1
	if len(scc) == 1 {
		for _, c := range cg[scc[0].ID] {
			if c == scc[0].ID {
				recursive = true
			}
		}
	}
	if !recursive {
		a.setSummary(scc[0].ID, a.analyzeFunc(scc[0]))
		return
	}
	digests := map[string]string{}
	for iter := 0; iter < 8; iter++ {
		changed := false
		for _, fn := range scc {
			s := a.analyzeFunc(fn)
			if d := s.Digest(); d != digests[fn.ID] {
				digests[fn.ID] = d
				a.setSummary(fn.ID, s)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

// setSummary records a function's summary for its callers.
func (a *analyzer) setSummary(id string, s *Summary) {
	a.smu.Lock()
	a.summaries[id] = s
	a.smu.Unlock()
}
