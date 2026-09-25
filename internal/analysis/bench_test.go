// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

// chain builds n functions: f0(email) passes its argument through a few
// temporaries to a sink and on to f1, and so on, so every summary depends
// on the next one and f0's email reaches all n sinks. Each function has its
// own file: summaries key sink hits by position.
func chain(n int) []*ir.Func {
	funcs := make([]*ir.Func, n)
	for i := range funcs {
		id := fmt.Sprintf("p.f%d", i)
		file := fmt.Sprintf("f%d.go", i)
		pos := func(line int) ir.Pos { return ir.Pos{File: file, Line: line} }
		fn := &ir.Func{ID: id, Name: fmt.Sprintf("f%d", i), Lang: "go", File: file}
		name := "v"
		if i == 0 {
			name = "email"
		}
		x := fn.AddParam(name, "string", pos(1))
		prev := x
		for j := 0; j < 4; j++ {
			t := fn.Temp(pos(2 + j))
			fn.Assign(t, pos(2+j), prev)
			prev = t
		}
		fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(10)), Args: []ir.VarID{prev}, Call: &ir.Call{Name: "leak"}, Pos: pos(10)})
		if i+1 < n {
			next := fmt.Sprintf("p.f%d", i+1)
			fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(11)), Args: []ir.VarID{prev}, Call: &ir.Call{Name: fmt.Sprintf("f%d", i+1), Target: next}, Pos: pos(11)})
		}
		funcs[i] = fn
	}
	return funcs
}

// BenchmarkAnalyze shows how the taint engine scales with program size.
func BenchmarkAnalyze(b *testing.B) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	schema := detect.BuildSchema(names, nil)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("funcs=%d", n), func(b *testing.B) {
			funcs := chain(n)
			in := Input{Rules: fakeRules{}, Schema: schema}
			b.ReportAllocs()
			b.ResetTimer()
			flows := 0
			for i := 0; i < b.N; i++ {
				res, err := Engine{Names: names}.Analyze(context.Background(), funcs, in)
				if err != nil {
					b.Fatal(err)
				}
				flows = len(res.Flows)
			}
			// Summaries keep a bounded number of sink hits per parameter, so
			// long chains report fewer than n flows.
			if flows == 0 {
				b.Fatal("no flows")
			}
			b.ReportMetric(float64(flows), "flows")
		})
	}
}
