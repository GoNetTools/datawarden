// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

func pos(line int) ir.Pos { return ir.Pos{File: "a.kt", Line: line} }

// helper(x) = mask(x) ; recurse(x) calls itself and logs x ; caller passes phone.
func TestSummariesAndRecursion(t *testing.T) {
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	logCall := func(f *ir.Func, arg ir.VarID, line int) {
		tag := f.ConstVar("TAG", pos(line))
		f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(line)), Args: []ir.VarID{tag, arg},
			Call: &ir.Call{Callee: "android.util.Log.d", Name: "d"}, Pos: pos(line)})
	}

	// fun recurse(x: String) { Log.d(TAG, x); recurse(x) }
	rec := &ir.Func{ID: "p.recurse", Name: "recurse", Lang: "kotlin", File: "a.kt"}
	x := rec.AddParam("x", "String", pos(1))
	logCall(rec, x, 2)
	rec.Emit(ir.Instr{Op: ir.OpCall, Dst: rec.Temp(pos(3)), Args: []ir.VarID{x}, Call: &ir.Call{Callee: "p.recurse", Name: "recurse", Target: "p.recurse"}, Pos: pos(3)})

	// fun maskPhone(p: String) = p.take(3) + "***"
	mask := &ir.Func{ID: "p.maskPhone", Name: "maskPhone", Lang: "kotlin", File: "a.kt"}
	p := mask.AddParam("p", "String", pos(10))
	r := mask.Temp(pos(11))
	mask.Assign(r, pos(11), p)
	mask.Emit(ir.Instr{Op: ir.OpReturn, Dst: ir.NoVar, Args: []ir.VarID{r}, Pos: pos(11)})

	// fun fill(out: Builder, v: String) { out.value = v }
	fill := &ir.Func{ID: "p.fill", Name: "fill", Lang: "kotlin", File: "a.kt"}
	out := fill.AddParam("out", "", pos(20))
	v := fill.AddParam("v", "", pos(20))
	fill.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{out, v}, Field: "value", Pos: pos(21)})

	// fun caller(phone: String) { recurse(phone); Log.d(TAG, maskPhone(phone)); val b = Builder(); fill(b, phone); Log.d(TAG, b) }
	caller := &ir.Func{ID: "p.caller", Name: "caller", Lang: "kotlin", File: "a.kt"}
	phone := caller.AddParam("phone", "String", pos(30))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: caller.Temp(pos(31)), Args: []ir.VarID{phone}, Call: &ir.Call{Name: "recurse", Target: "p.recurse"}, Pos: pos(31)})
	m := caller.Temp(pos(32))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: m, Args: []ir.VarID{phone}, Call: &ir.Call{Name: "maskPhone", Target: "p.maskPhone"}, Pos: pos(32)})
	logCall(caller, m, 32)
	b := caller.Named("b", "", pos(33))
	caller.Emit(ir.Instr{Op: ir.OpCall, Dst: caller.Temp(pos(34)), Args: []ir.VarID{b, phone}, Call: &ir.Call{Name: "fill", Target: "p.fill"}, Pos: pos(34)})
	logCall(caller, b, 35)

	names := detect.NewClassifier(detect.DefaultTaxonomy())
	eng := Engine{Names: names}
	res, err := eng.Analyze(context.Background(), []*ir.Func{caller, rec, mask, fill}, Input{Rules: rs, Schema: detect.BuildSchema(names, nil)})
	if err != nil {
		t.Fatal(err)
	}
	var viaRecursion, masked, viaOutParam bool
	for _, f := range res.Flows {
		if f.DataType != "phone" {
			continue
		}
		switch {
		case f.Function == "p.recurse" && f.Sink.Line == 2:
			viaRecursion = true
		case f.Function == "p.caller" && f.Sink.Line == 32:
			masked = len(f.Transforms) == 1 && f.Transforms[0] == "masked"
		case f.Function == "p.caller" && f.Sink.Line == 35:
			viaOutParam = true
		}
	}
	if !viaRecursion || !masked || !viaOutParam {
		t.Errorf("recursion=%v masked=%v outParam=%v flows=%+v", viaRecursion, masked, viaOutParam, res.Flows)
	}
	if s := res.Summaries["p.fill"]; s == nil || len(s.ParamParam[0][1]) == 0 {
		t.Errorf("fill summary should record v -> out: %+v", s)
	}
	if got := res.CallGraph["p.caller"]; len(got) != 3 {
		t.Errorf("call graph: %v", got)
	}
}

// fakeRules reports every call named "leak" as a third-party sink, so the
// engine can be tested without the YAML rule set.
type fakeRules struct{}

func (fakeRules) Match(lang, kind string, c *ir.Call) []rules.Hit {
	if kind != rules.KindSink || c.Name != "leak" {
		return nil
	}
	return []rules.Hit{{Rule: &rules.Rule{ID: "fake.leak", Arg: rules.ArgSpec{All: true}, Dest: rules.Dest{Kind: "third_party", Host: "x.test"}}, Conf: 1}}
}

func TestEngineWithFakeRules(t *testing.T) {
	fn := &ir.Func{ID: "p.f", Name: "f", Lang: "go", File: "a.go"}
	email := fn.AddParam("email", "string", pos(1))
	fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(2)), Args: []ir.VarID{email}, Call: &ir.Call{Name: "leak"}, Pos: pos(2)})
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	res, err := Engine{Names: names}.Analyze(context.Background(), []*ir.Func{fn}, Input{Rules: fakeRules{}, Schema: detect.BuildSchema(names, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 1 || res.Flows[0].SinkRule != "fake.leak" || res.Flows[0].DataType != "email" || res.Flows[0].Dest.Host != "x.test" {
		t.Errorf("flows: %+v", res.Flows)
	}
	if _, err := Analyze(context.Background(), nil, Options{}); err == nil {
		t.Error("missing dependencies accepted")
	}
}

// A map or object literal key names its value even when some type in the
// repository has a field of the same name (regression: the schema's field
// hint used to switch the key heuristic off for untyped stores).
func TestMapKeyLabelsValueDespiteSchemaField(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	schema := detect.BuildSchema(names, []*ir.TypeDecl{{Name: "p.User", Kind: "struct", Fields: []ir.Field{{Name: "Email", Type: "string"}}}})
	fn := &ir.Func{ID: "p.key", Name: "key", Lang: "go", File: "a.go"}
	value := fn.AddParam("value", "string", pos(1))
	m := fn.Named("payload", "map[string]string", pos(2))
	fn.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{m, value}, Field: "email", Pos: pos(2)})
	fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(3)), Args: []ir.VarID{m}, Call: &ir.Call{Name: "leak"}, Pos: pos(3)})
	res, err := Engine{Names: names}.Analyze(context.Background(), []*ir.Func{fn}, Input{Rules: fakeRules{}, Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 1 || res.Flows[0].DataType != "email" {
		t.Errorf("flows: %+v", res.Flows)
	}
}
