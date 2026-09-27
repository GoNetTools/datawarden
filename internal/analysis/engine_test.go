// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"testing"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/rules"
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

// noFieldSources matches no field or parameter sources.
type noFieldSources struct{}

func (noFieldSources) MatchField(lang, owner, field, recv string) []rules.Hit { return nil }
func (noFieldSources) MatchParam(lang string, annotations []string) []rules.Hit {
	return nil
}

// fakeRules reports every call named "leak" as a third-party sink, so the
// engine can be tested without the YAML rule set.
type fakeRules struct{ noFieldSources }

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

// Summaries keep one entry per transform set, preferring higher confidence.
func TestSummaryMerging(t *testing.T) {
	var s *Summary
	if !s.Empty() || !(&Summary{}).Empty() {
		t.Error("empty summaries")
	}
	s = &Summary{}
	s.addParamParam(0, 1, Transfer{Conf: 0.5})
	s.addParamParam(0, 1, Transfer{Conf: 0.9})
	s.addParamParam(0, 1, Transfer{Conf: 0.4})
	s.addParamParam(0, 1, Transfer{Conf: 0.7, Xf: []string{"masked"}})
	if got := s.ParamParam[0][1]; len(got) != 2 || got[0].Conf != 0.9 {
		t.Errorf("param→param: %+v", got)
	}
	s.addReturnFact(RealFact{DataType: "email", Conf: 0.6})
	s.addReturnFact(RealFact{DataType: "email", Conf: 0.8})
	s.addParamOut(1, RealFact{DataType: "phone", Conf: 0.7})
	if len(s.ReturnFacts) != 1 || s.ReturnFacts[0].Conf != 0.8 || len(s.ParamOut[1]) != 1 || s.Empty() {
		t.Errorf("facts: %+v %+v", s.ReturnFacts, s.ParamOut)
	}
	for i := 0; i < maxPerSlot+5; i++ {
		s.addReturnFact(RealFact{DataType: fmt.Sprintf("t%d", i), Conf: 0.5})
		s.addParamParam(2, 0, Transfer{Conf: 0.5, Xf: []string{fmt.Sprint(i)}})
	}
	if len(s.ReturnFacts) != maxPerSlot || len(s.ParamParam[2][0]) != maxPerSlot {
		t.Errorf("slots are bounded: %d %d", len(s.ReturnFacts), len(s.ParamParam[2][0]))
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.partner.example/v1/leads": "api.partner.example",
		"http://sms.vendor.example:8080/send":  "sms.vendor.example",
		"api.partner.example/v1":               "api.partner.example",
		"/relative/path":                       "",
		"https://[::1":                         "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// httpRules reports calls named "post" as a network sink whose first
// argument is the URL.
type httpRules struct{ noFieldSources }

func (httpRules) Match(lang, kind string, c *ir.Call) []rules.Hit {
	if kind != rules.KindSink || c.Name != "post" {
		return nil
	}
	host := 0
	return []rules.Hit{{Rule: &rules.Rule{ID: "net.fake.post", Arg: rules.ArgSpec{Indexes: []int{1}}, HostArg: &host, Dest: rules.Dest{Kind: rules.DestNetwork}, Category: "network"}, Conf: 1}}
}

// bothRules combines httpRules and fakeRules.
type bothRules struct{ noFieldSources }

func (bothRules) Match(lang, kind string, c *ir.Call) []rules.Hit {
	return append(httpRules{}.Match(lang, kind, c), fakeRules{}.Match(lang, kind, c)...)
}

// A network call's result is the remote's response: sending a password
// in a login request does not make the reply a password.
func TestNetworkResponseIsNotTheRequest(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	fn := &ir.Func{ID: "p.login", Name: "login", Lang: "go", File: "a.go"}
	password := fn.AddParam("password", "string", pos(1))
	url := fn.ConstVar("https://api.acme.example/session", pos(2))
	resp := fn.Temp(pos(2))
	fn.Emit(ir.Instr{Op: ir.OpCall, Dst: resp, Args: []ir.VarID{url, password}, Call: &ir.Call{Name: "post"}, Pos: pos(2)})
	fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(3)), Args: []ir.VarID{resp}, Call: &ir.Call{Name: "leak"}, Pos: pos(3)})
	res, err := Engine{Names: names}.Analyze(context.Background(), []*ir.Func{fn}, Input{Rules: bothRules{}, Schema: detect.BuildSchema(names, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 1 || res.Flows[0].SinkRule != "net.fake.post" || res.Flows[0].DataType != "password" {
		t.Errorf("want only the request flow: %+v", res.Flows)
	}
}

// A constant URL argument names the destination host, and hosts under the
// repository's first-party domains are first party.
func TestDestinationHostAndFirstParty(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	fn := &ir.Func{ID: "p.f", Name: "f", Lang: "go", File: "a.go"}
	email := fn.AddParam("email", "string", pos(1))
	for i, u := range []string{"https://crm.partner.example/leads", "https://api.acme.example/users"} {
		url := fn.ConstVar(u, pos(2+i))
		fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(2 + i)), Args: []ir.VarID{url, email}, Call: &ir.Call{Name: "post"}, Pos: pos(2 + i)})
	}
	res, err := Engine{Names: names}.Analyze(context.Background(), []*ir.Func{fn}, Input{Rules: httpRules{}, Schema: detect.BuildSchema(names, nil), FirstPartyDomains: []string{".acme.example"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Flows {
		got[f.Dest.Host] = f.Dest.Kind
	}
	if got["crm.partner.example"] != rules.DestNetwork || got["api.acme.example"] != rules.DestFirstParty {
		t.Errorf("destinations: %v", got)
	}
}

// In a PR scan unchanged callees are not in the program; their cached
// summaries are looked up, so a leak inside them is still reported.
func TestCachedSummaryOfUnchangedCallee(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	fn := &ir.Func{ID: "p.caller", Name: "caller", Lang: "go", File: "a.go"}
	email := fn.AddParam("email", "string", pos(1))
	fn.Emit(ir.Instr{Op: ir.OpCall, Dst: fn.Temp(pos(2)), Args: []ir.VarID{email}, Call: &ir.Call{Name: "send", Target: "p.send"}, Pos: pos(2)})
	cached := &Summary{ParamSink: map[int][]SinkHit{0: {{Rule: "fake.leak", Dest: finding.Destination{Kind: "third_party"}, Sink: ir.Pos{File: "b.go", Line: 9}, Func: "p.send", Conf: 1}}}}
	res, err := Engine{Names: names}.Analyze(context.Background(), []*ir.Func{fn}, Input{Rules: fakeRules{}, Schema: detect.BuildSchema(names, nil),
		Lookup: func(id string) *Summary {
			if id == "p.send" {
				return cached
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 1 || res.Flows[0].Sink.File != "b.go" || res.Flows[0].DataType != "email" {
		t.Errorf("flows: %+v", res.Flows)
	}
}

// email = digest(email); email = request.get("email"): a redefinition
// computed from the same name is not a new source, a fresh read is.
func TestRedefinitions(t *testing.T) {
	f := &ir.Func{ID: "p.f", Name: "f", Lang: "python", File: "a.py"}
	old := f.AddParam("email", "", pos(1))
	t1 := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: t1, Args: []ir.VarID{old}, Call: &ir.Call{Name: "digest"}, Pos: pos(2)})
	hashed := f.Named("email", "", pos(2))
	f.Assign(hashed, pos(2), t1)
	req := f.Named("request", "", pos(3))
	key := f.ConstVar("email", pos(3))
	fresh := f.Named("email", "", pos(3))
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: fresh, Args: []ir.VarID{req, key}, Call: &ir.Call{Name: "get", HasRecv: true}, Pos: pos(3)})
	loop := f.Named("email", "", pos(4))
	f.Assign(loop, pos(4), loop, fresh) // a loop header merging itself

	got := redefinitions(f)
	want := map[ir.VarID]bool{old: false, hashed: true, fresh: false, loop: true, t1: false, req: false}
	for v, w := range want {
		if got[v] != w {
			t.Errorf("var %d (%s): redefinition = %v, want %v", v, f.Vars[v].Name, got[v], w)
		}
	}
}
