// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"testing"

	"github.com/GoNetTools/datawarden/internal/analysis"
	"github.com/GoNetTools/datawarden/internal/ir"
)

type fakeHasher map[string]string

func (h fakeHasher) Hash(rel string) string { return h[rel] }

func TestRoundTripAndInvalidation(t *testing.T) {
	mem := &Memory{}
	hashes := fakeHasher{"a.go": "h1", "b.go": "h2"}
	s := Open(mem, hashes, "v1", "rules1")
	if !s.Empty() {
		t.Fatal("new cache should be empty")
	}
	funcs := []*ir.Func{{ID: "p.A", File: "a.go"}, {ID: "p.B", File: "b.go"}}
	res := &analysis.Result{
		CallGraph: map[string][]string{"p.B": {"p.A"}},
		Summaries: map[string]*analysis.Summary{"p.A": {ParamReturn: map[int][]analysis.Transfer{0: {{Conf: 1}}}}},
	}
	s.Update(funcs, res, []string{"a.go", "b.go"}, true)
	s.SetSchema("a.go", []*ir.TypeDecl{{Name: "User"}}, []*ir.Class{{Name: "p.Sms", File: "a.go", Supers: []string{"p.Channel"}}})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2 := Open(mem, hashes, "v1", "rules1")
	if s2.Lookup("p.A") == nil || !s2.Has("p.B") {
		t.Fatal("summary not restored")
	}
	if got := s2.Callers([]string{"a.go"}, 2); len(got) != 1 || got[0] != "b.go" {
		t.Errorf("callers = %v", got)
	}
	if got := s2.CallersOf("p.A"); len(got) != 1 || got[0] != "p.B" || len(s2.CallersOf("p.B")) != 0 {
		t.Errorf("CallersOf = %v", got)
	}
	if len(s2.SchemaTypes(nil)) != 1 || len(s2.SchemaTypes(map[string]bool{"a.go": true})) != 0 {
		t.Error("schema types")
	}
	if c := s2.Classes(nil); len(c) != 1 || c[0].Name != "p.Sms" || len(s2.Classes(map[string]bool{"a.go": true})) != 0 {
		t.Errorf("classes = %+v", c)
	}

	// Editing the defining file invalidates its summary.
	hashes["a.go"] = "h1-edited"
	if s2.Lookup("p.A") != nil || len(s2.SchemaTypes(nil)) != 0 || len(s2.Classes(nil)) != 0 {
		t.Error("stale entries returned after the file changed")
	}

	// Another rule set or tool version starts from scratch.
	if !Open(mem, hashes, "v1", "rules2").Empty() || !Open(mem, hashes, "v2", "rules1").Empty() {
		t.Error("incompatible cache reused")
	}
}

func TestPartialUpdateKeepsUntouchedFiles(t *testing.T) {
	s := Open(nil, fakeHasher{}, "v", "r")
	s.Update([]*ir.Func{{ID: "a", File: "a.go"}, {ID: "b", File: "b.go"}}, &analysis.Result{}, nil, true)
	s.Update([]*ir.Func{{ID: "a2", File: "a.go"}}, &analysis.Result{}, []string{"a.go"}, false)
	if s.Has("a") || !s.Has("a2") || !s.Has("b") {
		t.Error("partial update should replace only re-lowered files")
	}
}
