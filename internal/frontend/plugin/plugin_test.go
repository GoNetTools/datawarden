// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// greet is a well-formed function: func app.greet(email) { puts(email) }.
func greet() *ir.Func {
	at := ir.Pos{File: "app.rb", Line: 1}
	f := &ir.Func{ID: "app.greet", Name: "greet", File: "app.rb", Pos: at}
	email := f.AddParam("email", "", at)
	f.NewBlock()
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: ir.NoVar, Args: []ir.VarID{email}, Call: &ir.Call{Name: "puts", Callee: "Kernel.puts"}, Pos: at})
	f.Return(at)
	return f
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLowerRunsTheProgramFromTheRoot(t *testing.T) {
	var got struct {
		dir  string
		argv []string
		req  Request
	}
	exec := func(_ context.Context, dir string, argv []string, input []byte) ([]byte, error) {
		got.dir, got.argv = dir, argv
		if err := json.Unmarshal(input, &got.req); err != nil {
			t.Fatal(err)
		}
		return encode(t, Response{Version: ir.Version, Module: ir.Module{Funcs: []*ir.Func{greet()}}}), nil
	}
	fe := New("ruby", []string{"ruby", "tools/dw.rb"}, exec)(frontend.Options{Root: "/repo"})
	if fe.Lang() != "ruby" {
		t.Errorf("lang = %s", fe.Lang())
	}
	m, err := fe.Lower(context.Background(), []string{"app.rb"})
	if err != nil {
		t.Fatal(err)
	}
	if got.dir != "/repo" || strings.Join(got.argv, " ") != "ruby tools/dw.rb" {
		t.Errorf("ran %v in %s", got.argv, got.dir)
	}
	if got.req.Version != ir.Version || got.req.Lang != "ruby" || got.req.Root != "/repo" || strings.Join(got.req.Files, ",") != "app.rb" {
		t.Errorf("request = %+v", got.req)
	}
	if len(m.Funcs) != 1 || m.Funcs[0].ID != "app.greet" || m.Funcs[0].Lang != "ruby" || m.Lang != "ruby" {
		t.Errorf("module = %+v", m)
	}
}

func TestLowerReportsProgramFailure(t *testing.T) {
	exec := func(context.Context, string, []string, []byte) ([]byte, error) {
		return nil, errors.New("exit status 1: NoMethodError at dw.rb:3")
	}
	fe := New("ruby", []string{"ruby", "dw.rb"}, exec)(frontend.Options{Root: "/repo"})
	_, err := fe.Lower(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "frontend ruby (ruby): exit status 1: NoMethodError") {
		t.Errorf("err = %v", err)
	}
}

func TestDecodeRejectsBadOutput(t *testing.T) {
	bad := greet()
	bad.Instrs[0].Args = []ir.VarID{42} // an argument that is not a variable
	cases := map[string]struct {
		out  []byte
		want string
	}{
		"not json":      {[]byte("Traceback (most recent call last)"), "not a JSON module"},
		"other version": {encode(t, Response{Version: ir.Version + 1}), "IR version"},
		"invalid ir":    {encode(t, Response{Version: ir.Version, Module: ir.Module{Funcs: []*ir.Func{bad}}}), "invalid IR"},
		"null function": {[]byte(`{"version":3,"funcs":[null]}`), "null function"},
	}
	for name, c := range cases {
		_, err := Decode("ruby", c.out)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	m, err := Decode("ruby", []byte(`{"version":3}`))
	if err != nil || m.Funcs == nil || len(m.Funcs) != 0 {
		t.Errorf("empty module: %+v %v", m, err)
	}
}
