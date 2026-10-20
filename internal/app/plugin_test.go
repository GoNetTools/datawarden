// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/frontend/plugin"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// TestExternalFrontendHelper is the external frontend TestExternalFrontend
// runs (this test binary, re-executed). It lowers each file to one
// function, `<file>.greet(email)`, that passes its parameter to
// Kernel.puts; a frontend written in any language does the same with
// the real source.
func TestExternalFrontendHelper(t *testing.T) {
	if os.Getenv("DATAWARDEN_HELPER") != "1" {
		return
	}
	var req plugin.Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "bad request:", err)
		os.Exit(1)
	}
	resp := plugin.Response{Version: req.Version, Module: ir.Module{Lang: req.Lang}}
	for _, file := range req.Files {
		at := ir.Pos{File: file, Line: 1}
		f := &ir.Func{ID: strings.TrimSuffix(file, ".rb") + ".greet", Name: "greet", Lang: req.Lang, File: file, Pos: at}
		email := f.AddParam("email", "", at)
		f.NewBlock()
		f.Emit(ir.Instr{Op: ir.OpCall, Dst: ir.NoVar, Args: []ir.VarID{email}, Call: &ir.Call{Name: "puts", Callee: "Kernel.puts"}, Pos: at})
		f.Return(at)
		resp.Funcs = append(resp.Funcs, f)
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// TestExternalFrontend scans a repository whose .datawarden.yaml names an
// external frontend for Ruby and a sink rule for it, and finds the leak
// the frontend reports.
func TestExternalFrontend(t *testing.T) {
	t.Setenv("DATAWARDEN_HELPER", "1")
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".datawarden.yaml", fmt.Sprintf("frontends:\n  - lang: ruby\n    extensions: [.rb]\n    command: [%s, \"-test.run=^TestExternalFrontendHelper$\"]\n",
		strconv.Quote(os.Args[0])))
	write(".datawarden/rules/ruby.yaml", "- id: log.ruby.puts\n  lang: ruby\n  call: [Kernel.puts]\n  dest: {kind: log}\n")
	write("lib/app.rb", "def greet(email)\n  puts email\nend\n")
	write("spec/app_spec.rb", "describe 'greet'\n")

	code, r := scanJSON(t, dir, "--no-baseline")
	if len(r.Warnings) > 0 {
		t.Errorf("warnings: %v", r.Warnings)
	}
	f := findFlow(r, want{dataType: "email", rule: "log.ruby.puts", fn: "lib/app.greet", violation: true})
	if f == nil || code != 1 {
		t.Fatalf("flow from the external frontend not reported (exit %d): %+v", code, r.Flows)
	}
	if f.Sink.File != "lib/app.rb" || f.Lang != "ruby" {
		t.Errorf("flow: %+v", f)
	}

	// datawarden ir runs the frontend too, and verifies its output.
	_, out, errs := run(t, "ir", "--root", dir, "--verify", filepath.Join(dir, "lib"))
	if !strings.Contains(out, "func lib/app.greet(v0:email)") || strings.Contains(out, "spec/app_spec") {
		t.Errorf("ir output:\n%s%s", out, errs)
	}

	// A frontend that fails is a warning, not a crash.
	t.Setenv("DATAWARDEN_HELPER", "0")
	_, r = scanJSON(t, dir, "--no-baseline")
	if len(r.Flows) != 0 || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "frontend ruby") {
		t.Errorf("failing frontend: flows %d, warnings %v", len(r.Flows), r.Warnings)
	}
}
