// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const module = "github.com/GoNetTools/pii-scanner"

// vocabulary packages hold the types every component exchanges (the IR,
// findings, the language table). Calling their functions and methods is
// not coupling to another component's implementation.
var vocabulary = map[string]bool{
	module + "/internal/ir":      true,
	module + "/internal/finding": true,
	module + "/internal/lang":    true,
}

// dataMethods are methods on plain data values owned by another package.
// Keep this list short: anything with behaviour worth replacing belongs
// behind an interface.
var dataMethods = map[string]string{
	"rules.ArgSpec.Selects": "part of the rule definitions a RuleMatcher returns",
}

// TestComponentsTalkThroughInterfaces enforces the design rule: a
// component uses another component only through an interface it declares
// (or a function value it is given). Only the composition root
// (internal/app) and the commands in cmd/ pick concrete implementations.
func TestComponentsTalkThroughInterfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the whole module")
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:  filepath.Join("..", ".."),
	}
	pkgs, err := packages.Load(cfg, module+"/internal/...")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	for _, p := range pkgs {
		for _, e := range p.Errors {
			t.Fatalf("%s: %v", p.PkgPath, e)
		}
		if p.PkgPath == module+"/internal/app" {
			continue
		}
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if v := concreteCall(p, call); v != "" {
					pos := p.Fset.Position(call.Pos())
					rel, err := filepath.Rel(root, pos.Filename)
					if err != nil || strings.HasPrefix(rel, "..") {
						rel = pos.Filename
					}
					violations = append(violations, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), pos.Line, v))
				}
				return true
			})
		}
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
	if len(violations) > 0 {
		t.Log("declare an interface where it is used, implement it in the other package, and wire the implementation in internal/app")
	}
}

// concreteCall describes a call from package p into another internal
// package's concrete function or method, or returns "".
func concreteCall(p *packages.Package, call *ast.CallExpr) string {
	var obj types.Object
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[fun]
	case *ast.SelectorExpr:
		if sel, ok := p.TypesInfo.Selections[fun]; ok {
			if types.IsInterface(sel.Recv()) {
				return "" // through an interface
			}
			obj = sel.Obj()
		} else {
			obj = p.TypesInfo.Uses[fun.Sel]
		}
	case *ast.IndexExpr: // generic instantiation
		if id, ok := fun.X.(*ast.SelectorExpr); ok {
			obj = p.TypesInfo.Uses[id.Sel]
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "" // builtins, conversions, calls of function values
	}
	callee := fn.Pkg().Path()
	if callee == p.PkgPath || !strings.HasPrefix(callee, module+"/internal/") || vocabulary[callee] {
		return ""
	}
	sig := fn.Type().(*types.Signature)
	name := strings.TrimPrefix(callee, module+"/internal/") + "." + fn.Name()
	if r := sig.Recv(); r != nil {
		if types.IsInterface(r.Type()) {
			return ""
		}
		name = strings.TrimPrefix(types.TypeString(r.Type(), func(q *types.Package) string { return strings.TrimPrefix(q.Path(), module+"/internal/") }), "*") + "." + fn.Name()
		if _, ok := dataMethods[name]; ok {
			return ""
		}
		return "calls method " + name + " on a concrete type from another component"
	}
	return "calls " + name + " directly"
}
