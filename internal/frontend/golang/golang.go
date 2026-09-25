// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Package golang lowers Go code to IR using go/packages and the
// golang.org/x/tools SSA form. SSA gives fully resolved callees, precise
// types (struct tags included) and, with GlobalDebug, source names for
// values.
package golang

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/lang"
)

// PackageLoader loads Go packages; packages.Load in production.
type PackageLoader func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error)

// Frontend is the Go frontend.
type Frontend struct {
	opts frontend.Options
	load PackageLoader
}

// New returns a Go frontend that loads packages with load (packages.Load
// when nil).
func New(o frontend.Options, load PackageLoader) *Frontend {
	if load == nil {
		load = packages.Load
	}
	return &Frontend{opts: o, load: load}
}

// Register adds the Go frontend to a registry.
func Register(r *frontend.Registry, load PackageLoader) {
	r.Register(lang.Go, func(o frontend.Options) frontend.Frontend { return New(o, load) })
}

// Lang implements frontend.Frontend.
func (f *Frontend) Lang() string { return lang.Go }

// Lower implements frontend.Frontend. Files are grouped by their Go module
// and loaded one module at a time.
func (f *Frontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	out := &ir.Module{Lang: lang.Go}
	groups := map[string][]string{}
	for _, rel := range files {
		mod, ok := findModRoot(f.opts.FS, rel)
		if !ok {
			out.Warnings = append(out.Warnings, fmt.Sprintf("go: %s is not inside a Go module (no go.mod); skipped", rel))
			continue
		}
		groups[mod] = append(groups[mod], rel)
	}
	mods := make([]string, 0, len(groups))
	for m := range groups {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	for _, m := range mods {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		mm, err := f.lowerModule(ctx, m, groups[m])
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("go: module %s: %v", m, err))
			continue
		}
		out.Merge(mm)
	}
	return out, nil
}

// findModRoot returns the slash path (relative to the repository root) of
// the directory holding the nearest go.mod above rel.
func findModRoot(fsys fs.FS, rel string) (string, bool) {
	dir := path.Dir(rel)
	for {
		if _, err := fs.Stat(fsys, path.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

func modulePath(fsys fs.FS, modDir string) string {
	b, err := fs.ReadFile(fsys, path.Join(modDir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "module")), `"`)
		}
	}
	return ""
}

func (f *Frontend) lowerModule(ctx context.Context, modRel string, rels []string) (*ir.Module, error) {
	absRoot, _ := filepath.Abs(f.opts.Root)
	modDir := filepath.Join(absRoot, filepath.FromSlash(modRel))
	targets := map[string]bool{}
	dirs := map[string]bool{}
	for _, rel := range rels {
		abs := filepath.Join(absRoot, filepath.FromSlash(rel))
		targets[abs] = true
		d, _ := filepath.Rel(modDir, filepath.Dir(abs))
		dirs["./"+filepath.ToSlash(d)] = true
	}
	var patterns []string
	for d := range dirs {
		patterns = append(patterns, strings.TrimSuffix(strings.Replace(d, "./.", ".", 1), "/"))
	}
	sort.Strings(patterns)

	cfg := &packages.Config{
		Context: ctx,
		Dir:     modDir,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Tests: false,
	}
	if len(f.opts.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags=" + strings.Join(f.opts.BuildTags, ",")}
	}
	if f.opts.Logf != nil {
		f.opts.Logf("go: loading %v in %s", patterns, modDir)
	}
	pkgs, err := f.load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	mod := &ir.Module{Lang: lang.Go}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			mod.Warnings = append(mod.Warnings, "go: "+e.Error())
		}
	})
	if len(mod.Warnings) > 20 {
		n := len(mod.Warnings)
		mod.Warnings = append(mod.Warnings[:20], fmt.Sprintf("go: ... %d more package errors", n-20))
	}

	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.GlobalDebug)
	prog.Build()

	modPath := modulePath(f.opts.FS, modRel)
	initial := map[*types.Package]bool{}
	for i, sp := range ssaPkgs {
		if sp == nil {
			mod.Warnings = append(mod.Warnings, fmt.Sprintf("go: %s has type errors; skipped", pkgs[i].PkgPath))
			continue
		}
		initial[sp.Pkg] = true
	}

	l := &lowerer{
		prog: prog, root: absRoot, modPath: modPath, fset: prog.Fset,
		seenTypes: map[string]*types.Named{}, emittedTypes: map[string]bool{},
	}
	var fns []*ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Pkg == nil || !initial[fn.Pkg.Pkg] || fn.Synthetic != "" || len(fn.Blocks) == 0 {
			continue
		}
		if fn.Origin() != nil { // generic instantiation; the origin is lowered instead
			continue
		}
		file := prog.Fset.Position(fn.Pos()).Filename
		if !targets[file] {
			continue
		}
		fns = append(fns, fn)
	}
	sort.Slice(fns, func(i, j int) bool { return funcID(fns[i]) < funcID(fns[j]) })
	for _, fn := range fns {
		mod.Funcs = append(mod.Funcs, l.lowerFunc(fn))
	}
	// Struct declarations of the loaded packages and of every named type
	// the lowered code touched (dependencies included; their struct tags
	// come from export data).
	for _, sp := range ssaPkgs {
		if sp == nil {
			continue
		}
		scope := sp.Pkg.Scope()
		for _, name := range scope.Names() {
			if tn, ok := scope.Lookup(name).(*types.TypeName); ok {
				if n, ok := tn.Type().(*types.Named); ok {
					l.noteType(n)
				}
			}
		}
	}
	keys := make([]string, 0, len(l.seenTypes))
	for k := range l.seenTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if td := l.typeDecl(l.seenTypes[k]); td != nil {
			mod.Types = append(mod.Types, td)
		}
	}
	return mod, nil
}

type lowerer struct {
	prog         *ssa.Program
	fset         *token.FileSet
	root         string
	modPath      string
	fn           *ir.Func
	vars         map[ssa.Value]ir.VarID
	names        map[ssa.Value]string
	lastPos      ir.Pos
	seenTypes    map[string]*types.Named
	emittedTypes map[string]bool
}

func (l *lowerer) pos(p token.Pos) ir.Pos {
	if !p.IsValid() {
		return ir.Pos{}
	}
	pp := l.fset.Position(p)
	rel, err := filepath.Rel(l.root, pp.Filename)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ir.Pos{}
	}
	return ir.Pos{File: filepath.ToSlash(rel), Line: pp.Line, Col: pp.Column}
}

func (l *lowerer) at(p token.Pos) ir.Pos {
	if q := l.pos(p); q.IsValid() {
		l.lastPos = q
		return q
	}
	return l.lastPos
}

// funcID is the canonical, refactor-stable name of a function:
// "importpath.Func", "importpath.Type.Method", "importpath.Func$1".
func funcID(fn *ssa.Function) string {
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if p := fn.Parent(); p != nil {
		return funcID(p) + strings.TrimPrefix(fn.Name(), p.Name())
	}
	if obj, ok := fn.Object().(*types.Func); ok && obj != nil {
		return canonObj(obj)
	}
	if fn.Pkg != nil {
		return fn.Pkg.Pkg.Path() + "." + fn.Name()
	}
	return fn.Name()
}

func canonObj(obj *types.Func) string {
	if o := obj.Origin(); o != nil {
		obj = o
	}
	pkg := ""
	if obj.Pkg() != nil {
		pkg = obj.Pkg().Path()
	}
	sig, _ := obj.Type().(*types.Signature)
	if sig != nil && sig.Recv() != nil {
		if tn := namedOf(sig.Recv().Type()); tn != nil {
			p := pkg
			if tn.Obj().Pkg() != nil {
				p = tn.Obj().Pkg().Path()
			}
			return p + "." + tn.Obj().Name() + "." + obj.Name()
		}
	}
	if pkg == "" {
		return obj.Name()
	}
	return pkg + "." + obj.Name()
}

func namedOf(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	t = types.Unalias(t)
	if n, ok := t.(*types.Named); ok {
		return n
	}
	return nil
}

func typeStr(t types.Type) string {
	if t == nil {
		return ""
	}
	if n := namedOf(t); n != nil {
		if n.Obj().Pkg() != nil {
			return n.Obj().Pkg().Path() + "." + n.Obj().Name()
		}
		return n.Obj().Name()
	}
	return types.TypeString(t, nil)
}

func (l *lowerer) internal(fn *ssa.Function) bool {
	if fn.Pkg == nil || l.modPath == "" {
		return false
	}
	p := fn.Pkg.Pkg.Path()
	return p == l.modPath || strings.HasPrefix(p, l.modPath+"/")
}

func (l *lowerer) noteType(n *types.Named) {
	if n == nil {
		return
	}
	if _, ok := n.Underlying().(*types.Struct); !ok {
		return
	}
	k := typeStr(n)
	if _, ok := l.seenTypes[k]; !ok {
		l.seenTypes[k] = n
	}
}

func (l *lowerer) noteTypeOf(t types.Type) {
	if n := namedOf(t); n != nil {
		l.noteType(n)
	}
}

func (l *lowerer) typeDecl(n *types.Named) *ir.TypeDecl {
	st, ok := n.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	name := typeStr(n)
	if l.emittedTypes[name] {
		return nil
	}
	l.emittedTypes[name] = true
	td := &ir.TypeDecl{Name: name, Kind: "struct", Lang: lang.Go, Pos: l.pos(n.Obj().Pos())}
	if p := n.Obj().Pkg(); p == nil || (l.modPath != "" && p.Path() != l.modPath && !strings.HasPrefix(p.Path(), l.modPath+"/")) {
		td.External = true
	}
	for i := 0; i < st.NumFields(); i++ {
		fv := st.Field(i)
		tags := parseTag(st.Tag(i))
		if _, ok := tags["gorm"]; ok {
			td.Kind = "entity"
		}
		td.Fields = append(td.Fields, ir.Field{Name: fv.Name(), Type: typeStr(fv.Type()), Tags: tags, Pos: l.pos(fv.Pos())})
	}
	return td
}

// parseTag parses a struct tag (`json:"email" gorm:"column:email"`).
func parseTag(tag string) map[string]string {
	out := map[string]string{}
	for tag != "" {
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}
		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}
		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := tag[:i]
		tag = tag[i+1:]
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qv := tag[:i+1]
		tag = tag[i+1:]
		if v, err := strconv.Unquote(qv); err == nil {
			out[name] = v
		}
	}
	return out
}

func (l *lowerer) lowerFunc(fn *ssa.Function) *ir.Func {
	F := &ir.Func{ID: funcID(fn), Name: fn.Name(), Lang: lang.Go, Pos: l.pos(fn.Pos())}
	F.File = F.Pos.File
	l.fn = F
	l.vars = map[ssa.Value]ir.VarID{}
	l.names = debugNames(fn)
	l.lastPos = F.Pos
	for _, p := range fn.Params {
		l.vars[p] = F.AddParam(p.Name(), typeStr(p.Type()), l.pos(p.Pos()))
		l.noteTypeOf(p.Type())
	}
	for _, fv := range fn.FreeVars {
		l.vars[fv] = F.Named(fv.Name(), typeStr(fv.Type()), l.pos(fv.Pos()))
	}
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			l.instr(ins)
		}
	}
	return F
}

// debugNames maps SSA values to the source identifiers they were read
// from, using the DebugRef instructions emitted in GlobalDebug mode.
func debugNames(fn *ssa.Function) map[ssa.Value]string {
	names := map[ssa.Value]string{}
	for _, b := range fn.Blocks {
		for _, ins := range b.Instrs {
			switch x := ins.(type) {
			case *ssa.DebugRef:
				id, ok := ast.Unparen(x.Expr).(*ast.Ident)
				if !ok {
					continue
				}
				if v, ok := x.Object().(*types.Var); ok && !v.IsField() {
					if _, exists := names[x.X]; !exists {
						names[x.X] = id.Name
					}
				}
			case *ssa.Alloc:
				if x.Comment != "" && !strings.Contains(x.Comment, " ") && !syntheticAlloc[x.Comment] {
					if _, exists := names[x]; !exists {
						names[x] = x.Comment
					}
				}
			}
		}
	}
	return names
}

var syntheticAlloc = map[string]bool{"complit": true, "varargs": true, "slicelit": true, "makeslice": true, "new": true, "rangefunc.exit": true}

func (l *lowerer) v(val ssa.Value) ir.VarID {
	if val == nil {
		return ir.NoVar
	}
	if id, ok := l.vars[val]; ok {
		return id
	}
	F := l.fn
	var id ir.VarID
	switch x := val.(type) {
	case *ssa.Const:
		if x.Value == nil {
			id = F.ConstVar("nil", l.lastPos)
		} else if x.Value.Kind() == constant.String {
			id = F.ConstVar(constant.StringVal(x.Value), l.lastPos)
		} else {
			id = F.ConstVar(x.Value.ExactString(), l.lastPos)
		}
	case *ssa.Function, *ssa.Builtin:
		id = F.Temp(l.lastPos)
	case *ssa.Global:
		id = F.Named(x.Name(), typeStr(x.Type()), l.pos(x.Pos()))
	default:
		p := l.pos(val.Pos())
		if !p.IsValid() {
			p = l.lastPos
		}
		name := l.names[val]
		id = F.NewVar(ir.Var{Name: name, Type: typeStr(val.Type()), Param: -1, Pos: p})
		l.noteTypeOf(val.Type())
	}
	l.vars[val] = id
	return id
}

func fieldInfo(t types.Type, idx int) (name, owner string) {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	owner = typeStr(t)
	if st, ok := t.Underlying().(*types.Struct); ok && idx < st.NumFields() {
		return st.Field(idx).Name(), owner
	}
	return "", owner
}

func constString(v ssa.Value) (string, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(c.Value), true
}

func (l *lowerer) instr(ins ssa.Instruction) {
	F := l.fn
	pos := l.at(ins.Pos())
	switch x := ins.(type) {
	case *ssa.DebugRef:
		if p := l.pos(x.Pos()); p.IsValid() {
			l.lastPos = p
		}
	case *ssa.Alloc:
		l.v(x)
	case *ssa.Store:
		addr, val := l.v(x.Addr), l.v(x.Val)
		F.Assign(addr, pos, val)
		switch a := x.Addr.(type) {
		case *ssa.FieldAddr:
			name, owner := fieldInfo(a.X.Type(), a.Field)
			F.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{l.v(a.X), val}, Field: name, Owner: owner, Pos: pos})
		case *ssa.IndexAddr:
			F.Assign(l.v(a.X), pos, val)
		}
	case *ssa.FieldAddr:
		name, owner := fieldInfo(x.X.Type(), x.Field)
		l.noteTypeOf(x.X.Type())
		F.Emit(ir.Instr{Op: ir.OpLoad, Dst: l.v(x), Args: []ir.VarID{l.v(x.X)}, Field: name, Owner: owner, Pos: pos})
	case *ssa.Field:
		name, owner := fieldInfo(x.X.Type(), x.Field)
		l.noteTypeOf(x.X.Type())
		F.Emit(ir.Instr{Op: ir.OpLoad, Dst: l.v(x), Args: []ir.VarID{l.v(x.X)}, Field: name, Owner: owner, Pos: pos})
	case *ssa.UnOp:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.BinOp:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			l.v(x)
		default:
			F.Assign(l.v(x), pos, l.v(x.X), l.v(x.Y))
		}
	case *ssa.Convert:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.ChangeType:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.MakeInterface:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.ChangeInterface:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.SliceToArrayPointer:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.MultiConvert:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.TypeAssert:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.Extract:
		F.Assign(l.v(x), pos, l.v(x.Tuple))
	case *ssa.Phi:
		args := make([]ir.VarID, 0, len(x.Edges))
		for _, e := range x.Edges {
			args = append(args, l.v(e))
		}
		F.Assign(l.v(x), pos, args...)
	case *ssa.Slice:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.Index:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.IndexAddr:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.Lookup:
		if k, ok := constString(x.Index); ok {
			F.Emit(ir.Instr{Op: ir.OpLoad, Dst: l.v(x), Args: []ir.VarID{l.v(x.X)}, Field: k, Pos: pos})
		} else {
			F.Assign(l.v(x), pos, l.v(x.X))
		}
	case *ssa.MapUpdate:
		m, val := l.v(x.Map), l.v(x.Value)
		if k, ok := constString(x.Key); ok {
			F.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{m, val}, Field: k, Pos: pos})
		} else {
			F.Assign(m, pos, val, l.v(x.Key))
		}
	case *ssa.Range:
		F.Assign(l.v(x), pos, l.v(x.X))
	case *ssa.Next:
		F.Assign(l.v(x), pos, l.v(x.Iter))
	case *ssa.MakeClosure:
		args := make([]ir.VarID, 0, len(x.Bindings))
		for _, b := range x.Bindings {
			args = append(args, l.v(b))
		}
		F.Assign(l.v(x), pos, args...)
	case *ssa.Send:
		F.Assign(l.v(x.Chan), pos, l.v(x.X))
	case *ssa.Select:
		var args []ir.VarID
		for _, st := range x.States {
			args = append(args, l.v(st.Chan))
		}
		F.Assign(l.v(x), pos, args...)
	case *ssa.MakeMap, *ssa.MakeSlice, *ssa.MakeChan:
		l.v(x.(ssa.Value))
	case *ssa.Return:
		args := make([]ir.VarID, 0, len(x.Results))
		for _, r := range x.Results {
			args = append(args, l.v(r))
		}
		F.Emit(ir.Instr{Op: ir.OpReturn, Dst: ir.NoVar, Args: args, Pos: pos})
	case *ssa.Call:
		l.call(x.Common(), l.v(x), pos)
	case *ssa.Go:
		l.call(x.Common(), ir.NoVar, pos)
	case *ssa.Defer:
		l.call(x.Common(), ir.NoVar, pos)
	}
}

func (l *lowerer) call(c *ssa.CallCommon, dst ir.VarID, pos ir.Pos) {
	F := l.fn
	if p := l.pos(c.Pos()); p.IsValid() {
		pos = p
		l.lastPos = p
	}
	call := &ir.Call{}
	var args []ir.VarID
	switch {
	case c.IsInvoke():
		call.Callee = canonObj(c.Method)
		call.Name = c.Method.Name()
		call.HasRecv = true
		call.RecvType = typeStr(c.Value.Type())
		args = append(args, l.v(c.Value))
	default:
		if b, ok := c.Value.(*ssa.Builtin); ok {
			switch b.Name() {
			case "append":
				as := make([]ir.VarID, 0, len(c.Args))
				for _, a := range c.Args {
					as = append(as, l.v(a))
				}
				F.Assign(dst, pos, as...)
			case "copy":
				if len(c.Args) == 2 {
					F.Assign(l.v(c.Args[0]), pos, l.v(c.Args[1]))
				}
			case "print", "println":
				as := make([]ir.VarID, 0, len(c.Args))
				for _, a := range c.Args {
					as = append(as, l.v(a))
				}
				F.Emit(ir.Instr{Op: ir.OpCall, Dst: dst, Args: as, Call: &ir.Call{Callee: "builtin." + b.Name(), Name: b.Name()}, Pos: pos})
			}
			return
		}
		if fn := c.StaticCallee(); fn != nil {
			call.Name = fn.Name()
			if obj, ok := fn.Object().(*types.Func); ok && obj != nil && fn.Parent() == nil {
				call.Callee = canonObj(obj)
				call.Name = obj.Name()
			} else {
				call.Callee = funcID(fn)
			}
			if sig := fn.Signature; sig.Recv() != nil {
				call.HasRecv = true
				call.RecvType = typeStr(sig.Recv().Type())
			}
			if l.internal(fn) {
				call.Target = funcID(fn)
			}
		} else {
			call.Name = l.fn.Vars[l.v(c.Value)].Name
			if call.Name == "" {
				call.Name = c.Value.Name()
			}
		}
	}
	for _, a := range c.Args {
		args = append(args, l.v(a))
	}
	F.Emit(ir.Instr{Op: ir.OpCall, Dst: dst, Args: args, Call: call, Pos: pos})
}
