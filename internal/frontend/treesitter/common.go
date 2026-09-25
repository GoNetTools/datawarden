// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

// Package treesitter provides the Kotlin, Java, Python, Swift and
// TypeScript/JavaScript frontends. They parse with tree-sitter (cgo) and lower syntax to the
// shared IR with best-effort name and type resolution: imports, declared
// types of locals/parameters/fields, constructor calls and a program-wide
// index of classes and functions.
package treesitter

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/lang"
)

type srcFile struct {
	rel       string
	src       []byte
	tree      *sitter.Tree
	root      *sitter.Node
	pkg       string            // JVM package, or TS module id
	imports   map[string]string // simple name -> qualified name
	wildcards []string          // wildcard import prefixes
}

func (f *srcFile) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Content(f.src)
}

type classInfo struct {
	name     string // qualified
	short    string
	file     *srcFile
	fields   map[string]string // field -> declared type (resolved when possible)
	methods  map[string]string // method name -> function ID
	supers   []string
	isStatic bool // Kotlin object / companion: members called without receiver
}

type program struct {
	lang    string
	opts    frontend.Options
	files   []*srcFile
	classes map[string]*classInfo
	byShort map[string][]*classInfo
	funcs   map[string]bool   // all declared function IDs
	top     map[string]string // "<pkg or module>.<name>" -> function ID
	ext     map[string][]string
	modules map[string]bool // TS module ids in this run
	mod     *ir.Module
}

func newProgram(lang string, o frontend.Options) *program {
	return &program{lang: lang, opts: o, classes: map[string]*classInfo{}, byShort: map[string][]*classInfo{},
		funcs: map[string]bool{}, top: map[string]string{}, ext: map[string][]string{}, modules: map[string]bool{}, mod: &ir.Module{Lang: lang}}
}

func (p *program) warnf(format string, args ...any) {
	p.mod.Warnings = append(p.mod.Warnings, fmt.Sprintf(p.lang+": "+format, args...))
}

func (p *program) parse(ctx context.Context, rels []string, lang *sitter.Language) {
	for _, rel := range rels {
		if ctx.Err() != nil {
			return
		}
		if p.opts.FS == nil {
			p.warnf("%s: no source file system configured", rel)
			continue
		}
		src, err := fs.ReadFile(p.opts.FS, rel)
		if err != nil {
			p.warnf("%s: %v", rel, err)
			continue
		}
		parser := sitter.NewParser()
		parser.SetLanguage(lang)
		tree, err := parser.ParseCtx(ctx, nil, src)
		if err != nil {
			p.warnf("%s: parse: %v", rel, err)
			continue
		}
		p.files = append(p.files, &srcFile{rel: rel, src: src, tree: tree, root: tree.RootNode(), imports: map[string]string{}})
	}
}

func (p *program) addClass(c *classInfo) {
	if _, ok := p.classes[c.name]; ok {
		return
	}
	p.classes[c.name] = c
	p.byShort[c.short] = append(p.byShort[c.short], c)
}

// resolveType maps a type name as written in f to a qualified name.
func (p *program) resolveType(f *srcFile, t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimSuffix(t, "?")
	if i := strings.IndexAny(t, "<["); i > 0 {
		t = t[:i]
	}
	if t == "" {
		return ""
	}
	head, rest := t, ""
	if i := strings.IndexByte(t, '.'); i > 0 {
		head, rest = t[:i], t[i:]
	}
	if q, ok := f.imports[head]; ok {
		return q + rest
	}
	if f.pkg != "" && p.lang != lang.TypeScript {
		if _, ok := p.classes[f.pkg+"."+t]; ok {
			return f.pkg + "." + t
		}
	}
	if _, ok := p.classes[t]; ok {
		return t
	}
	if cs := p.byShort[head]; len(cs) == 1 {
		return cs[0].name + rest
	}
	if p.lang == lang.Java || p.lang == lang.Kotlin {
		switch head {
		case "String", "Object", "Integer", "Long", "Boolean", "Double", "Float", "System", "Math", "Thread", "Exception":
			return "java.lang." + t
		}
	}
	return t
}

func (p *program) class(name string) *classInfo {
	if c, ok := p.classes[name]; ok {
		return c
	}
	if cs := p.byShort[shortName(name)]; len(cs) == 1 {
		return cs[0]
	}
	return nil
}

// methodID finds a method on a class or its supertypes.
func (p *program) methodID(cls, name string, depth int) string {
	c := p.class(cls)
	if c == nil || depth > 5 {
		if c == nil {
			id := cls + "." + name
			if p.opts.KnownFunc != nil && p.opts.KnownFunc(id) {
				return id
			}
		}
		return ""
	}
	if id, ok := c.methods[name]; ok {
		return id
	}
	for _, s := range c.supers {
		if id := p.methodID(s, name, depth+1); id != "" {
			return id
		}
	}
	return ""
}

func (p *program) fieldType(cls, field string) string {
	c := p.class(cls)
	for depth := 0; c != nil && depth < 5; depth++ {
		if t, ok := c.fields[field]; ok {
			return t
		}
		if len(c.supers) == 0 {
			break
		}
		c = p.class(c.supers[0])
	}
	return ""
}

func (p *program) known(id string) bool {
	if p.funcs[id] {
		return true
	}
	return p.opts.KnownFunc != nil && p.opts.KnownFunc(id)
}

func shortName(s string) string {
	if i := strings.LastIndexAny(s, "./:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func isUpperStart(s string) bool { return s != "" && s[0] >= 'A' && s[0] <= 'Z' }

// ---- per-function builder ----

type builder struct {
	p       *program
	f       *srcFile
	cls     *classInfo
	fn      *ir.Func
	scope   map[string]ir.VarID
	this    ir.VarID
	names   map[string]ir.VarID // unresolved identifiers read as values
	lambdas map[ir.VarID]ir.VarID
	assigns [][]ir.VarID // stack of variables assigned inside lambdas
}

func (p *program) newBuilder(f *srcFile, cls *classInfo, id, name string, n *sitter.Node) *builder {
	b := &builder{p: p, f: f, cls: cls, scope: map[string]ir.VarID{}, this: ir.NoVar, names: map[string]ir.VarID{}, lambdas: map[ir.VarID]ir.VarID{}}
	b.fn = &ir.Func{ID: id, Name: name, Lang: p.lang, File: f.rel, Pos: b.pos(n)}
	return b
}

func (b *builder) pos(n *sitter.Node) ir.Pos {
	if n == nil {
		return ir.Pos{File: b.f.rel}
	}
	sp := n.StartPoint()
	return ir.Pos{File: b.f.rel, Line: int(sp.Row) + 1, Col: int(sp.Column) + 1}
}

func (b *builder) text(n *sitter.Node) string { return b.f.text(n) }

func (b *builder) temp(n *sitter.Node) ir.VarID { return b.fn.Temp(b.pos(n)) }

func (b *builder) constVar(v string, n *sitter.Node) ir.VarID { return b.fn.ConstVar(v, b.pos(n)) }

func (b *builder) addThis(typ string, n *sitter.Node) {
	b.this = b.fn.AddParam("this", typ, b.pos(n))
}

func (b *builder) param(name, typ string, n *sitter.Node) ir.VarID {
	v := b.fn.AddParam(name, typ, b.pos(n))
	if name != "" {
		b.scope[name] = v
	}
	return v
}

func (b *builder) declare(name, typ string, n *sitter.Node) ir.VarID {
	v := b.fn.Named(name, typ, b.pos(n))
	b.scope[name] = v
	b.noteAssign(v)
	return v
}

func (b *builder) noteAssign(v ir.VarID) {
	if len(b.assigns) > 0 {
		b.assigns[len(b.assigns)-1] = append(b.assigns[len(b.assigns)-1], v)
	}
}

// ident reads an identifier used as a value: a local, a field of this, or
// an unresolved name (kept as a named variable so name detectors see it).
func (b *builder) ident(name string, n *sitter.Node) ir.VarID {
	if v, ok := b.scope[name]; ok {
		return v
	}
	if b.cls != nil && b.this != ir.NoVar {
		if _, ok := b.cls.fields[name]; ok {
			dst := b.fn.Named(name, b.cls.fields[name], b.pos(n))
			b.fn.Emit(ir.Instr{Op: ir.OpLoad, Dst: dst, Args: []ir.VarID{b.this}, Field: name, Owner: b.cls.name, Pos: b.pos(n)})
			return dst
		}
	}
	if v, ok := b.names[name]; ok {
		return v
	}
	v := b.fn.Named(name, "", b.pos(n))
	b.names[name] = v
	return v
}

func (b *builder) assign(dst ir.VarID, n *sitter.Node, args ...ir.VarID) {
	b.fn.Assign(dst, b.pos(n), args...)
}

func (b *builder) load(obj ir.VarID, field, owner string, n *sitter.Node) ir.VarID {
	dst := b.fn.Named("", "", b.pos(n))
	if t := b.p.fieldType(owner, field); t != "" {
		b.fn.Vars[dst].Type = t
	}
	b.fn.Emit(ir.Instr{Op: ir.OpLoad, Dst: dst, Args: []ir.VarID{obj}, Field: field, Owner: owner, Pos: b.pos(n)})
	return dst
}

func (b *builder) store(obj ir.VarID, field, owner string, val ir.VarID, n *sitter.Node) {
	if obj == ir.NoVar || val == ir.NoVar {
		return
	}
	b.fn.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{obj, val}, Field: field, Owner: owner, Pos: b.pos(n)})
	b.noteAssign(obj)
}

func (b *builder) ret(n *sitter.Node, vals ...ir.VarID) {
	var args []ir.VarID
	for _, v := range vals {
		if v != ir.NoVar {
			args = append(args, v)
		}
	}
	b.fn.Emit(ir.Instr{Op: ir.OpReturn, Dst: ir.NoVar, Args: args, Pos: b.pos(n)})
}

// emitCall emits a call and returns its result variable.
func (b *builder) emitCall(n *sitter.Node, c *ir.Call, args []ir.VarID, resultType string) ir.VarID {
	dst := b.fn.Named("", resultType, b.pos(n))
	for _, a := range args {
		if cb, ok := b.lambdas[a]; ok {
			c.Callbacks = append(c.Callbacks, cb)
		}
	}
	b.fn.Emit(ir.Instr{Op: ir.OpCall, Dst: dst, Args: args, Call: c, Pos: b.pos(n)})
	return dst
}

// lambda lowers a lambda/closure inline. params are declared in scope and
// fed from a callback-input variable; the returned value variable carries
// the lambda's result and anything assigned inside it.
func (b *builder) lambda(n *sitter.Node, params []*sitter.Node, paramNames []string, implicitIt bool, body func() ir.VarID) ir.VarID {
	cb := b.temp(n)
	saved := map[string]ir.VarID{}
	had := map[string]bool{}
	declare := func(name string, pn *sitter.Node) {
		if old, ok := b.scope[name]; ok {
			saved[name], had[name] = old, true
		} else {
			had[name] = false
		}
		v := b.fn.Named(name, "", b.pos(pn))
		b.scope[name] = v
		b.assign(v, pn, cb)
	}
	for i, name := range paramNames {
		declare(name, params[i])
	}
	if implicitIt && len(paramNames) == 0 {
		declare("it", n)
	}
	b.assigns = append(b.assigns, nil)
	last := body()
	assigned := b.assigns[len(b.assigns)-1]
	b.assigns = b.assigns[:len(b.assigns)-1]
	val := b.temp(n)
	b.assign(val, n, append([]ir.VarID{last}, assigned...)...)
	for name, was := range had {
		if was {
			b.scope[name] = saved[name]
		} else {
			delete(b.scope, name)
		}
	}
	b.lambdas[val] = cb
	return val
}

func (b *builder) finish() *ir.Func {
	b.p.mod.Funcs = append(b.p.mod.Funcs, b.fn)
	return b.fn
}

// ---- tree helpers ----

func named(n *sitter.Node) []*sitter.Node {
	if n == nil {
		return nil
	}
	cnt := int(n.NamedChildCount())
	out := make([]*sitter.Node, 0, cnt)
	for i := 0; i < cnt; i++ {
		out = append(out, n.NamedChild(i))
	}
	return out
}

func firstOf(n *sitter.Node, types ...string) *sitter.Node {
	for _, c := range named(n) {
		for _, t := range types {
			if c.Type() == t {
				return c
			}
		}
	}
	return nil
}

func allOf(n *sitter.Node, types ...string) []*sitter.Node {
	var out []*sitter.Node
	for _, c := range named(n) {
		for _, t := range types {
			if c.Type() == t {
				out = append(out, c)
			}
		}
	}
	return out
}

func hasChildToken(n *sitter.Node, src []byte, tok string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if !c.IsNamed() && c.Content(src) == tok {
			return true
		}
	}
	return false
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 6 && (strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`)) {
		return s[3 : len(s)-3]
	}
	if len(s) >= 2 {
		q := s[0]
		if (q == '"' || q == '\'' || q == '`') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func trimText(s string) string {
	s = strings.Join(strings.Fields(s), "")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// tsModuleID is the module id of a TS/JS file: its path without extension.
func tsModuleID(rel string) string {
	ext := path.Ext(rel)
	return strings.TrimSuffix(rel, ext)
}

// hasBehaviour reports whether a class declares methods other than
// accessors and value-object boilerplate (i.e. it is a service, not data).
func hasBehaviour(methods map[string]string) bool {
	for m := range methods {
		switch {
		case m == "toString" || m == "equals" || m == "hashCode" || m == "copy" || m == "builder" || m == "toBuilder" || m == "compareTo" || m == "toJSON" || m == "toJson":
		case strings.HasPrefix(m, "get") || strings.HasPrefix(m, "set") || strings.HasPrefix(m, "is") || strings.HasPrefix(m, "component") || strings.HasPrefix(m, "with"):
		default:
			return true
		}
	}
	return false
}
