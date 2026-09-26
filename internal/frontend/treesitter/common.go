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
	"maps"
	"path"
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/lang"
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
	// consts holds boolean constants declared in the source, keyed by
	// "Class.NAME" for class members and "file|NAME" for top-level ones.
	consts map[string]bool
	// subs indexes direct subclasses and implementers by class name; nil
	// until first needed and whenever a class is added.
	subs map[string][]*classInfo
	// getters maps "Class.prop" to the function that computes the
	// property (Python @property, Kotlin get(), Swift computed properties).
	getters map[string]string
}

func newProgram(lang string, o frontend.Options) *program {
	return &program{lang: lang, opts: o, classes: map[string]*classInfo{}, byShort: map[string][]*classInfo{},
		funcs: map[string]bool{}, top: map[string]string{}, ext: map[string][]string{}, modules: map[string]bool{}, mod: &ir.Module{Lang: lang},
		consts: map[string]bool{}, getters: map[string]string{}}
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
		f := &srcFile{rel: rel, src: src, tree: tree, root: tree.RootNode(), imports: map[string]string{}}
		if n, line := syntaxErrors(f.root); n > 0 {
			p.warnf("%s:%d: %d syntax error(s) the parser could not read; the code around them is analysed as far as it could be recovered", rel, line, n)
		}
		p.files = append(p.files, f)
		p.collectConsts(f, f.root)
	}
}

// collectConsts records boolean constants: Java final fields, Kotlin val
// and const val, Swift let, TypeScript const and readonly fields, and
// Python UPPER_CASE assignments at module or class level, when their value
// is a boolean literal (static final boolean DEBUG = false).
func (p *program) collectConsts(f *srcFile, n *sitter.Node) {
	for _, c := range named(n) {
		switch c.Type() {
		case "block", "function_body", "method_declaration", "constructor_declaration", "function_declaration", "function_definition",
			"statement_block", "lambda_expression", "lambda_literal", "arrow_function":
			continue // locals are handled through their variables
		}
		name, val := p.constDecl(f, c)
		if name != "" && val != nil {
			switch strings.TrimSpace(f.text(val)) {
			case "true", "True":
				p.consts[constOwner(f, c)+name] = true
			case "false", "False":
				p.consts[constOwner(f, c)+name] = false
			}
		}
		p.collectConsts(f, c)
	}
}

// constDecl returns the name and value of an immutable declaration.
func (p *program) constDecl(f *srcFile, n *sitter.Node) (string, *sitter.Node) {
	text := f.text(n)
	switch p.lang {
	case lang.Java:
		if (n.Type() == "field_declaration" || n.Type() == "constant_declaration") && strings.Contains(f.text(firstOf(n, "modifiers")), "final") ||
			n.Type() == "constant_declaration" {
			if d := firstOf(n, "variable_declarator"); d != nil {
				return f.text(d.ChildByFieldName("name")), d.ChildByFieldName("value")
			}
		}
	case lang.Kotlin:
		if n.Type() == "property_declaration" && !strings.Contains(f.text(firstOf(n, "binding_pattern_kind")), "var") {
			if vd := firstOf(n, "variable_declaration"); vd != nil {
				return f.text(firstOf(vd, "simple_identifier")), ktPropValue(n)
			}
		}
	case lang.Swift:
		if n.Type() == "property_declaration" && strings.Contains(f.text(firstOf(n, "value_binding_pattern")), "let") {
			if id := n.ChildByFieldName("name"); id != nil {
				return strings.TrimSpace(f.text(id)), n.ChildByFieldName("value")
			}
		}
	case lang.TypeScript:
		switch {
		case n.Type() == "lexical_declaration" && strings.HasPrefix(text, "const"):
			if d := firstOf(n, "variable_declarator"); d != nil {
				return f.text(d.ChildByFieldName("name")), d.ChildByFieldName("value")
			}
		case (n.Type() == "public_field_definition" || n.Type() == "field_definition") && strings.Contains(text, "readonly"):
			return unquote(f.text(n.ChildByFieldName("name"))), n.ChildByFieldName("value")
		}
	case lang.Python:
		if n.Type() == "assignment" {
			if l := n.ChildByFieldName("left"); l != nil && l.Type() == "identifier" && f.text(l) == strings.ToUpper(f.text(l)) {
				return f.text(l), n.ChildByFieldName("right")
			}
		}
	}
	return "", nil
}

// constOwner is the key prefix of a declaration: its enclosing class's
// short name, or its file for a top-level declaration.
func constOwner(f *srcFile, n *sitter.Node) string {
	for a := n.Parent(); a != nil; a = a.Parent() {
		switch a.Type() {
		case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "object_declaration",
			"class_definition", "protocol_declaration", "abstract_class_declaration":
			name := a.ChildByFieldName("name")
			if name == nil {
				name = firstOf(a, "type_identifier", "simple_identifier", "identifier")
			}
			return f.text(name) + "."
		}
	}
	return f.rel + "|"
}

func (p *program) addClass(c *classInfo) {
	if _, ok := p.classes[c.name]; ok {
		return
	}
	p.classes[c.name] = c
	p.byShort[c.short] = append(p.byShort[c.short], c)
	p.subs = nil
}

// overrides lists the methods named m that a call on a receiver of type
// cls may run besides static: the overrides and implementations in cls's
// subclasses and implementers (class hierarchy analysis).
func (p *program) overrides(cls, m, static string) []string {
	root := p.class(cls)
	if root == nil || m == "" {
		return nil
	}
	if p.subs == nil {
		p.subs = map[string][]*classInfo{}
		for _, name := range slices.Sorted(maps.Keys(p.classes)) {
			c := p.classes[name]
			for _, s := range c.supers {
				if sc := p.class(s); sc != nil && sc != c {
					p.subs[sc.name] = append(p.subs[sc.name], c)
				}
			}
		}
	}
	var out []string
	seen := map[*classInfo]bool{root: true}
	work := append([]*classInfo(nil), p.subs[root.name]...)
	for len(work) > 0 && len(out) < 16 {
		c := work[0]
		work = work[1:]
		if seen[c] {
			continue
		}
		seen[c] = true
		if id, ok := c.methods[m]; ok && id != static && !slices.Contains(out, id) {
			out = append(out, id)
		}
		work = append(work, p.subs[c.name]...)
	}
	return out
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

// ctorID is the constructor function of class cls when it is lowered: its
// own or an inherited one (Java/Kotlin <init>, Python __init__, TypeScript
// constructor, Swift init).
func (p *program) ctorID(cls string) string {
	if p.class(cls) == nil {
		return ""
	}
	for _, name := range []string{"<init>", "__init__", "constructor", "init"} {
		if id := p.methodID(cls, name, 0); id != "" {
			return id
		}
	}
	for c, depth := p.class(cls), 0; c != nil && depth < 5; depth++ {
		if id := c.name + ".<init>"; p.funcs[id] {
			return id
		}
		if c.file != nil {
			if id := c.file.pkg + ":" + c.short + ".constructor"; p.funcs[id] {
				return id // TypeScript
			}
		}
		if len(c.supers) == 0 {
			break
		}
		c = p.class(c.supers[0])
	}
	return ""
}

// getter is the function that computes property field of cls or a
// superclass, or "".
func (p *program) getter(cls, field string) string {
	for c, depth := p.class(cls), 0; c != nil && depth < 5; depth++ {
		if id, ok := p.getters[c.name+"."+field]; ok {
			return id
		}
		if len(c.supers) == 0 {
			break
		}
		c = p.class(c.supers[0])
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
	assigns [][]ir.VarID        // stack of variables assigned inside lambdas
	kwargs  map[ir.VarID]string // keyword-argument variables -> parameter name

	// Control flow. floating counts the enclosing lambdas: their blocks
	// have no fixed place in the function's order. terminated is set once
	// the current path has returned; what follows it is unreachable.
	floating   int
	terminated bool
	targets    []*jumpTarget // enclosing loops and switches, innermost last
	label      string        // label of the statement being lowered

	// Exceptions. catchers holds, per enclosing try body, the variable its
	// handlers catch; caught is the one the handler being lowered binds;
	// escaped collects what leaves the function (NoVar until needed).
	catchers []ir.VarID
	caught   ir.VarID
	escaped  ir.VarID

	// JVM reflection: variables holding a Class, Field or Method handle,
	// and proxies with their invocation handler's callback input.
	refl    map[ir.VarID]reflHandle
	proxies map[ir.VarID]ir.VarID
}

// reflHandle is a reflective handle whose target is known from constant
// names: kind 'c' a class, 'f' a field of it, 'm' a method of it.
type reflHandle struct {
	kind          byte
	class, member string
}

// exit is where a path leaves a construct: its scope and block.
type exit struct {
	scope map[string]ir.VarID
	block int32
}

// jumpTarget is a loop or switch that break leaves; continue goes back to
// the header of a loop.
type jumpTarget struct {
	label        string
	loop         bool
	breaks, cont []exit
}

func (b *builder) here() exit { return exit{b.snapshot(), b.fn.CurBlock()} }

func blocksOf(es []exit) []int32 {
	out := make([]int32, len(es))
	for i, e := range es {
		out[i] = e.block
	}
	return out
}

func scopesOf(es []exit) []map[string]ir.VarID {
	out := make([]map[string]ir.VarID, len(es))
	for i, e := range es {
		out[i] = e.scope
	}
	return out
}

// takeLabel returns the label of the statement being lowered, once.
func (b *builder) takeLabel() string {
	l := b.label
	b.label = ""
	return l
}

// jump lowers break (or continue) with an optional label: the path ends
// here and resumes at the target's exit (or loop header). A jump with no
// target in this function (a break inside a lambda body) is ignored.
func (b *builder) jump(isContinue bool, label string) {
	for i := len(b.targets) - 1; i >= 0; i-- {
		t := b.targets[i]
		if (label != "" && t.label != label) || (isContinue && !t.loop) {
			continue
		}
		if isContinue {
			t.cont = append(t.cont, b.here())
		} else {
			t.breaks = append(t.breaks, b.here())
		}
		b.terminated = true
		b.newBlock()
		return
	}
}

func (p *program) newBuilder(f *srcFile, cls *classInfo, id, name string, n *sitter.Node) *builder {
	b := &builder{p: p, f: f, cls: cls, scope: map[string]ir.VarID{}, this: ir.NoVar, names: map[string]ir.VarID{}, lambdas: map[ir.VarID]ir.VarID{},
		caught: ir.NoVar, escaped: ir.NoVar}
	b.fn = &ir.Func{ID: id, Name: name, Lang: p.lang, File: f.rel, Pos: b.pos(n)}
	b.fn.NewBlock(false) // entry
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

// redefine gives a local a new version for a plain assignment (x = v):
// reads after it see the returned variable, reads before it keep the old
// one, so a value that is overwritten no longer reaches later sinks. Inside
// a lambda, which may run any number of times and at any time, the
// assignment stays a weak update of the existing variable.
func (b *builder) redefine(name string, old ir.VarID, typ string, n *sitter.Node) ir.VarID {
	if len(b.assigns) > 0 || old == b.this {
		b.noteAssign(old)
		return old
	}
	if typ == "" {
		typ = b.fn.Vars[old].Type
	}
	v := b.fn.Named(name, typ, b.pos(n))
	b.scope[name] = v
	return v
}

func (b *builder) snapshot() map[string]ir.VarID { return maps.Clone(b.scope) }

// join merges the scopes at the ends of alternative paths: a name bound to
// different versions gets a new version assigned from all of them. Names
// bound on only some paths are kept (Python, JS var and a missed block
// scope all leave them visible).
func (b *builder) join(n *sitter.Node, paths ...map[string]ir.VarID) {
	out := map[string]ir.VarID{}
	versions := map[string][]ir.VarID{}
	for _, p := range paths {
		for name, v := range p {
			if !slices.Contains(versions[name], v) {
				versions[name] = append(versions[name], v)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(versions)) {
		vs := versions[name]
		if len(vs) == 1 {
			out[name] = vs[0]
			continue
		}
		phi := b.fn.Named(name, b.fn.Vars[vs[0]].Type, b.pos(n))
		b.assign(phi, n, vs...)
		out[name] = phi
	}
	b.scope = out
}

// branches lowers alternative paths (if/else arms, switch cases) from the
// current scope and joins them. skippable adds the path that takes none of
// them: an if without else, a switch without default.
//
// Each arm starts a block from the current one, and the join is a new
// block after them. An arm that returns is left out of the join; when all
// of them return, what follows is unreachable.
func (b *builder) branches(n *sitter.Node, skippable bool, arms ...func()) {
	entry, from, dead := b.snapshot(), b.fn.CurBlock(), b.terminated
	var scopes []map[string]ir.VarID
	var ends []int32
	if skippable || len(arms) == 0 {
		scopes, ends = append(scopes, entry), append(ends, from)
	}
	for _, arm := range arms {
		b.scope = maps.Clone(entry)
		b.terminated = false
		b.newBlock(from)
		arm()
		if !b.terminated {
			scopes, ends = append(scopes, b.scope), append(ends, b.fn.CurBlock())
		}
	}
	b.newBlock(ends...)
	b.terminated = dead || len(scopes) == 0
	if len(scopes) == 0 {
		b.scope = entry
		return
	}
	b.join(n, scopes...)
}

// loop lowers a loop body that may run zero or more times.
func (b *builder) loop(n *sitter.Node, body func()) { b.loopWith(n, loopSpec{body: body}) }

type loopSpec struct {
	body func()
	// orelse runs when the loop ends other than by break (Python's
	// for/while ... else).
	orelse func()
	// infinite marks while(true): the loop is left only by break.
	infinite bool
}

// loopWith lowers a loop. The body starts in a header block that the end of
// the body and every continue loop back to. A local the body redefines gets
// a header version merging the value from before the loop with the value at
// each of those back edges; reads in the body are rewritten to it. The code
// after the loop joins the header's exit with every break.
func (b *builder) loopWith(n *sitter.Node, spec loopSpec) {
	entry, dead := b.snapshot(), b.terminated
	t := &jumpTarget{label: b.takeLabel(), loop: true}
	head := b.newBlock(b.fn.CurBlock())
	b.targets = append(b.targets, t)
	start := len(b.fn.Instrs)
	b.terminated = false
	spec.body()
	end := len(b.fn.Instrs)
	b.targets = b.targets[:len(b.targets)-1]
	backs := t.cont
	if !b.terminated {
		backs = append(backs, b.here())
	}
	for _, bk := range backs {
		b.fn.Edge(bk.block, head)
	}
	if spec.infinite {
		b.newBlock()
	} else {
		b.newBlock(head)
	}

	// Header versions, emitted after the body so the rewrite leaves them alone.
	rename := map[ir.VarID]ir.VarID{}
	for _, name := range slices.Sorted(maps.Keys(entry)) {
		pre := entry[name]
		var vs []ir.VarID
		for _, bk := range backs {
			if v, ok := bk.scope[name]; ok && v != pre && !slices.Contains(vs, v) {
				vs = append(vs, v)
			}
		}
		if len(vs) == 0 {
			continue
		}
		h := b.fn.Named(name, b.fn.Vars[pre].Type, b.pos(n))
		rename[pre] = h
		b.assign(h, n, append([]ir.VarID{pre}, vs...)...)
	}
	for i := start; i < end; i++ {
		in := &b.fn.Instrs[i]
		for j, a := range in.Args {
			if h, ok := rename[a]; ok {
				in.Args[j] = h
			}
		}
	}
	remap := func(sc map[string]ir.VarID) map[string]ir.VarID {
		out := maps.Clone(sc)
		for k, v := range out {
			if h, ok := rename[v]; ok {
				out[k] = h
			}
		}
		return out
	}

	var exits []exit
	if !spec.infinite {
		// Leaving from the header: the header versions, plus the names
		// the body binds for the first time as the last iteration left them.
		paths := []map[string]ir.VarID{remap(entry)}
		for _, bk := range backs {
			fresh := map[string]ir.VarID{}
			for k, v := range bk.scope {
				if _, ok := entry[k]; !ok {
					fresh[k] = v
				}
			}
			paths = append(paths, fresh)
		}
		b.terminated = false
		b.join(n, paths...)
		if spec.orelse != nil {
			spec.orelse()
		}
		if !b.terminated {
			exits = append(exits, b.here())
		}
	}
	for _, br := range t.breaks {
		exits = append(exits, exit{remap(br.scope), br.block})
	}
	b.newBlock(blocksOf(exits)...)
	b.terminated = dead || len(exits) == 0
	if len(exits) == 0 {
		b.scope = remap(entry) // while(true) without break: nothing follows
		return
	}
	b.join(n, scopesOf(exits)...)
}

// switchCases lowers the cases of a switch statement. With fallthrough (C,
// Java and JavaScript switch statements, fallsThrough), a case that does not end in break
// continues into the next one; break leaves the switch. exhaustive means a
// default case exists, so no path skips every case.
func (b *builder) switchCases(n *sitter.Node, fallsThrough, exhaustive bool, cases []func()) {
	entry, from, dead := b.snapshot(), b.fn.CurBlock(), b.terminated
	t := &jumpTarget{label: b.takeLabel()}
	b.targets = append(b.targets, t)
	var ends []exit
	var prev *exit
	for _, c := range cases {
		starts := []exit{{entry, from}}
		if prev != nil {
			starts = append(starts, *prev)
		}
		b.newBlock(blocksOf(starts)...)
		b.terminated = false
		b.join(n, scopesOf(starts)...)
		c()
		prev = nil
		if !b.terminated {
			if e := b.here(); fallsThrough {
				prev = &e
			} else {
				ends = append(ends, e)
			}
		}
	}
	if prev != nil {
		ends = append(ends, *prev)
	}
	b.targets = b.targets[:len(b.targets)-1]
	ends = append(ends, t.breaks...)
	if !exhaustive || len(cases) == 0 {
		ends = append(ends, exit{entry, from})
	}
	b.newBlock(blocksOf(ends)...)
	b.terminated = dead || len(ends) == 0
	if len(ends) == 0 {
		b.scope = entry
		return
	}
	b.join(n, scopesOf(ends)...)
}

// ifElse lowers an if statement whose condition was already lowered: then
// and els (nil without an else) are alternative paths. A constant
// condition (see truth) leaves out the arm that cannot run.
func (b *builder) ifElse(n, cond *sitter.Node, then, els func()) {
	v, known := b.truth(cond)
	switch {
	case known && v:
		b.branches(n, false, then)
	case known && els != nil:
		b.branches(n, false, els)
	case known:
		// if false { ... } without else: nothing runs.
	case els != nil:
		b.branches(n, false, then, els)
	default:
		b.branches(n, true, then)
	}
}

// truth folds a condition whose value is fixed in the source: a boolean
// literal, a negation or parenthesised form of one, or a local variable
// whose only definition is such a constant (verbose = false). Anything
// that depends on data is unknown.
func (b *builder) truth(n *sitter.Node) (value, known bool) {
	for depth := 0; n != nil && depth < 8; depth++ {
		t := strings.TrimSpace(b.text(n))
		switch t {
		case "true", "True":
			return true, true
		case "false", "False":
			return false, true
		}
		k := named(n)
		switch {
		case len(k) == 1 && (strings.HasPrefix(t, "!") || strings.HasPrefix(t, "not ")) && !strings.HasPrefix(t, "!="):
			v, ok := b.truth(k[0])
			return !v, ok
		case len(k) == 1 && (n.Type() == "parenthesized_expression" || n.Type() == "condition" || n.Type() == "expression_statement"):
			n = k[0]
			continue
		case n.Type() == "identifier" || n.Type() == "simple_identifier":
			if v, ok := b.scope[t]; ok {
				return b.constTruth(v, 0)
			}
			return b.constant("", t)
		case len(k) >= 2 && isQualifiedName(t):
			i := strings.LastIndexByte(t, '.')
			return b.constant(t[:i], t[i+1:])
		}
		return false, false
	}
	return false, false
}

// constant looks up a declared boolean constant: NAME in the current class
// or file, or Owner.NAME (this.NAME, self.NAME, Config.NAME).
func (b *builder) constant(owner, name string) (value, known bool) {
	cls := ""
	if b.cls != nil {
		cls = b.cls.short
	}
	switch owner {
	case "", "this", "self", "Self":
		if v, ok := b.p.consts[cls+"."+name]; ok && cls != "" {
			return v, true
		}
		if owner != "" {
			return false, false
		}
		v, ok := b.p.consts[b.f.rel+"|"+name]
		return v, ok
	}
	v, ok := b.p.consts[shortName(owner)+"."+name]
	return v, ok
}

// isQualifiedName reports whether s is a dotted name: Config.DEBUG.
func isQualifiedName(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for i, r := range part {
			if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// constTruth follows a variable through single-definition copies to a
// boolean literal.
func (b *builder) constTruth(v ir.VarID, depth int) (value, known bool) {
	if v < 0 || int(v) >= len(b.fn.Vars) || depth > 4 {
		return false, false
	}
	if c := b.fn.Vars[v].Const; c != nil {
		switch *c {
		case "true", "True":
			return true, true
		case "false", "False":
			return false, true
		}
		return false, false
	}
	if b.fn.Vars[v].Param >= 0 {
		return false, false
	}
	var def *ir.Instr
	for i := range b.fn.Instrs {
		if b.fn.Instrs[i].Dst == v {
			if def != nil {
				return false, false // assigned more than once
			}
			def = &b.fn.Instrs[i]
		}
	}
	if def == nil || def.Op != ir.OpAssign || def.Snapshot || len(def.Args) != 1 {
		return false, false
	}
	return b.constTruth(def.Args[0], depth+1)
}

// tryCatch lowers try/catch/finally. A handler can start after any part of
// the body ran, so it starts from the join of the scopes before and after
// the body; the finally block runs after either.
//
// Handler blocks have edges from the start and the end of the body.
func (b *builder) tryCatch(n *sitter.Node, body func(), handlers []func(), finally func()) {
	entry, from, dead := b.snapshot(), b.fn.CurBlock(), b.terminated
	start := b.newBlock(from)
	b.terminated = false
	thrown := b.fn.Temp(b.pos(n))
	b.catchers = append(b.catchers, thrown)
	body()
	b.catchers = b.catchers[:len(b.catchers)-1]
	done, doneBlock := b.snapshot(), b.fn.CurBlock()
	var scopes []map[string]ir.VarID
	var ends []int32
	if !b.terminated {
		scopes, ends = append(scopes, done), append(ends, doneBlock)
	}
	for _, h := range handlers {
		b.newBlock(from, start, doneBlock)
		b.terminated = false
		b.join(n, entry, done)
		saved := b.caught
		b.caught = thrown
		h()
		b.caught = saved
		if !b.terminated {
			scopes, ends = append(scopes, b.scope), append(ends, b.fn.CurBlock())
		}
	}
	b.newBlock(ends...)
	b.terminated = dead || len(scopes) == 0
	if len(scopes) == 0 {
		b.scope = entry
	} else {
		b.join(n, scopes...)
	}
	if finally != nil {
		finally()
	}
}

func (b *builder) noteAssign(v ir.VarID) {
	if len(b.assigns) > 0 {
		b.assigns[len(b.assigns)-1] = append(b.assigns[len(b.assigns)-1], v)
	}
}

// kwarg makes a variable for a keyword or named argument (f(to=x)): the
// call records its name, so the value reaches the parameter of that name.
func (b *builder) kwarg(name string, v ir.VarID, n *sitter.Node) ir.VarID {
	nv := b.fn.Named(name, "", b.pos(n))
	b.assign(nv, n, v)
	if b.kwargs == nil {
		b.kwargs = map[ir.VarID]string{}
	}
	b.kwargs[nv] = name
	return nv
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
	// Reflective handles and proxies stay what they are through copies
	// and casts.
	for _, a := range args {
		if r, ok := b.refl[a]; ok && dst >= 0 {
			b.markRefl(dst, r)
		}
		if cb, ok := b.proxies[a]; ok && dst >= 0 {
			b.proxies[dst] = cb
		}
	}
	// A variable holding a lambda (show = { log(it) }) is one: calling it
	// feeds the lambda's parameters.
	if _, has := b.lambdas[dst]; !has {
		for _, a := range args {
			if cb, ok := b.lambdas[a]; ok && dst >= 0 {
				b.lambdas[dst] = cb
				break
			}
		}
	}
}

// compute is assign for a new value built from the arguments' current
// state (concatenation, interpolation, arithmetic), not a reference to them.
func (b *builder) compute(dst ir.VarID, n *sitter.Node, args ...ir.VarID) {
	b.fn.Compute(dst, b.pos(n), args...)
}

func (b *builder) load(obj ir.VarID, field, owner string, n *sitter.Node) ir.VarID {
	if id := b.p.getter(owner, field); id != "" && obj != ir.NoVar {
		// A computed property: reading it runs its getter.
		c := &ir.Call{Callee: id, Name: field, Target: id, HasRecv: true, RecvType: owner}
		return b.emitCall(n, c, []ir.VarID{obj}, b.p.fieldType(owner, field))
	}
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
	// Whatever follows on this path is unreachable.
	b.terminated = true
	b.newBlock()
}

// yieldValue lowers a generator's yield: the value is produced to the
// caller, like a return, but the function goes on.
func (b *builder) yieldValue(v ir.VarID, n *sitter.Node) {
	if v != ir.NoVar {
		b.fn.Emit(ir.Instr{Op: ir.OpReturn, Dst: ir.NoVar, Args: []ir.VarID{v}, Pos: b.pos(n)})
	}
}

// newBlock starts a new basic block with edges from preds.
func (b *builder) newBlock(preds ...int32) int32 {
	return b.fn.NewBlock(b.floating > 0, preds...)
}

// floatingRegion lowers code that runs at no fixed point of the function:
// a lambda or local function body, which may run when it is created, later
// or never. Its blocks are unordered, and a return inside it ends only it.
func (b *builder) floatingRegion(body func()) {
	from, terminated, targets, catchers := b.fn.CurBlock(), b.terminated, b.targets, b.catchers
	b.floating++
	b.targets, b.catchers = nil, nil
	b.newBlock()
	body()
	b.floating--
	b.fn.SetBlock(from)
	b.terminated, b.targets, b.catchers = terminated, targets, catchers
}

// thrown is the variable a throw at this point reaches: the innermost
// enclosing handler's, or the function's escaping exception.
func (b *builder) thrown() ir.VarID {
	if n := len(b.catchers); n > 0 {
		return b.catchers[n-1]
	}
	if b.escaped == ir.NoVar {
		b.escaped = b.fn.Temp(b.fn.Pos)
	}
	return b.escaped
}

// throwValue lowers throw/raise v.
func (b *builder) throwValue(v ir.VarID, n *sitter.Node) {
	b.assign(b.thrown(), n, v)
}

// caughtValue is the value a catch clause binds: what the try body threw.
func (b *builder) caughtValue(n *sitter.Node) ir.VarID {
	if b.caught != ir.NoVar {
		return b.caught
	}
	return b.temp(n)
}

// emitCall emits a call and returns its result variable.
func (b *builder) emitCall(n *sitter.Node, c *ir.Call, args []ir.VarID, resultType string) ir.VarID {
	if v, ok := b.reflectCall(n, c, args); ok {
		return v
	}
	dst := b.fn.Named("", resultType, b.pos(n))
	defer b.noteReflect(c, args, dst)
	// A call on a proxy runs its invocation handler with the arguments.
	if c.HasRecv && len(args) > 0 {
		if cb, ok := b.proxies[args[0]]; ok {
			c.Callbacks = append(c.Callbacks, cb)
			c.Target, c.Targets = "", nil
		}
	}
	if c.Construct && c.Ctor == "" {
		c.Ctor = b.p.ctorID(c.Callee)
	}
	c.Catch = []ir.VarID{b.thrown()}
	// Calling a lambda held in a variable: show(email), show.invoke(email),
	// show.accept(email), show.call(email). Its arguments reach the
	// lambda's parameters.
	if c.Target == "" && !c.Construct {
		if v, ok := b.scope[c.Name]; ok && !c.HasRecv {
			if cb, ok := b.lambdas[v]; ok {
				c.Callbacks = append(c.Callbacks, cb)
			}
		}
		if c.HasRecv && len(args) > 0 {
			if cb, ok := b.lambdas[args[0]]; ok {
				c.Callbacks = append(c.Callbacks, cb)
			}
		}
	}
	if !c.Construct && c.RecvType != "" && c.Targets == nil {
		c.Targets = b.p.overrides(c.RecvType, c.Name, c.Target)
	}
	for i, a := range args {
		if name, ok := b.kwargs[a]; ok {
			if c.ArgNames == nil {
				c.ArgNames = make([]string, len(args))
			}
			c.ArgNames[i] = name
		}
	}
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
	last := ir.NoVar
	b.floatingRegion(func() { last = body() })
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

func (b *builder) markRefl(v ir.VarID, r reflHandle) {
	if b.refl == nil {
		b.refl = map[ir.VarID]reflHandle{}
	}
	b.refl[v] = r
}

// handle returns the reflective handle v holds: one recorded for it, or a
// class literal (User.class, User::class) lowered as the constant
// "<class>.class".
func (b *builder) handle(v ir.VarID) (reflHandle, bool) {
	if r, ok := b.refl[v]; ok {
		return r, true
	}
	if v >= 0 && int(v) < len(b.fn.Vars) {
		if c := b.fn.Vars[v].Const; c != nil && strings.HasSuffix(*c, ".class") {
			return reflHandle{kind: 'c', class: b.p.resolveType(b.f, strings.TrimSuffix(*c, ".class"))}, true
		}
	}
	return reflHandle{}, false
}

func (b *builder) constString(v ir.VarID) (string, bool) {
	if v < 0 || int(v) >= len(b.fn.Vars) || b.fn.Vars[v].Const == nil {
		return "", false
	}
	return *b.fn.Vars[v].Const, true
}

// reflectCall lowers a use of a reflective handle as what it does:
// field.get(obj) reads the field, field.set(obj, v) writes it,
// method.invoke(obj, args...) calls the method, cls.newInstance() and
// ctor.newInstance(args...) construct the class.
func (b *builder) reflectCall(n *sitter.Node, c *ir.Call, args []ir.VarID) (ir.VarID, bool) {
	if !c.HasRecv || len(args) == 0 {
		return ir.NoVar, false
	}
	h, ok := b.handle(args[0])
	if !ok {
		return ir.NoVar, false
	}
	switch {
	case h.kind == 'f' && strings.HasPrefix(c.Name, "get") && len(args) >= 2:
		return b.load(args[1], h.member, h.class, n), true
	case h.kind == 'f' && c.Name == "call" && len(args) >= 2: // Kotlin KProperty.call(obj)
		return b.load(args[1], h.member, h.class, n), true
	case h.kind == 'f' && strings.HasPrefix(c.Name, "set") && len(args) >= 3:
		b.store(args[1], h.member, h.class, args[2], n)
		return b.temp(n), true
	case h.kind == 'm' && (c.Name == "invoke" || c.Name == "call") && len(args) >= 2:
		id := b.p.methodID(h.class, h.member, 0)
		call := &ir.Call{Callee: h.class + "." + h.member, Name: h.member, HasRecv: true, RecvType: h.class}
		if id != "" {
			call.Callee, call.Target = id, id
		}
		return b.emitCall(n, call, args[1:], ""), true
	case h.kind == 'c' && c.Name == "newInstance":
		return b.emitCall(n, &ir.Call{Callee: h.class, Name: shortName(h.class), Construct: true}, args[1:], h.class), true
	}
	return ir.NoVar, false
}

// noteReflect records the handle a reflective call returns: Class.forName
// and getClass give a class; getDeclaredField, getMethod and their
// variants on a class give a field or method of it; a constructor handle
// stays the class. Proxy.newProxyInstance gives a proxy that runs the
// handler lambda.
func (b *builder) noteReflect(c *ir.Call, args []ir.VarID, dst ir.VarID) {
	switch c.Name {
	case "forName":
		if len(args) > 0 && strings.Contains(c.Callee+c.RecvType+c.RecvText, "Class") {
			if name, ok := b.constString(args[len(args)-1]); ok {
				b.markRefl(dst, reflHandle{kind: 'c', class: name})
			}
		}
		return
	case "getClass":
		if c.HasRecv && c.RecvType != "" {
			b.markRefl(dst, reflHandle{kind: 'c', class: c.RecvType})
		}
		return
	case "newProxyInstance":
		if len(args) > 0 {
			if cb, ok := b.lambdas[args[len(args)-1]]; ok {
				if b.proxies == nil {
					b.proxies = map[ir.VarID]ir.VarID{}
				}
				b.proxies[dst] = cb
			}
		}
		return
	}
	if !c.HasRecv || len(args) == 0 {
		return
	}
	h, ok := b.handle(args[0])
	if !ok || h.kind != 'c' {
		return
	}
	switch c.Name {
	case "getDeclaredField", "getField", "getDeclaredMethod", "getMethod":
		if len(args) < 2 {
			return
		}
		if name, ok := b.constString(args[1]); ok {
			kind := byte('m')
			if strings.HasSuffix(c.Name, "Field") {
				kind = 'f'
			}
			b.markRefl(dst, reflHandle{kind: kind, class: h.class, member: name})
		}
	case "getDeclaredConstructor", "getConstructor":
		b.markRefl(dst, h)
	}
}

func (b *builder) finish() *ir.Func {
	if b.escaped != ir.NoVar {
		// What the function throws, from wherever it is thrown.
		b.fn.NewBlock(true)
		b.fn.Emit(ir.Instr{Op: ir.OpReturn, Dst: ir.NoVar, Args: []ir.VarID{b.escaped}, Throw: true, Pos: b.fn.Pos})
	}
	b.p.mod.Funcs = append(b.p.mod.Funcs, b.fn)
	return b.fn
}

// ---- tree helpers ----

// named returns the named children of n. An ERROR node (syntax the
// grammar could not parse) is transparent: its children take its place, so
// declarations and statements inside it are still lowered.
func named(n *sitter.Node) []*sitter.Node {
	if n == nil {
		return nil
	}
	cnt := int(n.NamedChildCount())
	out := make([]*sitter.Node, 0, cnt)
	for i := 0; i < cnt; i++ {
		c := n.NamedChild(i)
		if c.Type() == "ERROR" {
			out = append(out, named(c)...)
			continue
		}
		out = append(out, c)
	}
	return out
}

// syntaxErrors counts the ERROR and missing nodes under n and returns the
// first one's line.
func syntaxErrors(n *sitter.Node) (count, line int) {
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		if c.IsError() || c.IsMissing() {
			if count == 0 {
				line = int(c.StartPoint().Row) + 1
			}
			count++
			if c.IsMissing() {
				return
			}
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			walk(c.Child(i))
		}
	}
	if n != nil && n.HasError() {
		walk(n)
	}
	return count, line
}

// fieldChildren returns the children of n stored under a field name, for
// fields that repeat (a for loop's init and update clauses).
func fieldChildren(n *sitter.Node, field string) []*sitter.Node {
	var out []*sitter.Node
	if n == nil {
		return nil
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		if n.FieldNameForChild(i) == field {
			out = append(out, n.Child(i))
		}
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
