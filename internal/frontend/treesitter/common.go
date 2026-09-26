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
	"strconv"
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
	// closureSeq numbers the closures of each function.
	closureSeq map[string]int
}

func newProgram(lang string, o frontend.Options) *program {
	return &program{lang: lang, opts: o, classes: map[string]*classInfo{}, byShort: map[string][]*classInfo{},
		funcs: map[string]bool{}, top: map[string]string{}, ext: map[string][]string{}, modules: map[string]bool{}, mod: &ir.Module{Lang: lang},
		consts: map[string]bool{}, getters: map[string]string{}, closureSeq: map[string]int{}}
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
	p     *program
	f     *srcFile
	cls   *classInfo
	fn    *ir.Func
	scope map[string]ir.VarID
	this  ir.VarID
	names map[string]ir.VarID // unresolved identifiers read as values
	// closures maps variables holding a closure to its function ID.
	closures map[ir.VarID]string
	kwargs   map[ir.VarID]string // keyword-argument variables -> parameter name

	// Closures are lowered as functions of their own. While a closure body
	// is lowered, outer is the enclosing function's builder: a name the
	// closure reads from it becomes a capture parameter (captured maps the
	// outer variable to it), and binds lists the outer variables in
	// capture order.
	outer    *builder
	captured map[ir.VarID]ir.VarID
	binds    []ir.VarID
	// declared lists the names a Python nested function declares
	// nonlocal or global: assigning them writes the enclosing variable.
	declared map[string]bool

	// Control flow. terminated is set once the current path has returned;
	// what follows it is unreachable.
	terminated bool
	targets    []*jumpTarget // enclosing loops and switches, innermost last
	label      string        // label of the statement being lowered

	// Exceptions. tries holds the enclosing try bodies, innermost last;
	// caught is the exception the handler being lowered binds.
	tries  []*tryBody
	caught ir.VarID

	// JVM reflection: variables holding a Class, Field or Method handle,
	// and proxies with the invocation handler closure they run.
	refl    map[ir.VarID]reflHandle
	proxies map[ir.VarID]ir.VarID
}

// tryBody collects the points of a try body where an exception can be
// raised: blocks ending in a throw or a call, with the scope there. Its
// handlers are entered from them through exceptional edges.
type tryBody struct {
	sites []exit
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
	b := &builder{p: p, f: f, cls: cls, scope: map[string]ir.VarID{}, this: ir.NoVar, names: map[string]ir.VarID{}, closures: map[ir.VarID]string{},
		caught: ir.NoVar}
	b.fn = &ir.Func{ID: id, Name: name, Lang: p.lang, File: f.rel, Pos: b.pos(n)}
	b.fn.NewBlock() // entry
	return b
}

// lookup finds the variable a name refers to: a local, or, inside a
// closure, a variable of an enclosing function, which the closure then
// captures.
func (b *builder) lookup(name string) (ir.VarID, bool) {
	if v, ok := b.scope[name]; ok {
		return v, true
	}
	if b.outer == nil {
		return ir.NoVar, false
	}
	ov, ok := b.outer.lookup(name)
	if !ok {
		return ir.NoVar, false
	}
	v := b.capture(name, ov)
	b.scope[name] = v
	return v, true
}

// capture makes outer variable ov available in the closure being lowered
// as a capture parameter.
func (b *builder) capture(name string, ov ir.VarID) ir.VarID {
	if v, ok := b.captured[ov]; ok {
		return v
	}
	ovar := b.outer.fn.Vars[ov]
	v := b.fn.AddCapture(name, ovar.Type, ovar.Pos)
	b.captured[ov] = v
	b.binds = append(b.binds, ov)
	// What the builder knows about the value holds inside the closure too.
	if id, ok := b.outer.closures[ov]; ok {
		b.closures[v] = id
	}
	if r, ok := b.outer.refl[ov]; ok {
		b.markRefl(v, r)
	}
	if h, ok := b.outer.proxies[ov]; ok {
		if b.proxies == nil {
			b.proxies = map[ir.VarID]ir.VarID{}
		}
		b.proxies[v] = b.capture("", h)
	}
	return v
}

// isCapture reports whether v is a capture parameter of the function.
func (b *builder) isCapture(v ir.VarID) bool {
	for _, c := range b.captured {
		if c == v {
			return true
		}
	}
	return false
}

// cell marks a variable as a location that is written by weak updates.
func (b *builder) cell(v ir.VarID) {
	if v >= 0 && int(v) < len(b.fn.Vars) && !b.fn.Vars[v].IsConst() {
		b.fn.Vars[v].Cell = true
	}
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
	return v
}

// redefine gives a local a new version for a plain assignment (x = v):
// reads after it see the returned variable, reads before it keep the old
// one, so a value that is overwritten no longer reaches later sinks. A
// closure assigning a variable it captured writes the enclosing
// function's variable, which may be read at any time: the capture is a
// cell and the assignment a weak update of it.
func (b *builder) redefine(name string, old ir.VarID, typ string, n *sitter.Node) ir.VarID {
	if old == b.this || b.isCapture(old) {
		b.cell(old)
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

// join merges the scopes at the ends of alternative paths, which must be
// the predecessors of the current block: a name bound to different
// versions, or bound on only some paths (Python, JS var and a missed block
// scope all leave it visible), gets a phi of the versions arriving from
// each path.
func (b *builder) join(n *sitter.Node, paths ...exit) {
	out := map[string]ir.VarID{}
	names := map[string]bool{}
	for _, p := range paths {
		for name := range p.scope {
			names[name] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		var args []ir.VarID
		var from []int32
		same := true
		for _, p := range paths {
			v, ok := p.scope[name]
			if !ok {
				same = false
				continue
			}
			if len(args) > 0 && v != args[0] {
				same = false
			}
			args, from = append(args, v), append(from, p.block)
		}
		if same {
			out[name] = args[0]
			continue
		}
		phi := b.fn.Named(name, b.fn.Vars[args[0]].Type, b.pos(n))
		b.fn.Phi(phi, b.pos(n), args, from)
		b.propagate(phi, args...)
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
// of them return, what follows is unreachable. It returns the arms' entry
// blocks and the join block.
func (b *builder) branches(n *sitter.Node, skippable bool, arms ...func()) (starts []int32, join int32) {
	entry, from, dead := b.snapshot(), b.fn.CurBlock(), b.terminated
	var ends []exit
	if skippable || len(arms) == 0 {
		ends = append(ends, exit{entry, from})
	}
	for _, arm := range arms {
		b.scope = maps.Clone(entry)
		b.terminated = false
		starts = append(starts, b.newBlock(from))
		arm()
		if !b.terminated {
			ends = append(ends, b.here())
		}
	}
	join = b.newBlock(blocksOf(ends)...)
	b.terminated = dead || len(ends) == 0
	if len(ends) == 0 {
		b.scope = entry
		return starts, join
	}
	b.join(n, ends...)
	return starts, join
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
	// cond, when set, lowers the condition tested before each iteration
	// (while, for): a test block after the header branches on it to the
	// body or out of the loop.
	cond func() ir.VarID
	// post, when set, lowers the condition tested after each iteration
	// (do-while, repeat-while): the end of the body branches on it back
	// to the header or out of the loop, and the header has no exit.
	post func() ir.VarID
}

// loopWith lowers a loop. A header block, which the end of the body and
// every continue loop back to, leads to the body and to the exit. A local the body redefines gets
// a phi at the start of the header merging the value from before the loop
// with the value at each back edge; reads in the body are rewritten to it.
// The code after the loop joins the header's exit with every break.
func (b *builder) loopWith(n *sitter.Node, spec loopSpec) {
	entry, dead := b.snapshot(), b.terminated
	pre := b.fn.CurBlock()
	t := &jumpTarget{label: b.takeLabel(), loop: true}
	head := b.newBlock(pre)
	start := len(b.fn.Instrs)
	// The header holds only the phis; the test and the body start after
	// it.
	b.newBlock(head)
	b.terminated = false
	test, testCond := int32(-1), ir.NoVar
	var testScope map[string]ir.VarID
	if spec.cond != nil && !spec.infinite {
		testCond = spec.cond()
		test, testScope = b.fn.CurBlock(), b.snapshot()
		b.newBlock(test)
	}
	bodyStart := b.fn.CurBlock()
	b.targets = append(b.targets, t)
	spec.body()
	var post exit
	postCond := ir.NoVar
	if spec.post != nil && !spec.infinite && !b.terminated {
		postCond = spec.post()
		post = b.here()
	}
	end := len(b.fn.Instrs)
	b.targets = b.targets[:len(b.targets)-1]
	backs := t.cont
	if !b.terminated {
		backs = append(backs, b.here())
	}
	for _, bk := range backs {
		b.fn.Edge(bk.block, head)
	}

	// Header phis. A name bound for the first time in the body gets one
	// too when it stays visible after the loop (Python, JS var): it
	// merges the values the back edges bring.
	pos := b.pos(n)
	names := map[string]bool{}
	for _, bk := range backs {
		for name := range bk.scope {
			names[name] = true
		}
	}
	rename := map[ir.VarID]ir.VarID{}
	headScope := maps.Clone(entry)
	var phis []ir.Instr
	for _, name := range slices.Sorted(maps.Keys(names)) {
		old, before := entry[name]
		changed := false
		for _, bk := range backs {
			if v, ok := bk.scope[name]; ok && v != old {
				changed = true
			}
		}
		if !changed {
			continue
		}
		var typ string
		if before {
			typ = b.fn.Vars[old].Type
		}
		h := b.fn.Named(name, typ, pos)
		phi := ir.Instr{Op: ir.OpPhi, Dst: h, Pos: pos, Block: head}
		if before {
			phi.Args, phi.From = append(phi.Args, old), append(phi.From, pre)
			rename[old] = h
		}
		for _, bk := range backs {
			v, ok := bk.scope[name]
			switch {
			case !ok:
				continue
			case before && v == old:
				v = h // unchanged on this path: the header value
			}
			phi.Args, phi.From = append(phi.Args, v), append(phi.From, bk.block)
		}
		phis = append(phis, phi)
		headScope[name] = h
	}
	for i := start; i < end; i++ {
		in := &b.fn.Instrs[i]
		for j, a := range in.Args {
			if h, ok := rename[a]; ok {
				in.Args[j] = h
			}
		}
	}
	for blk := int(head); blk < len(b.fn.Blocks); blk++ {
		if h, ok := rename[b.fn.Blocks[blk].Cond]; ok && b.fn.Blocks[blk].Term == ir.TermIf {
			b.fn.Blocks[blk].Cond = h
		}
	}
	for i := range phis {
		// A back edge value read before its redefinition is the header's.
		for j, a := range phis[i].Args {
			if h, ok := rename[a]; ok && phis[i].From[j] != pre {
				phis[i].Args[j] = h
			}
		}
		for _, a := range phis[i].Args {
			b.propagate(phis[i].Dst, a)
		}
	}
	b.fn.Instrs = slices.Insert(b.fn.Instrs, start, phis...)
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
	switch {
	case spec.infinite:
	case postCond != ir.NoVar:
		// Leaving after the body when the condition is false.
		out := b.newBlock(post.block)
		b.scope = remap(post.scope)
		b.terminated = false
		b.branch(post.block, postCond, head, out)
		exits = append(exits, b.here())
	case spec.post != nil:
		// The body always ends in a jump: only break leaves.
	default:
		// Leaving from the header (or the test after it), with the
		// header's versions.
		from, scope := head, headScope
		if test >= 0 {
			from, scope = test, remap(testScope)
		}
		out := b.newBlock(from)
		b.scope = scope
		b.terminated = false
		if test >= 0 {
			b.branch(test, testCond, bodyStart, out)
		}
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
		b.scope = headScope // while(true) without break: nothing follows
		return
	}
	b.join(n, exits...)
}

// switchCases lowers the cases of a switch statement. With fallthrough (C,
// Java and JavaScript switch statements, fallsThrough), a case that does not end in break
// continues into the next one; break leaves the switch. exhaustive means a
// default case exists, so no path skips every case.
//
// tests, when given, holds each case's test: a function lowering the
// condition under which the case is entered (subject == value, or the
// condition of a when without subject), or nil for the default case. The
// tests run in order, each in a block that branches to its case or to the
// next test; the default case, or the end of the switch, follows the
// last. A test returning NoVar is not known: its block goes to both.
//
// A Kotlin when is not a break target: break inside it leaves the
// enclosing loop (noBreak).
func (b *builder) switchCases(n *sitter.Node, s switchSpec) {
	fallsThrough, exhaustive, cases, tests := s.fallsThrough, s.exhaustive, s.cases, s.tests
	from, dead := b.fn.CurBlock(), b.terminated
	// The chain of tests: case i is entered from enter[i].
	enter := make([]int32, len(cases))
	conds := make([]ir.VarID, len(cases))
	for i := range enter {
		enter[i], conds[i] = from, ir.NoVar
	}
	var falses []int32
	if len(tests) == len(cases) {
		for i, test := range tests {
			if test == nil {
				enter[i] = -1
				continue
			}
			conds[i] = test()
			enter[i] = b.fn.CurBlock()
			falses = append(falses, b.newBlock(enter[i]))
		}
		from = b.fn.CurBlock() // every test failed
		for i := range enter {
			if enter[i] < 0 {
				enter[i] = from
			}
		}
	}
	entry := b.snapshot()
	t := &jumpTarget{}
	if !s.noBreak {
		t.label = b.takeLabel()
		b.targets = append(b.targets, t)
	}
	var ends []exit
	var prev *exit
	next := 0
	for i, c := range cases {
		starts := []exit{{entry, enter[i]}}
		if prev != nil {
			starts = append(starts, *prev)
		}
		start := b.newBlock(blocksOf(starts)...)
		if len(tests) == len(cases) && tests[i] != nil {
			b.branch(enter[i], conds[i], start, falses[next])
			next++
		}
		b.terminated = false
		b.join(n, starts...)
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
	if !s.noBreak {
		b.targets = b.targets[:len(b.targets)-1]
	}
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
	b.join(n, ends...)
}

// switchSpec describes a switch for switchCases.
type switchSpec struct {
	fallsThrough, exhaustive, noBreak bool
	cases                             []func()
	tests                             []func() ir.VarID
}

// matches lowers a case test: subject equals one of values. With no
// subject (a when without one) the value is the condition itself.
func (b *builder) matches(n *sitter.Node, subject ir.VarID, values ...ir.VarID) ir.VarID {
	var tests []ir.VarID
	for _, v := range values {
		if v == ir.NoVar {
			return ir.NoVar // a pattern the builder does not read: unknown
		}
		if subject == ir.NoVar {
			tests = append(tests, v)
			continue
		}
		eq := b.temp(n)
		b.fn.Compute(eq, b.pos(n), "==", subject, v)
		tests = append(tests, eq)
	}
	switch len(tests) {
	case 0:
		return ir.NoVar
	case 1:
		return tests[0]
	}
	any := b.temp(n)
	b.fn.Compute(any, b.pos(n), "||", tests...)
	return any
}

// ifElse lowers an if statement whose condition was already lowered to c:
// then and els (nil without an else) are alternative paths, and the
// current block ends with a branch on c. A constant condition (see truth)
// leaves out the arm that cannot run.
func (b *builder) ifElse(n, cond *sitter.Node, c ir.VarID, then, els func()) {
	v, known := b.truth(cond)
	from := b.fn.CurBlock()
	switch {
	case known && v:
		b.branches(n, false, then)
	case known && els != nil:
		b.branches(n, false, els)
	case known:
		// if false { ... } without else: nothing runs.
	case els != nil:
		starts, _ := b.branches(n, false, then, els)
		b.branch(from, c, starts[0], starts[1])
	default:
		starts, join := b.branches(n, true, then)
		b.branch(from, c, starts[0], join)
	}
}

// branch ends block from with a branch on c, when c is known.
func (b *builder) branch(from int32, c ir.VarID, ifTrue, ifFalse int32) {
	if c >= 0 && int(c) < len(b.fn.Vars) && ifTrue != ifFalse {
		b.fn.Branch(from, c, ifTrue, ifFalse)
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
	if def == nil || def.Op != ir.OpAssign || len(def.Args) != 1 {
		return false, false
	}
	return b.constTruth(def.Args[0], depth+1)
}

// tryCatch lowers try/catch/finally. Every call and throw in the body
// ends its block, with an exceptional edge to a dispatch block that starts
// with the caught exception (OpCatch) and joins the scopes at those
// points; each handler is a path from it. An empty block before the body
// is such a point too, for exceptions the runtime raises anywhere in it.
// The finally block runs after the body or a handler.
func (b *builder) tryCatch(n *sitter.Node, body func(), handlers []func(), finally func()) {
	entry, from, dead := b.snapshot(), b.fn.CurBlock(), b.terminated
	first := b.newBlock(from)
	b.newBlock(first)
	b.terminated = false
	var t *tryBody
	if len(handlers) > 0 {
		t = &tryBody{}
		b.tries = append(b.tries, t)
	}
	body()
	var ends []exit
	if t != nil {
		b.tries = b.tries[:len(b.tries)-1]
	}
	if !b.terminated {
		ends = append(ends, b.here())
	}
	if t != nil {
		sites := append([]exit{{entry, first}}, t.sites...)
		dispatch := b.newBlock()
		for _, st := range sites {
			b.fn.ExcEdge(st.block, dispatch)
		}
		b.terminated = false
		b.join(n, sites...)
		caught := b.fn.Named("", "", b.pos(n))
		b.fn.Emit(ir.Instr{Op: ir.OpCatch, Dst: caught, Pos: b.pos(n)})
		hentry := b.snapshot()
		saved := b.caught
		b.caught = caught
		for _, h := range handlers {
			b.scope = maps.Clone(hentry)
			b.terminated = false
			b.newBlock(dispatch)
			h()
			if !b.terminated {
				ends = append(ends, b.here())
			}
		}
		b.caught = saved
	}
	b.newBlock(blocksOf(ends)...)
	b.terminated = dead || len(ends) == 0
	if len(ends) == 0 {
		b.scope = entry
	} else {
		b.join(n, ends...)
	}
	if finally != nil {
		finally()
	}
}

// mayThrow ends the current block after an instruction that may throw
// inside a try body: the handlers are entered from here.
func (b *builder) mayThrow() {
	if len(b.tries) == 0 {
		return
	}
	t := b.tries[len(b.tries)-1]
	t.sites = append(t.sites, b.here())
	b.newBlock(b.fn.CurBlock())
}

// resultName is the scope entry that the arms of a construct with a value
// (Kotlin if and when, a Java switch expression) bind their value to, so
// that the join merges the arms' values with a phi.
const resultName = "#result"

// valued lowers a construct whose arms call setResult, and returns the
// value it has after them.
func (b *builder) valued(n *sitter.Node, lower func()) ir.VarID {
	saved, had := b.scope[resultName]
	delete(b.scope, resultName)
	lower()
	v, ok := b.scope[resultName]
	delete(b.scope, resultName)
	if had {
		b.scope[resultName] = saved
	}
	if !ok {
		return b.temp(n)
	}
	if b.fn.Vars[v].Name == resultName {
		b.fn.Vars[v].Name = "" // a phi of the arms' values
	}
	return v
}

// setResult binds the value of the arm being lowered.
func (b *builder) setResult(v ir.VarID) {
	if v != ir.NoVar {
		b.scope[resultName] = v
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
	if v, ok := b.lookup(name); ok {
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
	b.propagate(dst, args...)
}

// propagate carries what the builder knows about values through a copy,
// cast or merge: reflective handles, proxies and closures stay what they
// are, so calling the copy of a closure (show = { log(it) }; show(x))
// runs it.
func (b *builder) propagate(dst ir.VarID, args ...ir.VarID) {
	if dst < 0 {
		return
	}
	for _, a := range args {
		if r, ok := b.refl[a]; ok {
			b.markRefl(dst, r)
		}
		if h, ok := b.proxies[a]; ok {
			b.proxies[dst] = h
		}
		if id, ok := b.closures[a]; ok {
			if _, has := b.closures[dst]; !has {
				b.closures[dst] = id
			}
		}
	}
}

// compute is assign for a new value built from the arguments' current
// state (concatenation, interpolation, arithmetic), not a reference to
// them. The operator is read off n.
func (b *builder) compute(dst ir.VarID, n *sitter.Node, args ...ir.VarID) {
	b.fn.Compute(dst, b.pos(n), b.operator(n), args...)
}

// logic lowers a boolean operation (a comparison, !, &&, ||, not, and,
// or): its result carries no data of the operands, but the analysis reads
// consent checks through it.
func (b *builder) logic(n *sitter.Node, args ...ir.VarID) ir.VarID {
	dst := b.temp(n)
	op := b.operator(n)
	if !ir.Logical(op) {
		op = "cmp"
	}
	b.fn.Compute(dst, b.pos(n), op, args...)
	return dst
}

// operator is the operator of an expression node, normalized: "!" for
// every negation, "&&" and "||" for the boolean connectives.
func (b *builder) operator(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	var op string
	for _, field := range []string{"operator", "operation"} {
		if o := n.ChildByFieldName(field); o != nil {
			op = strings.TrimSpace(b.text(o))
			break
		}
	}
	switch n.Type() {
	case "not_operator":
		op = "!"
	case "conjunction_expression":
		op = "&&"
	case "disjunction_expression":
		op = "||"
	case "prefix_expression", "unary_expression":
		if t := strings.TrimSpace(b.text(n)); strings.HasPrefix(t, "!") && !strings.HasSuffix(t, "!!") {
			op = "!"
		}
	case "comparison_operator", "comparison_expression", "equality_expression", "check_expression":
		if op == "" {
			op = "=="
		}
	}
	switch op {
	case "not":
		op = "!"
	case "and":
		op = "&&"
	case "or":
		op = "||"
	}
	return op
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

// literalField is a property of an object or map literal with a static key.
type literalField struct {
	name string
	val  ir.VarID
	n    *sitter.Node
}

// objectLiteral lowers an object or map literal: a new value holding the
// merged parts (spreads, computed keys), then a store of each field. A
// function-valued field stays merged into the value, so it is called only
// through that object ({run: () => ...}.run()), not by every method call
// of that name on an object of unknown type.
func (b *builder) objectLiteral(n *sitter.Node, parts []ir.VarID, fields []literalField) ir.VarID {
	var data []literalField
	for _, f := range fields {
		if _, fn := b.closures[f.val]; fn {
			parts = append(parts, f.val)
			continue
		}
		data = append(data, f)
	}
	dst := b.temp(n)
	if len(parts) > 0 {
		b.assign(dst, n, parts...)
	} else {
		b.fn.Emit(ir.Instr{Op: ir.OpNew, Dst: dst, Call: &ir.Call{Name: "{}"}, Pos: b.pos(n)})
	}
	for _, f := range data {
		b.store(dst, f.name, "", f.val, f.n)
	}
	return dst
}

func (b *builder) store(obj ir.VarID, field, owner string, val ir.VarID, n *sitter.Node) {
	if obj == ir.NoVar || val == ir.NoVar {
		return
	}
	b.fn.Emit(ir.Instr{Op: ir.OpStore, Dst: ir.NoVar, Args: []ir.VarID{obj, val}, Field: field, Owner: owner, Pos: b.pos(n)})
}

func (b *builder) ret(n *sitter.Node, vals ...ir.VarID) {
	b.fn.Return(b.pos(n), vals...)
	// Whatever follows on this path is unreachable.
	b.terminated = true
	b.newBlock()
}

// yieldValue lowers a generator's yield: the value is produced to the
// caller, like a return, but the function goes on.
func (b *builder) yieldValue(v ir.VarID, n *sitter.Node) {
	if v != ir.NoVar {
		b.fn.Emit(ir.Instr{Op: ir.OpYield, Dst: ir.NoVar, Args: []ir.VarID{v}, Pos: b.pos(n)})
	}
}

// newBlock starts a new basic block with edges from preds.
func (b *builder) newBlock(preds ...int32) int32 {
	return b.fn.NewBlock(preds...)
}

// throwValue lowers throw/raise v: the block ends, and the exception goes
// to the enclosing try's handlers or leaves the function.
func (b *builder) throwValue(v ir.VarID, n *sitter.Node) {
	if v == ir.NoVar {
		v = b.temp(n)
	}
	b.fn.Throw(b.pos(n), v)
	if len(b.tries) > 0 {
		t := b.tries[len(b.tries)-1]
		t.sites = append(t.sites, b.here())
	}
	b.terminated = true
	b.newBlock()
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
	switch {
	case c.HasRecv && len(args) > 0 && hasKey(b.proxies, args[0]):
		// A call on a proxy runs its invocation handler with the proxy,
		// the method and the arguments.
		all := b.temp(n)
		b.assign(all, n, args[1:]...)
		c = &ir.Call{Name: c.Name, RecvText: c.RecvText, Indirect: true}
		args = []ir.VarID{b.proxies[args[0]], args[0], b.constVar(c.Name, n), all}
	case c.Target == "" && !c.HasRecv:
		// Calling a closure held in a variable: show(email).
		v, local := b.scope[c.Name]
		if !local && b.closureInScope(c.Name) {
			v, local = b.lookup(c.Name)
		}
		if local && hasKey(b.closures, v) {
			c.Indirect = true
			args = append([]ir.VarID{v}, args...)
		}
	case c.Target == "" && c.HasRecv && len(args) > 0 && hasKey(b.closures, args[0]):
		// show.invoke(email), show.accept(email), show.call(email).
		c.HasRecv, c.Indirect = false, true
	}
	for i, a := range args {
		if name, ok := b.kwargs[a]; ok {
			if c.ArgNames == nil {
				c.ArgNames = make([]string, len(args))
			}
			c.ArgNames[i] = name
		}
	}
	b.fn.Emit(ir.Instr{Op: ir.OpCall, Dst: dst, Args: args, Call: c, Pos: b.pos(n)})
	b.mayThrow()
	return dst
}

// closureInScope reports whether name is an enclosing function's variable
// holding a closure.
func (b *builder) closureInScope(name string) bool {
	for o := b.outer; o != nil; o = o.outer {
		if v, ok := o.scope[name]; ok {
			return hasKey(o.closures, v)
		}
	}
	return false
}

func hasKey[K comparable, V any](m map[K]V, k K) bool {
	_, ok := m[k]
	return ok
}

// newObject emits the construction of an object of class cls, running its
// constructor when it is code under analysis.
func (b *builder) newObject(n *sitter.Node, cls string, args []ir.VarID, resultType string) ir.VarID {
	dst := b.fn.Named("", resultType, b.pos(n))
	c := &ir.Call{Callee: cls, Name: shortName(cls), Target: b.p.ctorID(cls)}
	for i, a := range args {
		if name, ok := b.kwargs[a]; ok {
			if c.ArgNames == nil {
				c.ArgNames = make([]string, len(args))
			}
			c.ArgNames[i] = name
		}
	}
	b.fn.Emit(ir.Instr{Op: ir.OpNew, Dst: dst, Args: args, Call: c, Pos: b.pos(n)})
	b.mayThrow()
	return dst
}

// lambda lowers a lambda, closure, anonymous class or local function as a
// function of its own, with params (paramNames, or it when implicitIt) as
// its parameters, and returns a variable holding the closure. Names the
// body reads from the enclosing function become capture parameters, and
// the closure binds the enclosing variables to them; this is captured
// whenever there is one. body returns the value of an expression body.
func (b *builder) lambda(n *sitter.Node, params []*sitter.Node, paramNames []string, implicitIt bool, body func() ir.VarID) ir.VarID {
	b.p.closureSeq[b.fn.ID]++
	id := fmt.Sprintf("%s$%d", b.fn.ID, b.p.closureSeq[b.fn.ID])
	outer := *b
	inner := builder{p: b.p, f: b.f, cls: b.cls, scope: map[string]ir.VarID{}, this: ir.NoVar, names: map[string]ir.VarID{},
		closures: map[ir.VarID]string{}, caught: ir.NoVar, outer: &outer, captured: map[ir.VarID]ir.VarID{}}
	inner.fn = &ir.Func{ID: id, Name: b.fn.Name + "$" + strconv.Itoa(b.p.closureSeq[b.fn.ID]), Lang: b.p.lang, File: b.f.rel, Pos: b.pos(n), Parent: b.fn.ID}
	inner.fn.NewBlock()
	*b = inner
	for i, name := range paramNames {
		b.param(name, "", params[i])
	}
	if implicitIt && len(paramNames) == 0 {
		b.param("it", "", n)
	}
	if outer.this != ir.NoVar {
		b.this = b.capture("this", outer.this)
	}
	last := body()
	if !b.terminated && last != ir.NoVar {
		b.fn.Return(b.pos(n), last)
	}
	b.inputsFirst()
	b.p.mod.Funcs = append(b.p.mod.Funcs, b.fn)
	binds := b.binds
	*b = outer
	dst := b.temp(n)
	b.fn.Emit(ir.Instr{Op: ir.OpClosure, Dst: dst, Args: binds, Func: id, Pos: b.pos(n)})
	b.closures[dst] = id
	return dst
}

// inputsFirst orders a closure's parameters as the IR requires: its own
// parameters, then the captures in binding order.
func (b *builder) inputsFirst() {
	var in, caps []ir.VarID
	for _, p := range b.fn.Params {
		if b.isCapture(p) {
			continue
		}
		in = append(in, p)
	}
	for _, ov := range b.binds {
		caps = append(caps, b.captured[ov])
	}
	b.fn.Params = append(in, caps...)
	for i, p := range b.fn.Params {
		b.fn.Vars[p].Param = i
	}
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
		return b.newObject(n, h.class, args[1:], h.class), true
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
			if h := args[len(args)-1]; hasKey(b.closures, h) {
				if b.proxies == nil {
					b.proxies = map[ir.VarID]ir.VarID{}
				}
				b.proxies[dst] = h
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
	b.p.mod.Funcs = append(b.p.mod.Funcs, b.fn)
	return b.fn
}

// classTable is the class table of the program: every class, interface,
// protocol and object with its supertypes and methods.
func (p *program) classTable() []*ir.Class {
	var out []*ir.Class
	for _, name := range slices.Sorted(maps.Keys(p.classes)) {
		c := p.classes[name]
		k := &ir.Class{Name: c.name, Lang: p.lang, Methods: maps.Clone(c.methods)}
		if c.file != nil {
			k.File = c.file.rel
		}
		for _, s := range c.supers {
			if sc := p.class(s); sc != nil {
				s = sc.name
			}
			if !slices.Contains(k.Supers, s) {
				k.Supers = append(k.Supers, s)
			}
		}
		out = append(out, k)
	}
	return out
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
