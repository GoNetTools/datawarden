// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/swift"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// NewSwift returns the Swift frontend.
func NewSwift(o frontend.Options) frontend.Frontend { return &swFrontend{opts: o} }

type swFrontend struct{ opts frontend.Options }

func (fe *swFrontend) Lang() string { return lang.Swift }

// swProgram lowers Swift. Swift imports whole modules, so types are named
// as written ("SentrySDK", "UserDefaults.standard") and rules use those
// names; functions are "<name>" and methods "<Type>.<name>", with the
// methods of extensions merged into their type.
type swProgram struct {
	*program
	static  map[string]bool // static and class methods
	lowered map[string]int  // function ids already lowered (overloads)
	decls   map[string]*ir.TypeDecl
}

func (fe *swFrontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	sp := &swProgram{program: newProgram(lang.Swift, fe.opts), static: map[string]bool{}, lowered: map[string]int{}, decls: map[string]*ir.TypeDecl{}}
	sp.parse(ctx, files, swift.GetLanguage())
	for _, f := range sp.files {
		sp.collect(f, f.root, "")
	}
	for _, c := range sp.classes {
		for k, t := range c.fields {
			c.fields[k] = sp.resolveType(c.file, t)
		}
	}
	for _, td := range sp.decls {
		if len(td.Fields) > 0 {
			sp.mod.Types = append(sp.mod.Types, td)
		}
	}
	for _, f := range sp.files {
		sp.lowerFile(f)
	}
	return sp.mod, nil
}

// swKeyword is the declaration keyword of a class_declaration: class,
// struct, enum, extension or actor.
func swKeyword(f *srcFile, d *sitter.Node) string {
	for i := 0; i < int(d.ChildCount()); i++ {
		c := d.Child(i)
		if c.IsNamed() {
			continue
		}
		switch t := f.text(c); t {
		case "class", "struct", "enum", "extension", "actor":
			return t
		}
	}
	return ""
}

// swTypeName reduces a type node to the named type it holds: User? and
// User! are User; [User] and (String) -> Void are not named types.
func swTypeName(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "type_annotation":
		for _, c := range named(n) {
			return swTypeName(f, c)
		}
	case "optional_type", "implicitly_unwrapped_type":
		for _, c := range named(n) {
			return swTypeName(f, c)
		}
	case "user_type":
		var parts []string
		for _, c := range named(n) {
			if c.Type() == "type_identifier" {
				parts = append(parts, f.text(c))
			}
		}
		return strings.Join(parts, ".")
	}
	return ""
}

func swIsType(n *sitter.Node) bool {
	switch n.Type() {
	case "user_type", "optional_type", "implicitly_unwrapped_type", "array_type", "dictionary_type", "function_type", "tuple_type":
		return true
	}
	return false
}

// swAttributes are the attribute names of a declaration (@Model, @objc).
func swAttributes(f *srcFile, d *sitter.Node) []string {
	var out []string
	for _, m := range allOf(d, "modifiers") {
		for _, a := range allOf(m, "attribute") {
			if t := firstOf(a, "user_type"); t != nil {
				out = append(out, swTypeName(f, t))
			}
		}
	}
	return out
}

func swHasModifier(f *srcFile, d *sitter.Node, words ...string) bool {
	for _, m := range allOf(d, "modifiers") {
		for _, c := range named(m) {
			for _, w := range words {
				if f.text(c) == w {
					return true
				}
			}
		}
	}
	return false
}

var swEntityBases = map[string]bool{"NSManagedObject": true, "Object": true, "Model": true}

func (sp *swProgram) classFor(name string, f *srcFile) *classInfo {
	if c, ok := sp.classes[name]; ok {
		return c
	}
	c := &classInfo{name: name, short: shortName(name), file: f, fields: map[string]string{}, methods: map[string]string{}}
	sp.addClass(c)
	return c
}

// collect indexes the declarations of a scope (pass 1).
func (sp *swProgram) collect(f *srcFile, n *sitter.Node, outer string) {
	for _, d := range named(n) {
		switch d.Type() {
		case "function_declaration":
			if outer == "" {
				name := f.text(d.ChildByFieldName("name"))
				sp.funcs[name] = true
				sp.top[name] = name
			}
		case "class_declaration":
			sp.collectClass(f, d, outer)
		case "protocol_declaration":
			// Protocols have no bodies to analyse, but calls on one may
			// run any conforming type's method.
			if name := strings.TrimSpace(f.text(d.ChildByFieldName("name"))); name != "" {
				sp.classFor(name, f)
			}
		}
	}
}

func (sp *swProgram) collectClass(f *srcFile, d *sitter.Node, outer string) {
	kw := swKeyword(f, d)
	nameNode := d.ChildByFieldName("name")
	short := f.text(nameNode)
	if nameNode != nil && nameNode.Type() == "user_type" {
		short = swTypeName(f, nameNode)
	}
	if short == "" {
		return
	}
	name := short
	if outer != "" {
		name = outer + "." + short
	}
	ci := sp.classFor(name, f)
	if kw != "extension" {
		ci.file = f
	}
	var supers []string
	for _, s := range allOf(d, "inheritance_specifier") {
		if t := s.ChildByFieldName("inherits_from"); t != nil {
			supers = append(supers, swTypeName(f, t))
		}
	}
	ci.supers = append(ci.supers, supers...)
	body := d.ChildByFieldName("body")
	if kw == "enum" {
		if short == "CodingKeys" && outer != "" {
			sp.codingKeys(f, outer, body)
		}
		sp.collect(f, body, name)
		for _, m := range allOf(body, "function_declaration") {
			sp.collectMethod(f, ci, m)
		}
		return
	}
	td := sp.decls[name]
	if td == nil && kw != "extension" {
		td = &ir.TypeDecl{Name: name, Kind: "class", Lang: lang.Swift, Annotations: swAttributes(f, d), Pos: posOf(f, d)}
		sp.decls[name] = td
	}
	for _, m := range named(body) {
		switch m.Type() {
		case "property_declaration":
			pat := m.ChildByFieldName("name")
			id := firstOf(pat, "simple_identifier")
			if pat != nil && id == nil {
				id = pat.ChildByFieldName("bound_identifier")
			}
			if id == nil {
				continue
			}
			fn := f.text(id)
			if m.ChildByFieldName("computed_value") != nil {
				sp.getters[ci.name+"."+fn] = name + "." + fn // lowered as a getter
			}
			typ := swTypeName(f, firstOf(m, "type_annotation"))
			if typ == "" {
				if v := m.ChildByFieldName("value"); v != nil && v.Type() == "call_expression" {
					if callee := named(v); len(callee) > 0 && callee[0].Type() == "simple_identifier" && isUpperStart(f.text(callee[0])) {
						typ = f.text(callee[0])
					}
				}
			}
			ci.fields[fn] = typ
			if td != nil {
				td.Fields = append(td.Fields, ir.Field{Name: fn, Type: typ, Pos: posOf(f, m)})
			}
		case "function_declaration":
			sp.collectMethod(f, ci, m)
		case "init_declaration":
			id := name + ".init"
			sp.funcs[id] = true
			ci.methods["init"] = id
		case "class_declaration":
			sp.collectClass(f, m, name)
		}
	}
	if td == nil {
		return
	}
	attrs := td.Annotations
	switch {
	case containsStr(attrs, "Model") || containsStr(attrs, "objc") && anyIn(supers, swEntityBases):
		td.Kind = "entity"
	case anyIn(supers, swEntityBases):
		td.Kind = "entity"
	case !hasBehaviour(ci.methods) || kw == "struct" && anyIn(supers, map[string]bool{"Codable": true, "Decodable": true, "Encodable": true}):
		td.Kind = "data"
	}
}

func (sp *swProgram) collectMethod(f *srcFile, ci *classInfo, m *sitter.Node) {
	mn := f.text(m.ChildByFieldName("name"))
	id := ci.name + "." + mn
	sp.funcs[id] = true
	if _, dup := ci.methods[mn]; !dup {
		ci.methods[mn] = id
	}
	if swHasModifier(f, m, "static", "class") {
		sp.static[id] = true
	}
}

// codingKeys turns `case email = "email_address"` in a CodingKeys enum into
// the field's serialized name.
func (sp *swProgram) codingKeys(f *srcFile, owner string, body *sitter.Node) {
	td := sp.decls[owner]
	if td == nil {
		return
	}
	for _, e := range allOf(body, "enum_entry") {
		raw := e.ChildByFieldName("raw_value")
		if raw == nil {
			continue
		}
		name := f.text(e.ChildByFieldName("name"))
		for i := range td.Fields {
			if td.Fields[i].Name == name {
				if td.Fields[i].Tags == nil {
					td.Fields[i].Tags = map[string]string{}
				}
				td.Fields[i].Tags["json"] = swString(f, raw)
			}
		}
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func anyIn(xs []string, set map[string]bool) bool {
	for _, x := range xs {
		if set[shortName(x)] {
			return true
		}
	}
	return false
}

// swString is the text of a string literal without interpolations.
func swString(f *srcFile, n *sitter.Node) string {
	var sb strings.Builder
	for _, c := range named(n) {
		switch c.Type() {
		case "line_str_text", "multi_line_str_text", "raw_str_part", "str_escaped_char":
			sb.WriteString(f.text(c))
		}
	}
	return sb.String()
}

// uniqueID gives each lowered function its own id; overloads after the
// first get a #n suffix (calls resolve to the first).
func (sp *swProgram) uniqueID(id string) string {
	n := sp.lowered[id]
	sp.lowered[id] = n + 1
	if n == 0 {
		return id
	}
	return fmt.Sprintf("%s#%d", id, n+1)
}

func (sp *swProgram) lowerFile(f *srcFile) {
	var init *swBuilder
	for _, d := range named(f.root) {
		switch d.Type() {
		case "import_declaration", "protocol_declaration", "comment", "multiline_comment", "typealias_declaration":
		case "function_declaration":
			name := f.text(d.ChildByFieldName("name"))
			sp.lowerFunction(f, nil, name, name, d, true)
		case "class_declaration":
			sp.lowerClass(f, d, "")
		default:
			if init == nil {
				init = &swBuilder{builder: sp.newBuilder(f, nil, f.rel+":<init>", "<init>", d), sp: sp}
			}
			init.stmt(d)
		}
	}
	if init != nil && len(init.fn.Instrs) > 0 {
		init.finish()
	}
}

func (sp *swProgram) lowerClass(f *srcFile, d *sitter.Node, outer string) {
	nameNode := d.ChildByFieldName("name")
	short := f.text(nameNode)
	if nameNode != nil && nameNode.Type() == "user_type" {
		short = swTypeName(f, nameNode)
	}
	name := short
	if outer != "" {
		name = outer + "." + short
	}
	ci := sp.classes[name]
	if ci == nil {
		return
	}
	var fieldInit *swBuilder
	for _, m := range named(d.ChildByFieldName("body")) {
		switch m.Type() {
		case "function_declaration":
			mn := f.text(m.ChildByFieldName("name"))
			id := name + "." + mn
			sp.lowerFunction(f, ci, id, mn, m, sp.static[id])
		case "init_declaration":
			sp.lowerFunction(f, ci, name+".init", "init", m, false)
		case "class_declaration":
			sp.lowerClass(f, m, name)
		case "property_declaration":
			if cv := m.ChildByFieldName("computed_value"); cv != nil {
				// A computed property is a getter method.
				pat := m.ChildByFieldName("name")
				if id := firstOf(pat, "simple_identifier"); id != nil {
					sp.lowerBody(f, ci, name+"."+f.text(id), f.text(id), m, cv, false)
				}
				continue
			}
			v := m.ChildByFieldName("value")
			if v == nil {
				continue
			}
			if fieldInit == nil {
				b := sp.newBuilder(f, ci, name+".<fields>", "<fields>", m)
				b.addThis(name, m)
				fieldInit = &swBuilder{builder: b, sp: sp}
			}
			pat := m.ChildByFieldName("name")
			if id := firstOf(pat, "simple_identifier"); id != nil {
				fieldInit.store(fieldInit.this, f.text(id), name, fieldInit.expr(v), m)
			}
		}
	}
	if fieldInit != nil && len(fieldInit.fn.Instrs) > 0 {
		fieldInit.finish()
	}
}

func (sp *swProgram) lowerFunction(f *srcFile, cls *classInfo, id, name string, n *sitter.Node, static bool) {
	sp.lowerBody(f, cls, id, name, n, n.ChildByFieldName("body"), static)
}

func (sp *swProgram) lowerBody(f *srcFile, cls *classInfo, id, name string, decl, body *sitter.Node, static bool) {
	b := sp.newBuilder(f, cls, sp.uniqueID(id), name, decl)
	sb := &swBuilder{builder: b, sp: sp}
	if cls != nil && !static {
		b.addThis(cls.name, decl)
	}
	for _, p := range allOf(decl, "parameter") {
		pn, typ := swParam(f, p)
		b.param(pn, sp.resolveType(f, typ), p)
	}
	last := sb.stmt(body)
	if st := firstOf(body, "statements"); st != nil && len(named(st)) == 1 && last != ir.NoVar {
		b.ret(body, last) // single-expression body: an implicit return
	} else if body != nil && body.Type() == "computed_property" && last != ir.NoVar {
		b.ret(body, last)
	}
	b.finish()
}

// swParam returns a parameter's local name and type.
func swParam(f *srcFile, p *sitter.Node) (string, string) {
	name, typ := "", ""
	for i := 0; i < int(p.ChildCount()); i++ {
		c := p.Child(i)
		if !c.IsNamed() || p.FieldNameForChild(i) == "external_name" {
			continue
		}
		switch {
		case c.Type() == "simple_identifier" && name == "":
			name = f.text(c)
		case swIsType(c) && typ == "":
			typ = swTypeName(f, c)
		}
	}
	return name, typ
}

type swBuilder struct {
	*builder
	sp *swProgram
	// osLog is set while lowering the message of a Logger call, whose
	// interpolated values are redacted unless marked privacy: .public.
	osLog bool
}

var swLoggerMethods = map[string]bool{"debug": true, "info": true, "notice": true, "warning": true, "error": true, "fault": true,
	"critical": true, "log": true, "trace": true}

func (sb *swBuilder) stmt(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "function_body", "statements", "computed_property", "switch_entry",
		"defer_statement", "labeled_statement", "computed_getter":
		last := ir.NoVar
		for _, c := range named(n) {
			if c.Type() == "statement_label" { // outer: for ...
				sb.label = strings.TrimSuffix(sb.text(c), ":")
				continue
			}
			last = sb.stmt(c)
			sb.label = ""
		}
		return last
	case "property_declaration":
		v := ir.NoVar
		if val := n.ChildByFieldName("value"); val != nil {
			v = sb.expr(val)
		}
		typ := sb.sp.resolveType(sb.f, swTypeName(sb.f, firstOf(n, "type_annotation")))
		if typ == "" && v != ir.NoVar {
			typ = sb.fn.Vars[v].Type
		}
		sb.bindPattern(n.ChildByFieldName("name"), v, typ)
		return ir.NoVar
	case "assignment":
		return sb.assignment(n)
	case "control_transfer_statement":
		if t := sb.text(n); strings.HasPrefix(t, "break") || strings.HasPrefix(t, "continue") {
			label := ""
			if r := n.ChildByFieldName("result"); r != nil {
				label = sb.text(r)
			}
			sb.jump(strings.HasPrefix(t, "continue"), label)
			return ir.NoVar
		}
		var v ir.VarID = ir.NoVar
		if r := n.ChildByFieldName("result"); r != nil {
			v = sb.expr(r)
		} else if k := named(n); len(k) > 0 {
			v = sb.expr(k[len(k)-1])
		}
		if firstOf(n, "throw_keyword") != nil {
			sb.throwValue(v, n)
		}
		if hasChildToken(n, sb.f.src, "return") {
			sb.ret(n, v)
		}
		return ir.NoVar
	case "if_statement", "guard_statement":
		sb.conditions(n)
		return ir.NoVar
	case "for_statement":
		iter := sb.expr(n.ChildByFieldName("collection"))
		sb.loop(n, func() {
			sb.bindPattern(n.ChildByFieldName("item"), iter, "")
			for _, c := range named(n) {
				switch c.Type() {
				case "statements":
					sb.stmt(c)
				case "where_clause":
					for _, k := range named(c) {
						sb.expr(k)
					}
				}
			}
		})
		return ir.NoVar
	case "while_statement", "repeat_while_statement":
		cond := n.ChildByFieldName("condition")
		v, known := sb.truth(cond)
		if known && !v && n.Type() == "while_statement" {
			sb.expr(cond) // while false: the body never runs
			return ir.NoVar
		}
		sb.loopWith(n, loopSpec{infinite: known && v, body: func() {
			for _, c := range named(n) {
				sb.stmt(c)
			}
		}})
		return ir.NoVar
	case "switch_statement":
		subject := sb.expr(n.ChildByFieldName("expr"))
		var cases []func()
		exhaustive := false
		for _, e := range allOf(n, "switch_entry") {
			if firstOf(e, "default_keyword") != nil {
				exhaustive = true
			}
			cases = append(cases, func() {
				// case .some(let e), case let .user(name, mail): the
				// bound names take (parts of) the subject.
				for _, sp := range allOf(e, "switch_pattern") {
					var bound []*sitter.Node
					for _, p := range allOf(sp, "pattern") {
						swCaseBindings(p, false, false, &bound)
					}
					for _, id := range bound {
						sb.assign(sb.declare(sb.text(id), "", id), id, subject)
					}
				}
				sb.stmt(firstOf(e, "statements"))
			})
		}
		// Swift cases do not fall through; break leaves the switch.
		sb.switchCases(n, false, exhaustive, cases)
		return ir.NoVar
	case "do_statement":
		var body *sitter.Node
		var handlers []func()
		for _, c := range named(n) {
			switch c.Type() {
			case "statements":
				body = c
			case "catch_block":
				handlers = append(handlers, func() {
					errVar := sb.caughtValue(c)
					if p := c.ChildByFieldName("error"); p != nil {
						sb.bindPattern(p, errVar, "")
					} else {
						dst := sb.declare("error", "", c)
						sb.assign(dst, c, errVar)
					}
					sb.stmt(firstOf(c, "statements"))
				})
			}
		}
		sb.tryCatch(n, func() { sb.stmt(body) }, handlers, nil)
		return ir.NoVar
	case "function_declaration":
		fv := sb.closure(n, allOf(n, "parameter"), n.ChildByFieldName("body"))
		dst := sb.declare(sb.text(n.ChildByFieldName("name")), "", n)
		sb.assign(dst, n, fv)
		return ir.NoVar
	case "class_declaration", "protocol_declaration", "import_declaration", "comment", "multiline_comment", "typealias_declaration":
		return ir.NoVar
	}
	return sb.expr(n)
}

// swCaseBindings collects the names a case pattern binds: a
// bound_identifier, or, under let/var, an identifier in a nested pattern
// (let .some(g), let (a, b)); the enum case name itself is not bound.
func swCaseBindings(p *sitter.Node, binding, nested bool, out *[]*sitter.Node) {
	if firstOf(p, "value_binding_pattern") != nil {
		binding = true
	}
	for i := 0; i < int(p.ChildCount()); i++ {
		c := p.Child(i)
		if !c.IsNamed() {
			continue
		}
		switch {
		case p.FieldNameForChild(i) == "bound_identifier":
			*out = append(*out, c)
		case c.Type() == "pattern":
			swCaseBindings(c, binding, true, out)
		case c.Type() == "simple_identifier" && binding && nested:
			*out = append(*out, c)
		}
	}
}

// conditions lowers if/guard: `if let x = expr, cond { ... } else { ... }`
// binds x to expr for the body. The body and the else branch are
// alternative paths; a guard's else branch leaves the scope, so only the
// bindings of its conditions carry on.
func (sb *swBuilder) conditions(n *sitter.Node) {
	var pending *sitter.Node // the name of an `if let` binding
	var then, els *sitter.Node
	var conds []*sitter.Node
	bound := false
	afterElse := false
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if !c.IsNamed() {
			continue
		}
		switch field := n.FieldNameForChild(i); {
		case c.Type() == "value_binding_pattern":
		case c.Type() == "else":
			afterElse = true
		case field == "bound_identifier":
			pending = c
			bound = true
		case field == "condition":
			conds = append(conds, c)
			v := sb.expr(c)
			if pending != nil {
				dst := sb.declare(sb.text(pending), sb.fn.Vars[v].Type, pending)
				sb.assign(dst, c, v)
				pending = nil
			}
		case afterElse:
			els = c // the else body, or an else-if
		case c.Type() == "statements" && then == nil:
			then = c
		default:
			sb.stmt(c)
		}
	}
	if n.Type() == "guard_statement" {
		// The else branch must leave the scope; the code after the guard
		// continues from the conditions only.
		entry, from, dead := sb.snapshot(), sb.fn.CurBlock(), sb.terminated
		sb.newBlock(from)
		sb.stmt(els)
		sb.scope = entry
		sb.newBlock(from)
		sb.terminated = dead
		return
	}
	var elseArm func()
	if els != nil {
		elseArm = func() { sb.stmt(els) }
	}
	if len(conds) == 1 && !bound {
		sb.ifElse(n, conds[0], func() { sb.stmt(then) }, elseArm)
		return
	}
	arms := []func(){func() { sb.stmt(then) }}
	if elseArm != nil {
		arms = append(arms, elseArm)
	}
	sb.branches(n, els == nil, arms...)
}

// bindPattern assigns v to the names a pattern binds.
func (sb *swBuilder) bindPattern(p *sitter.Node, v ir.VarID, typ string) {
	if p == nil {
		return
	}
	if p.Type() == "simple_identifier" {
		dst := sb.declare(sb.text(p), typ, p)
		sb.assign(dst, p, v)
		return
	}
	if id := p.ChildByFieldName("bound_identifier"); id != nil {
		dst := sb.declare(sb.text(id), typ, id)
		sb.assign(dst, p, v)
		return
	}
	for _, c := range named(p) {
		switch c.Type() {
		case "simple_identifier":
			dst := sb.declare(sb.text(c), "", c)
			sb.assign(dst, c, v)
		case "pattern", "tuple_pattern":
			sb.bindPattern(c, v, "")
		}
	}
}

func (sb *swBuilder) assignment(n *sitter.Node) ir.VarID {
	v := sb.expr(n.ChildByFieldName("result"))
	target := n.ChildByFieldName("target")
	if target != nil && target.Type() == "directly_assignable_expression" {
		if k := named(target); len(k) > 0 {
			target = k[0]
		}
	}
	if target == nil {
		return v
	}
	op := n.ChildByFieldName("operator")
	if op != nil && sb.text(op) != "=" {
		old := sb.expr(target)
		sum := sb.temp(n)
		sb.assign(sum, n, old, v)
		v = sum
	}
	switch target.Type() {
	case "simple_identifier":
		name := sb.text(target)
		if name == "_" {
			return v
		}
		if old, ok := sb.scope[name]; ok {
			sb.assign(sb.redefine(name, old, "", target), n, v)
			return v
		}
		if sb.cls != nil && sb.this != ir.NoVar {
			if _, field := sb.cls.fields[name]; field {
				sb.store(sb.this, name, sb.cls.name, v, n)
				return v
			}
		}
		dst := sb.declare(name, "", target)
		sb.assign(dst, n, v)
	case "navigation_expression":
		obj := target.ChildByFieldName("target")
		field := swSuffix(sb.f, target)
		if p := sb.staticPath(obj); p != "" {
			// UIPasteboard.general.string = x is a setter call rules can
			// name ("UIPasteboard.general.string").
			sb.emitCall(n, &ir.Call{Callee: p + "." + field, Name: field, RecvText: trimText(sb.text(obj))}, []ir.VarID{v}, "")
			return v
		}
		sb.store(sb.expr(obj), field, sb.typeOf(obj), v, n)
	case "call_expression":
		// dict["phone"] = x
		base, key := sb.subscript(target)
		if key != "" {
			sb.store(base, key, "", v, n)
		} else if base != ir.NoVar {
			sb.assign(base, n, v)
			sb.noteAssign(base)
		}
	}
	return v
}

// swSuffix is the member name of a navigation expression (x.email).
func swSuffix(f *srcFile, n *sitter.Node) string {
	s := n.ChildByFieldName("suffix")
	if s == nil {
		return ""
	}
	if id := s.ChildByFieldName("suffix"); id != nil {
		return f.text(id)
	}
	return strings.TrimPrefix(f.text(s), ".")
}

// isSubscript reports whether a call_expression is a subscript: x["key"].
func isSubscript(f *srcFile, n *sitter.Node) (*sitter.Node, bool) {
	suffix := firstOf(n, "call_suffix")
	if suffix == nil {
		return nil, false
	}
	args := firstOf(suffix, "value_arguments")
	if args == nil || args.ChildCount() == 0 {
		return nil, false
	}
	return args, f.text(args.Child(0)) == "["
}

// subscript lowers the base of a subscript and returns the constant key,
// if any.
func (sb *swBuilder) subscript(n *sitter.Node) (ir.VarID, string) {
	args, ok := isSubscript(sb.f, n)
	if !ok {
		return sb.expr(n), ""
	}
	base := sb.expr(named(n)[0])
	vals := allOf(args, "value_argument")
	if len(vals) == 1 {
		if v := vals[0].ChildByFieldName("value"); v != nil && v.Type() == "line_string_literal" && firstOf(v, "interpolated_expression") == nil {
			return base, swString(sb.f, v)
		}
	}
	for _, a := range vals {
		sb.expr(a.ChildByFieldName("value"))
	}
	return base, ""
}

func (sb *swBuilder) expr(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "simple_identifier":
		name := sb.text(n)
		if _, local := sb.scope[name]; !local && isUpperStart(name) && !sb.hasField(name) {
			return sb.fn.Named(name, name, sb.pos(n))
		}
		return sb.ident(name, n)
	case "self_expression", "super_expression":
		if sb.this != ir.NoVar {
			return sb.this
		}
		return sb.ident("self", n)
	case "line_string_literal", "multi_line_string_literal", "raw_string_literal":
		subs := allOf(n, "interpolated_expression")
		if len(subs) == 0 {
			return sb.constVar(swString(sb.f, n), n)
		}
		var parts []ir.VarID
		for i, s := range subs {
			if s.ChildByFieldName("name") != nil {
				continue // an option of the previous value (privacy: .public)
			}
			if sb.osLog && !swPublic(sb.f, subs, i) {
				continue // redacted in the log
			}
			parts = append(parts, sb.expr(s.ChildByFieldName("value")))
		}
		dst := sb.temp(n)
		sb.compute(dst, n, parts...)
		return dst
	case "integer_literal", "real_literal", "boolean_literal", "hex_literal", "bin_literal", "oct_literal", "nil":
		return sb.constVar(sb.text(n), n)
	case "navigation_expression":
		obj := n.ChildByFieldName("target")
		field := swSuffix(sb.f, n)
		if p := sb.staticPath(obj); p != "" {
			return sb.load(sb.fn.Named(shortName(p), p, sb.pos(obj)), field, p, n)
		}
		if obj == nil {
			return sb.constVar(field, n) // .someCase
		}
		return sb.load(sb.expr(obj), field, sb.typeOf(obj), n)
	case "call_expression":
		if _, ok := isSubscript(sb.f, n); ok {
			base, key := sb.subscript(n)
			if key != "" {
				return sb.load(base, key, "", n)
			}
			dst := sb.temp(n)
			sb.assign(dst, n, base)
			return dst
		}
		return sb.call(n)
	case "try_expression", "await_expression", "as_expression", "postfix_expression", "parenthesized_expression", "value_argument",
		"directly_assignable_expression", "interpolated_expression":
		if e := n.ChildByFieldName("expr"); e != nil {
			return sb.expr(e)
		}
		if e := n.ChildByFieldName("target"); e != nil {
			return sb.expr(e)
		}
		if e := n.ChildByFieldName("value"); e != nil {
			return sb.expr(e)
		}
		for _, c := range named(n) {
			if !swIsType(c) && c.Type() != "try_operator" && c.Type() != "as_operator" {
				return sb.expr(c)
			}
		}
		return sb.temp(n)
	case "prefix_expression":
		op := n.ChildByFieldName("operation")
		target := n.ChildByFieldName("target")
		if op == nil && target != nil {
			return sb.constVar(sb.text(target), n) // .default, .info
		}
		v := sb.expr(target)
		if op != nil && sb.text(op) == "!" {
			return sb.temp(n)
		}
		return v
	case "comparison_expression", "equality_expression", "conjunction_expression", "disjunction_expression", "check_expression":
		for _, c := range named(n) {
			sb.expr(c)
		}
		return sb.temp(n)
	case "ternary_expression":
		sb.expr(n.ChildByFieldName("condition"))
		a, b := sb.expr(n.ChildByFieldName("if_true")), sb.expr(n.ChildByFieldName("if_false"))
		dst := sb.temp(n)
		sb.assign(dst, n, a, b)
		return dst
	case "dictionary_literal":
		var parts []ir.VarID
		var key *sitter.Node
		for i := 0; i < int(n.ChildCount()); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			switch n.FieldNameForChild(i) {
			case "key":
				key = c
			case "value":
				v := sb.expr(c)
				if key != nil && key.Type() == "line_string_literal" {
					nv := sb.fn.Named(swString(sb.f, key), "", sb.pos(key))
					sb.assign(nv, c, v)
					v = nv
				} else if key != nil {
					sb.expr(key)
				}
				parts = append(parts, v)
				key = nil
			}
		}
		dst := sb.temp(n)
		sb.assign(dst, n, parts...)
		return dst
	case "lambda_literal":
		return sb.lambdaLit(n)
	case "comment", "multiline_comment":
		return sb.temp(n)
	}
	// additive/multiplicative expressions, nil coalescing, tuples, arrays:
	// the value carries every part.
	var parts []ir.VarID
	for _, c := range named(n) {
		if swIsType(c) {
			continue
		}
		parts = append(parts, sb.expr(c))
	}
	dst := sb.temp(n)
	if t := n.Type(); t == "additive_expression" || t == "multiplicative_expression" {
		sb.compute(dst, n, parts...) // a new value built from the parts
	} else {
		sb.assign(dst, n, parts...)
	}
	return dst
}

// hasField reports whether name is a field of the enclosing type, read
// through implicit self.
func (sb *swBuilder) hasField(name string) bool {
	if sb.cls == nil {
		return false
	}
	_, ok := sb.cls.fields[name]
	return ok
}

// lambdaLit lowers a closure; without declared parameters, $0 and $1
// stand for its arguments.
func (sb *swBuilder) lambdaLit(n *sitter.Node) ir.VarID {
	var nodes []*sitter.Node
	var names []string
	if t := n.ChildByFieldName("type"); t != nil {
		if ps := firstOf(t, "lambda_function_type_parameters"); ps != nil {
			for _, p := range allOf(ps, "lambda_parameter") {
				if id := firstOf(p, "simple_identifier"); id != nil {
					nodes, names = append(nodes, id), append(names, sb.text(id))
				}
			}
		}
	}
	if len(names) == 0 {
		nodes, names = []*sitter.Node{n, n}, []string{"$0", "$1"}
	}
	return sb.lambda(n, nodes, names, false, func() ir.VarID {
		return sb.stmt(firstOf(n, "statements"))
	})
}

// closure lowers a nested function inline.
func (sb *swBuilder) closure(n *sitter.Node, params []*sitter.Node, body *sitter.Node) ir.VarID {
	var nodes []*sitter.Node
	var names []string
	for _, p := range params {
		if pn, _ := swParam(sb.f, p); pn != "" {
			nodes, names = append(nodes, p), append(names, pn)
		}
	}
	return sb.lambda(n, nodes, names, false, func() ir.VarID { return sb.stmt(body) })
}

// args lowers a call's arguments, a labelled argument as a value named
// after its label (email: x), and trailing closures.
func (sb *swBuilder) args(suffix *sitter.Node) []ir.VarID {
	var out []ir.VarID
	for _, c := range named(suffix) {
		switch c.Type() {
		case "value_arguments":
			for _, a := range allOf(c, "value_argument") {
				v := sb.expr(a.ChildByFieldName("value"))
				if l := a.ChildByFieldName("name"); l != nil && v != ir.NoVar {
					nv := sb.fn.Named(sb.text(l), "", sb.pos(a))
					sb.assign(nv, a, v)
					v = nv
				}
				out = append(out, v)
			}
		case "lambda_literal":
			out = append(out, sb.lambdaLit(c))
		case "annotated_lambda":
			if l := firstOf(c, "lambda_literal"); l != nil {
				out = append(out, sb.lambdaLit(l))
			}
		}
	}
	return out
}

// staticPath resolves type and static member references: SentrySDK,
// UserDefaults.standard, Analytics.shared.
func (sb *swBuilder) staticPath(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "simple_identifier":
		name := sb.text(n)
		if _, local := sb.scope[name]; local || !isUpperStart(name) || sb.hasField(name) {
			return ""
		}
		return name
	case "navigation_expression":
		if p := sb.staticPath(n.ChildByFieldName("target")); p != "" {
			return p + "." + swSuffix(sb.f, n)
		}
	}
	return ""
}

func (sb *swBuilder) typeOf(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "simple_identifier":
		if v, ok := sb.scope[sb.text(n)]; ok {
			return sb.fn.Vars[v].Type
		}
		if sb.cls != nil {
			return sb.sp.fieldType(sb.cls.name, sb.text(n))
		}
	case "self_expression":
		if sb.cls != nil {
			return sb.cls.name
		}
	case "navigation_expression":
		if owner := sb.typeOf(n.ChildByFieldName("target")); owner != "" {
			return sb.sp.fieldType(owner, swSuffix(sb.f, n))
		}
	case "call_expression":
		if k := named(n); len(k) > 0 && k[0].Type() == "simple_identifier" {
			if c := sb.sp.class(sb.text(k[0])); c != nil {
				return c.name
			}
			if _, local := sb.scope[sb.text(k[0])]; !local && isUpperStart(sb.text(k[0])) {
				return sb.text(k[0]) // Data(...), URL(...)
			}
		}
	case "try_expression", "await_expression", "postfix_expression", "parenthesized_expression":
		if e := n.ChildByFieldName("expr"); e != nil {
			return sb.typeOf(e)
		}
		if e := n.ChildByFieldName("target"); e != nil {
			return sb.typeOf(e)
		}
	}
	return ""
}

func (sb *swBuilder) call(n *sitter.Node) ir.VarID {
	k := named(n)
	if len(k) == 0 {
		return sb.temp(n)
	}
	fn, suffix := k[0], firstOf(n, "call_suffix")
	switch fn.Type() {
	case "simple_identifier":
		name := sb.text(fn)
		if v, local := sb.scope[name]; local {
			return sb.emitCall(n, &ir.Call{Name: name, HasRecv: true, RecvText: name}, append([]ir.VarID{v}, sb.args(suffix)...), "")
		}
		if sb.cls != nil {
			if id := sb.sp.methodID(sb.cls.name, name, 0); id != "" {
				if sb.sp.static[id] || sb.this == ir.NoVar {
					return sb.emitCall(n, &ir.Call{Callee: id, Name: name, Target: id}, sb.args(suffix), "")
				}
				return sb.emitCall(n, &ir.Call{Callee: id, Name: name, Target: id, HasRecv: true, RecvText: "self"}, append([]ir.VarID{sb.this}, sb.args(suffix)...), "")
			}
		}
		if id, ok := sb.sp.top[name]; ok {
			return sb.emitCall(n, &ir.Call{Callee: id, Name: name, Target: id}, sb.args(suffix), "")
		}
		if name == "os_log" {
			return sb.emitCall(n, &ir.Call{Callee: name, Name: name}, sb.osLogArgs(suffix), "")
		}
		if isUpperStart(name) {
			typ := name
			if c := sb.sp.class(name); c != nil {
				typ = c.name
			}
			return sb.emitCall(n, &ir.Call{Callee: typ, Name: shortName(typ), Construct: true}, sb.args(suffix), typ)
		}
		return sb.emitCall(n, &ir.Call{Callee: name, Name: name}, sb.args(suffix), "")
	case "navigation_expression":
		obj := fn.ChildByFieldName("target")
		m := swSuffix(sb.f, fn)
		if swLoggerMethods[m] && (sb.typeOf(obj) == "Logger" || strings.HasSuffix(strings.ToLower(sb.text(obj)), "logger")) {
			sb.osLog = true
			defer func() { sb.osLog = false }()
		}
		if obj != nil && obj.Type() == "call_expression" {
			// factory().method(): Crashlytics.crashlytics().setUserID(...)
			// Type(...) is a constructor, not a factory: only Type.factory() is.
			if inner := named(obj); len(inner) > 0 && inner[0].Type() == "navigation_expression" {
				if p := sb.staticPath(inner[0]); p != "" && sb.sp.class(p) == nil {
					recv := sb.expr(obj)
					c := &ir.Call{Callee: p + "()." + m, Name: m, HasRecv: true, RecvText: trimText(sb.text(obj))}
					return sb.emitCall(n, c, append([]ir.VarID{recv}, sb.args(suffix)...), "")
				}
			}
		}
		if p := sb.staticPath(obj); p != "" {
			if c := sb.sp.class(p); c != nil {
				if id := sb.sp.methodID(c.name, m, 0); id != "" {
					return sb.emitCall(n, &ir.Call{Callee: id, Name: m, Target: id}, sb.args(suffix), "")
				}
			}
			return sb.emitCall(n, &ir.Call{Callee: p + "." + m, Name: m, RecvText: trimText(sb.text(obj))}, sb.args(suffix), "")
		}
		typ := sb.typeOf(obj)
		recv := sb.expr(obj)
		c := &ir.Call{Name: m, HasRecv: true, RecvType: typ, RecvText: trimText(sb.text(obj))}
		if typ != "" {
			if id := sb.sp.methodID(typ, m, 0); id != "" {
				c.Target, c.Callee = id, id
				if sb.sp.static[id] {
					c.HasRecv = false
					return sb.emitCall(n, c, sb.args(suffix), "")
				}
			} else if sb.sp.class(typ) == nil {
				c.Callee = typ + "." + m
			}
		}
		return sb.emitCall(n, c, append([]ir.VarID{recv}, sb.args(suffix)...), "")
	}
	fv := sb.expr(fn)
	return sb.emitCall(n, &ir.Call{Name: "call", HasRecv: true, RecvText: trimText(sb.text(fn))}, append([]ir.VarID{fv}, sb.args(suffix)...), "")
}

// swPublic reports whether the interpolation at i is followed by a
// privacy: .public option.
func swPublic(f *srcFile, subs []*sitter.Node, i int) bool {
	for j := i + 1; j < len(subs) && subs[j].ChildByFieldName("name") != nil; j++ {
		if f.text(subs[j].ChildByFieldName("name")) == "privacy" && strings.HasSuffix(f.text(subs[j].ChildByFieldName("value")), "public") {
			return true
		}
	}
	return false
}

// osLogArgs lowers os_log(format, args...): arguments are private (redacted
// in the log) unless the format marks them %{public}, so only then do they
// reach the log.
func (sb *swBuilder) osLogArgs(suffix *sitter.Node) []ir.VarID {
	args := sb.args(suffix)
	vals := allOf(firstOf(suffix, "value_arguments"), "value_argument")
	if len(vals) > 0 {
		if fmtNode := vals[0].ChildByFieldName("value"); fmtNode != nil && !strings.Contains(sb.text(fmtNode), "{public}") {
			return args[:1]
		}
	}
	return args
}
