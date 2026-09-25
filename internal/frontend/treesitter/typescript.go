// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"path"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/lang"
)

// NewTypeScript returns the typescript frontend.
func NewTypeScript(o frontend.Options) frontend.Frontend { return &tsFrontend{opts: o} }

type tsFrontend struct{ opts frontend.Options }

func (fe *tsFrontend) Lang() string { return lang.TypeScript }

type tsProgram struct {
	*program
	static  map[string]bool
	ctorIDs map[string]string // class short name -> constructor id
	classOf map[string]string // class short name -> "module:Class"
}

// Browser/Node globals whose members are resolved by name.
var tsGlobals = map[string]bool{
	"console": true, "localStorage": true, "sessionStorage": true, "navigator": true, "document": true, "JSON": true,
	"Math": true, "Object": true, "Array": true, "Promise": true, "fetch": true, "gtag": true, "fbq": true, "Intercom": true,
	"process": true, "Buffer": true, "crypto": true, "btoa": true, "atob": true, "location": true, "history": true, "XMLHttpRequest": true,
}

func (fe *tsFrontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	tp := &tsProgram{program: newProgram(lang.TypeScript, fe.opts), static: map[string]bool{}, ctorIDs: map[string]string{}, classOf: map[string]string{}}
	var tsFiles, tsxFiles []string
	for _, f := range files {
		switch strings.ToLower(path.Ext(f)) {
		case ".ts", ".mts", ".cts":
			tsFiles = append(tsFiles, f)
		default:
			tsxFiles = append(tsxFiles, f)
		}
	}
	tp.parse(ctx, tsFiles, typescript.GetLanguage())
	tp.parse(ctx, tsxFiles, tsx.GetLanguage())
	for _, f := range tp.files {
		f.pkg = tsModuleID(f.rel)
		tp.modules[f.pkg] = true
	}
	for _, f := range tp.files {
		tp.header(f)
		tp.collect(f)
	}
	for _, c := range tp.classes {
		for k, t := range c.fields {
			c.fields[k] = tp.resolveType(c.file, t)
		}
	}
	for _, f := range tp.files {
		tp.lowerFile(f)
	}
	return tp.mod, nil
}

// resolveModule maps an import specifier to a module id.
func (tp *tsProgram) resolveModule(from, spec string) string {
	if !strings.HasPrefix(spec, ".") {
		for _, alias := range []string{"@/", "~/"} {
			if strings.HasPrefix(spec, alias) {
				rest := strings.TrimPrefix(spec, alias)
				for _, cand := range []string{"src/" + rest, rest} {
					cand = tsModuleID(cand)
					if tp.modules[cand] || tp.modules[cand+"/index"] {
						if tp.modules[cand] {
							return cand
						}
						return cand + "/index"
					}
				}
			}
		}
		return spec
	}
	p := tsModuleID(path.Join(path.Dir(from), spec))
	if !tp.modules[p] && tp.modules[p+"/index"] {
		return p + "/index"
	}
	return p
}

func stringValue(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	var sb strings.Builder
	frags := allOf(n, "string_fragment")
	if len(frags) == 0 {
		return unquote(f.text(n))
	}
	for _, c := range frags {
		sb.WriteString(f.text(c))
	}
	return sb.String()
}

func (tp *tsProgram) header(f *srcFile) {
	for _, st := range named(f.root) {
		switch st.Type() {
		case "import_statement":
			src := tp.resolveModule(f.rel, stringValue(f, st.ChildByFieldName("source")))
			clause := firstOf(st, "import_clause")
			if clause == nil {
				if req := firstOf(st, "import_require_clause"); req != nil {
					if id := firstOf(req, "identifier"); id != nil {
						f.imports[f.text(id)] = tp.resolveModule(f.rel, stringValue(f, firstOf(req, "string")))
					}
				}
				continue
			}
			for _, c := range named(clause) {
				switch c.Type() {
				case "identifier":
					f.imports[f.text(c)] = src
				case "namespace_import":
					if id := firstOf(c, "identifier"); id != nil {
						f.imports[f.text(id)] = src
					}
				case "named_imports":
					for _, spec := range allOf(c, "import_specifier") {
						name := f.text(spec.ChildByFieldName("name"))
						local := name
						if a := spec.ChildByFieldName("alias"); a != nil {
							local = f.text(a)
						}
						f.imports[local] = src + "." + name
					}
				}
			}
		case "lexical_declaration", "variable_declaration":
			for _, d := range allOf(st, "variable_declarator") {
				val := d.ChildByFieldName("value")
				if val == nil || val.Type() != "call_expression" || f.text(val.ChildByFieldName("function")) != "require" {
					continue
				}
				args := named(val.ChildByFieldName("arguments"))
				if len(args) == 0 {
					continue
				}
				src := tp.resolveModule(f.rel, stringValue(f, args[0]))
				name := d.ChildByFieldName("name")
				switch name.Type() {
				case "identifier":
					f.imports[f.text(name)] = src
				case "object_pattern":
					for _, c := range named(name) {
						switch c.Type() {
						case "shorthand_property_identifier_pattern":
							f.imports[f.text(c)] = src + "." + f.text(c)
						case "pair_pattern":
							f.imports[f.text(c.ChildByFieldName("value"))] = src + "." + f.text(c.ChildByFieldName("key"))
						}
					}
				}
			}
		}
	}
}

// topDecls yields top-level declarations, unwrapping export statements.
func topDecls(root *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for _, c := range named(root) {
		if c.Type() == "export_statement" {
			if d := c.ChildByFieldName("declaration"); d != nil {
				out = append(out, d)
				continue
			}
			for _, k := range named(c) {
				switch k.Type() {
				case "function_declaration", "class_declaration", "abstract_class_declaration", "lexical_declaration", "function_expression", "arrow_function", "class":
					out = append(out, k)
				}
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

func isFuncValue(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "arrow_function", "function_expression", "function", "generator_function":
		return true
	}
	return false
}

func tsDecorators(f *srcFile, n *sitter.Node) (map[string]string, []string) {
	tags := map[string]string{}
	var names []string
	for _, d := range allOf(n, "decorator") {
		inner := named(d)
		if len(inner) == 0 {
			continue
		}
		name, val := "", ""
		switch inner[0].Type() {
		case "identifier":
			name = f.text(inner[0])
		case "call_expression":
			name = f.text(inner[0].ChildByFieldName("function"))
			for _, a := range named(inner[0].ChildByFieldName("arguments")) {
				switch a.Type() {
				case "string":
					if val == "" {
						val = stringValue(f, a)
					}
				case "object":
					for _, p := range allOf(a, "pair") {
						if k := f.text(p.ChildByFieldName("key")); k == "name" || k == "value" {
							val = stringValue(f, p.ChildByFieldName("value"))
						}
					}
				}
			}
		}
		name = shortName(name)
		if name != "" {
			names = append(names, name)
			tags["@"+name] = val
		}
	}
	return tags, names
}

func tsTypeName(f *srcFile, ann *sitter.Node) string {
	if ann == nil {
		return ""
	}
	for _, c := range named(ann) {
		switch c.Type() {
		case "type_identifier", "nested_type_identifier":
			return f.text(c)
		case "generic_type":
			if n := c.ChildByFieldName("name"); n != nil {
				return f.text(n)
			}
		case "predefined_type":
			return f.text(c)
		}
	}
	return ""
}

func (tp *tsProgram) collect(f *srcFile) {
	for _, d := range topDecls(f.root) {
		switch d.Type() {
		case "function_declaration", "generator_function_declaration":
			name := f.text(d.ChildByFieldName("name"))
			id := f.pkg + ":" + name
			tp.funcs[id] = true
			tp.top[f.pkg+"."+name] = id
		case "lexical_declaration", "variable_declaration":
			for _, vd := range allOf(d, "variable_declarator") {
				if isFuncValue(vd.ChildByFieldName("value")) {
					name := f.text(vd.ChildByFieldName("name"))
					id := f.pkg + ":" + name
					tp.funcs[id] = true
					tp.top[f.pkg+"."+name] = id
				}
			}
		case "class_declaration", "abstract_class_declaration", "class":
			tp.collectClass(f, d)
		case "interface_declaration", "type_alias_declaration":
			name := f.text(d.ChildByFieldName("name"))
			body := d.ChildByFieldName("body")
			if body == nil {
				body = d.ChildByFieldName("value")
			}
			if body == nil {
				continue
			}
			td := &ir.TypeDecl{Name: name, Kind: "interface", Lang: lang.TypeScript, Pos: posOf(f, d)}
			for _, ps := range allOf(body, "property_signature") {
				fn := unquote(f.text(ps.ChildByFieldName("name")))
				td.Fields = append(td.Fields, ir.Field{Name: fn, Type: tsTypeName(f, ps.ChildByFieldName("type")), Pos: posOf(f, ps)})
			}
			if len(td.Fields) > 0 {
				tp.mod.Types = append(tp.mod.Types, td)
			}
		}
	}
}

func (tp *tsProgram) collectClass(f *srcFile, d *sitter.Node) {
	name := f.text(d.ChildByFieldName("name"))
	if name == "" {
		return
	}
	ci := &classInfo{name: name, short: name, file: f, fields: map[string]string{}, methods: map[string]string{}}
	_, ann := tsDecorators(f, d)
	if p := d.Parent(); p != nil && p.Type() == "export_statement" {
		_, more := tsDecorators(f, p)
		ann = append(ann, more...)
	}
	td := &ir.TypeDecl{Name: name, Kind: "class", Lang: lang.TypeScript, Annotations: ann, Pos: posOf(f, d)}
	if isEntityAnnotation(ann) {
		td.Kind = "entity"
	}
	if h := firstOf(d, "class_heritage"); h != nil {
		for _, c := range named(h) {
			for _, t := range named(c) {
				if t.Type() == "identifier" || t.Type() == "type_identifier" {
					ci.supers = append(ci.supers, f.text(t))
				}
			}
		}
	}
	tp.classOf[name] = f.pkg + ":" + name
	for _, m := range named(d.ChildByFieldName("body")) {
		switch m.Type() {
		case "public_field_definition", "field_definition":
			fn := unquote(f.text(m.ChildByFieldName("name")))
			typ := tsTypeName(f, m.ChildByFieldName("type"))
			if typ == "" {
				if v := m.ChildByFieldName("value"); v != nil && v.Type() == "new_expression" {
					typ = f.text(v.ChildByFieldName("constructor"))
				}
			}
			ci.fields[fn] = typ
			tags, _ := tsDecorators(f, m)
			td.Fields = append(td.Fields, ir.Field{Name: fn, Type: typ, Tags: tags, Pos: posOf(f, m)})
		case "method_definition", "method_signature", "abstract_method_signature":
			mn := unquote(f.text(m.ChildByFieldName("name")))
			id := f.pkg + ":" + name + "." + mn
			tp.funcs[id] = true
			if mn == "constructor" {
				tp.ctorIDs[name] = id
				for _, p := range named(m.ChildByFieldName("parameters")) {
					if firstOf(p, "accessibility_modifier", "override_modifier") == nil && !hasChildToken(p, f.src, "readonly") {
						continue
					}
					pn := p.ChildByFieldName("pattern")
					if pn != nil && pn.Type() == "identifier" {
						ci.fields[f.text(pn)] = tsTypeName(f, p.ChildByFieldName("type"))
					}
				}
				continue
			}
			if _, dup := ci.methods[mn]; !dup {
				ci.methods[mn] = id
			}
			if hasChildToken(m, f.src, "static") {
				tp.static[id] = true
			}
		}
	}
	if td.Kind != "entity" && !hasBehaviour(ci.methods) {
		td.Kind = "data"
	}
	tp.addClass(ci)
	if len(td.Fields) > 0 {
		tp.mod.Types = append(tp.mod.Types, td)
	}
}

func (tp *tsProgram) lowerFile(f *srcFile) {
	var init *tsBuilder
	getInit := func(n *sitter.Node) *tsBuilder {
		if init == nil {
			init = &tsBuilder{builder: tp.newBuilder(f, nil, f.pkg+":<init>", "<init>", n), tp: tp}
		}
		return init
	}
	for _, d := range topDecls(f.root) {
		switch d.Type() {
		case "import_statement", "interface_declaration", "type_alias_declaration", "enum_declaration", "comment", "ambient_declaration":
		case "function_declaration", "generator_function_declaration":
			name := f.text(d.ChildByFieldName("name"))
			tp.lowerFunction(f, nil, f.pkg+":"+name, name, d, false)
		case "lexical_declaration", "variable_declaration":
			for _, vd := range allOf(d, "variable_declarator") {
				val := vd.ChildByFieldName("value")
				if isFuncValue(val) {
					name := f.text(vd.ChildByFieldName("name"))
					tp.lowerFunction(f, nil, f.pkg+":"+name, name, val, false)
					continue
				}
				if val != nil && val.Type() == "call_expression" && f.text(val.ChildByFieldName("function")) == "require" {
					continue
				}
				getInit(vd).declarator(vd)
			}
		case "class_declaration", "abstract_class_declaration", "class":
			tp.lowerClass(f, d)
		default:
			getInit(d).stmt(d)
		}
	}
	if init != nil && len(init.fn.Instrs) > 0 {
		init.finish()
	}
}

func (tp *tsProgram) lowerClass(f *srcFile, d *sitter.Node) {
	name := f.text(d.ChildByFieldName("name"))
	ci := tp.classes[name]
	if ci == nil || ci.file != f {
		return
	}
	var fieldInit *tsBuilder
	for _, m := range named(d.ChildByFieldName("body")) {
		switch m.Type() {
		case "method_definition":
			mn := unquote(f.text(m.ChildByFieldName("name")))
			id := f.pkg + ":" + name + "." + mn
			tp.lowerFunction(f, ci, id, mn, m, tp.static[id])
		case "public_field_definition", "field_definition":
			v := m.ChildByFieldName("value")
			if v == nil {
				continue
			}
			if fieldInit == nil {
				b := tp.newBuilder(f, ci, f.pkg+":"+name+".<fields>", "<fields>", m)
				b.addThis(name, m)
				fieldInit = &tsBuilder{builder: b, tp: tp}
			}
			fn := unquote(f.text(m.ChildByFieldName("name")))
			if isFuncValue(v) {
				// Arrow-function property: lower as a method.
				tp.lowerFunction(f, ci, f.pkg+":"+name+"."+fn, fn, v, false)
				continue
			}
			val := fieldInit.expr(v)
			fieldInit.store(fieldInit.this, fn, name, val, m)
		}
	}
	if fieldInit != nil && len(fieldInit.fn.Instrs) > 0 {
		fieldInit.finish()
	}
}

func (tp *tsProgram) lowerFunction(f *srcFile, cls *classInfo, id, name string, n *sitter.Node, static bool) {
	b := tp.newBuilder(f, cls, id, name, n)
	tb := &tsBuilder{builder: b, tp: tp}
	if cls != nil && !static {
		b.addThis(cls.name, n)
	}
	params := n.ChildByFieldName("parameters")
	if params == nil {
		if p := n.ChildByFieldName("parameter"); p != nil {
			b.param(f.text(p), "", p)
		}
	}
	for _, p := range named(params) {
		tb.paramNode(p, name == "constructor")
	}
	body := n.ChildByFieldName("body")
	if body != nil && body.Type() != "statement_block" {
		b.ret(body, tb.expr(body))
	} else {
		tb.stmt(body)
	}
	b.finish()
}

type tsBuilder struct {
	*builder
	tp *tsProgram
}

func (tb *tsBuilder) paramNode(p *sitter.Node, ctor bool) {
	switch p.Type() {
	case "required_parameter", "optional_parameter":
		pat := p.ChildByFieldName("pattern")
		typ := tb.tp.resolveType(tb.f, tsTypeName(tb.f, p.ChildByFieldName("type")))
		if pat == nil {
			return
		}
		switch pat.Type() {
		case "identifier":
			v := tb.param(tb.text(pat), typ, pat)
			if ctor && tb.this != ir.NoVar && (firstOf(p, "accessibility_modifier") != nil || hasChildToken(p, tb.f.src, "readonly")) {
				tb.store(tb.this, tb.text(pat), tb.cls.name, v, p)
			}
		case "object_pattern", "array_pattern":
			v := tb.param("", typ, pat)
			tb.destructure(pat, v, typ)
		case "rest_pattern":
			tb.param(strings.TrimPrefix(tb.text(pat), "..."), typ, pat)
		default:
			tb.param(tb.text(pat), typ, pat)
		}
	case "identifier":
		tb.param(tb.text(p), "", p)
	}
}

// destructure declares the names bound by an object/array pattern.
func (tb *tsBuilder) destructure(pat *sitter.Node, src ir.VarID, owner string) {
	switch pat.Type() {
	case "identifier":
		dst := tb.declare(tb.text(pat), "", pat)
		tb.assign(dst, pat, src)
	case "object_pattern":
		for _, c := range named(pat) {
			switch c.Type() {
			case "shorthand_property_identifier_pattern":
				v := tb.load(src, tb.text(c), owner, c)
				dst := tb.declare(tb.text(c), "", c)
				tb.assign(dst, c, v)
			case "pair_pattern":
				key := unquote(tb.text(c.ChildByFieldName("key")))
				v := tb.load(src, key, owner, c)
				tb.destructure(c.ChildByFieldName("value"), v, "")
			case "object_assignment_pattern":
				left := c.ChildByFieldName("left")
				if left != nil {
					v := tb.load(src, tb.text(left), owner, c)
					dst := tb.declare(tb.text(left), "", left)
					tb.assign(dst, c, v, tb.expr(c.ChildByFieldName("right")))
				}
			case "rest_pattern":
				if id := firstOf(c, "identifier"); id != nil {
					dst := tb.declare(tb.text(id), "", id)
					tb.assign(dst, c, src)
				}
			}
		}
	case "array_pattern":
		for _, c := range named(pat) {
			tb.destructure(c, src, "")
		}
	case "assignment_pattern":
		if l := pat.ChildByFieldName("left"); l != nil {
			tb.destructure(l, src, owner)
		}
	case "rest_pattern":
		if id := firstOf(pat, "identifier"); id != nil {
			dst := tb.declare(tb.text(id), "", id)
			tb.assign(dst, pat, src)
		}
	}
}

func (tb *tsBuilder) declarator(vd *sitter.Node) {
	name := vd.ChildByFieldName("name")
	var v ir.VarID = ir.NoVar
	typ := tb.tp.resolveType(tb.f, tsTypeName(tb.f, vd.ChildByFieldName("type")))
	if val := vd.ChildByFieldName("value"); val != nil {
		v = tb.expr(val)
		if typ == "" && v != ir.NoVar {
			typ = tb.fn.Vars[v].Type
		}
	}
	if name == nil {
		return
	}
	if name.Type() == "identifier" {
		dst := tb.declare(tb.text(name), typ, name)
		tb.assign(dst, vd, v)
		return
	}
	src := v
	if src == ir.NoVar {
		src = tb.temp(vd)
	}
	tb.destructure(name, src, typ)
}

func (tb *tsBuilder) stmt(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "statement_block", "program", "else_clause", "switch_body", "switch_case", "switch_default", "finally_clause":
		last := ir.NoVar
		for _, c := range named(n) {
			last = tb.stmt(c)
		}
		return last
	case "lexical_declaration", "variable_declaration":
		for _, vd := range allOf(n, "variable_declarator") {
			tb.declarator(vd)
		}
		return ir.NoVar
	case "expression_statement":
		for _, c := range named(n) {
			return tb.expr(c)
		}
		return ir.NoVar
	case "return_statement":
		var v ir.VarID = ir.NoVar
		if k := named(n); len(k) > 0 {
			v = tb.expr(k[0])
		}
		tb.ret(n, v)
		return ir.NoVar
	case "for_in_statement":
		iter := tb.expr(n.ChildByFieldName("right"))
		if left := n.ChildByFieldName("left"); left != nil {
			tb.destructure(left, iter, "")
		}
		tb.stmt(n.ChildByFieldName("body"))
		return ir.NoVar
	case "catch_clause":
		if p := n.ChildByFieldName("parameter"); p != nil {
			tb.destructure(p, tb.temp(p), "")
		}
		tb.stmt(n.ChildByFieldName("body"))
		return ir.NoVar
	case "function_declaration", "generator_function_declaration":
		name := tb.text(n.ChildByFieldName("name"))
		fv := tb.lambdaFn(n)
		dst := tb.declare(name, "", n)
		tb.assign(dst, n, fv)
		return ir.NoVar
	case "if_statement", "for_statement", "while_statement", "do_statement", "try_statement", "switch_statement",
		"labeled_statement", "throw_statement", "parenthesized_expression", "with_statement":
		last := ir.NoVar
		for _, c := range named(n) {
			last = tb.stmt(c)
		}
		return last
	case "class_declaration", "interface_declaration", "type_alias_declaration", "comment", "empty_statement", "import_statement", "export_statement", "debugger_statement", "break_statement", "continue_statement":
		return ir.NoVar
	}
	return tb.expr(n)
}

var tsCompare = map[string]bool{"==": true, "===": true, "!=": true, "!==": true, "<": true, ">": true, "<=": true, ">=": true, "instanceof": true, "in": true}

func (tb *tsBuilder) expr(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "identifier", "shorthand_property_identifier":
		name := tb.text(n)
		if name == "undefined" {
			return tb.constVar(name, n)
		}
		if _, local := tb.scope[name]; !local {
			if q, ok := tb.f.imports[name]; ok {
				return tb.fn.Named(name, q, tb.pos(n))
			}
		}
		return tb.ident(name, n)
	case "this", "super":
		if tb.this != ir.NoVar {
			return tb.this
		}
		return tb.ident("this", n)
	case "string":
		return tb.constVar(stringValue(tb.f, n), n)
	case "template_string":
		subs := allOf(n, "template_substitution")
		if len(subs) == 0 {
			return tb.constVar(stringValue(tb.f, n), n)
		}
		var parts []ir.VarID
		for _, s := range subs {
			for _, e := range named(s) {
				parts = append(parts, tb.expr(e))
			}
		}
		dst := tb.temp(n)
		tb.assign(dst, n, parts...)
		return dst
	case "number", "true", "false", "null", "regex":
		return tb.constVar(tb.text(n), n)
	case "member_expression":
		obj := n.ChildByFieldName("object")
		prop := tb.text(n.ChildByFieldName("property"))
		if p := tb.staticPath(obj); p != "" {
			o := tb.fn.Named(shortName(p), p, tb.pos(obj))
			return tb.load(o, prop, p, n)
		}
		owner := tb.typeOf(obj)
		return tb.load(tb.expr(obj), prop, owner, n)
	case "subscript_expression":
		base := tb.expr(n.ChildByFieldName("object"))
		idx := n.ChildByFieldName("index")
		if idx != nil && idx.Type() == "string" {
			return tb.load(base, stringValue(tb.f, idx), "", n)
		}
		tb.expr(idx)
		dst := tb.temp(n)
		tb.assign(dst, n, base)
		return dst
	case "call_expression":
		return tb.call(n)
	case "new_expression":
		ctor := n.ChildByFieldName("constructor")
		typ := tb.tp.resolveType(tb.f, tb.text(ctor))
		args := tb.args(n.ChildByFieldName("arguments"))
		return tb.emitCall(n, &ir.Call{Callee: typ, Name: shortName(typ), Construct: true}, args, typ)
	case "await_expression", "parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression", "type_assertion", "spread_element", "yield_expression":
		k := named(n)
		if len(k) == 0 {
			return tb.temp(n)
		}
		if n.Type() == "type_assertion" {
			return tb.expr(k[len(k)-1])
		}
		return tb.expr(k[0])
	case "binary_expression":
		op := tb.text(n.ChildByFieldName("operator"))
		l, r := tb.expr(n.ChildByFieldName("left")), tb.expr(n.ChildByFieldName("right"))
		dst := tb.temp(n)
		if tsCompare[op] {
			return dst
		}
		tb.assign(dst, n, l, r)
		return dst
	case "unary_expression":
		arg := tb.expr(n.ChildByFieldName("argument"))
		switch tb.text(n.ChildByFieldName("operator")) {
		case "!", "typeof", "void", "delete":
			return tb.temp(n)
		}
		return arg
	case "update_expression":
		return tb.expr(n.ChildByFieldName("argument"))
	case "assignment_expression", "augmented_assignment_expression":
		return tb.assignment(n)
	case "ternary_expression":
		tb.expr(n.ChildByFieldName("condition"))
		a, b := tb.expr(n.ChildByFieldName("consequence")), tb.expr(n.ChildByFieldName("alternative"))
		dst := tb.temp(n)
		tb.assign(dst, n, a, b)
		return dst
	case "object":
		var parts []ir.VarID
		for _, c := range named(n) {
			switch c.Type() {
			case "pair":
				key := c.ChildByFieldName("key")
				v := tb.expr(c.ChildByFieldName("value"))
				if key != nil && (key.Type() == "property_identifier" || key.Type() == "string") {
					nv := tb.fn.Named(stringValue(tb.f, key), "", tb.pos(key))
					tb.assign(nv, c, v)
					parts = append(parts, nv)
				} else {
					parts = append(parts, v)
				}
			case "method_definition":
				parts = append(parts, tb.lambdaFn(c))
			default:
				parts = append(parts, tb.expr(c))
			}
		}
		dst := tb.temp(n)
		tb.assign(dst, n, parts...)
		return dst
	case "arrow_function", "function_expression", "function", "generator_function":
		return tb.lambdaFn(n)
	case "sequence_expression":
		var last ir.VarID = ir.NoVar
		for _, c := range named(n) {
			last = tb.expr(c)
		}
		return last
	case "class", "comment", "jsx_text", "html_comment":
		return tb.temp(n)
	}
	var parts []ir.VarID
	for _, c := range named(n) {
		parts = append(parts, tb.expr(c))
	}
	dst := tb.temp(n)
	tb.assign(dst, n, parts...)
	return dst
}

func (tb *tsBuilder) lambdaFn(n *sitter.Node) ir.VarID {
	var patterns []*sitter.Node
	if ps := n.ChildByFieldName("parameters"); ps != nil {
		for _, p := range named(ps) {
			if pat := p.ChildByFieldName("pattern"); pat != nil {
				patterns = append(patterns, pat)
			} else if p.Type() == "identifier" {
				patterns = append(patterns, p)
			}
		}
	} else if p := n.ChildByFieldName("parameter"); p != nil {
		patterns = append(patterns, p)
	}
	var simpleNodes []*sitter.Node
	var simpleNames []string
	var complexPats []*sitter.Node
	for _, p := range patterns {
		if p.Type() == "identifier" {
			simpleNodes, simpleNames = append(simpleNodes, p), append(simpleNames, tb.text(p))
		} else {
			complexPats = append(complexPats, p)
		}
	}
	body := n.ChildByFieldName("body")
	return tb.lambda(n, simpleNodes, simpleNames, false, func() ir.VarID {
		for _, p := range complexPats {
			tb.destructure(p, tb.temp(p), "")
		}
		if body == nil {
			return ir.NoVar
		}
		if body.Type() == "statement_block" {
			return tb.stmt(body)
		}
		return tb.expr(body)
	})
}

func (tb *tsBuilder) assignment(n *sitter.Node) ir.VarID {
	left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
	v := tb.expr(right)
	augmented := n.Type() == "augmented_assignment_expression"
	switch left.Type() {
	case "identifier":
		name := tb.text(left)
		dst, ok := tb.scope[name]
		if !ok {
			dst = tb.declare(name, "", left)
		}
		if augmented {
			tb.assign(dst, n, dst, v)
		} else {
			tb.assign(dst, n, v)
		}
		tb.noteAssign(dst)
		return dst
	case "member_expression":
		obj := left.ChildByFieldName("object")
		prop := tb.text(left.ChildByFieldName("property"))
		var o ir.VarID
		owner := ""
		if p := tb.staticPath(obj); p != "" {
			o = tb.fn.Named(shortName(p), p, tb.pos(obj))
			owner = p
		} else {
			o = tb.expr(obj)
			owner = tb.typeOf(obj)
		}
		tb.store(o, prop, owner, v, n)
	case "subscript_expression":
		base := tb.expr(left.ChildByFieldName("object"))
		idx := left.ChildByFieldName("index")
		if idx != nil && idx.Type() == "string" {
			tb.store(base, stringValue(tb.f, idx), "", v, n)
		} else {
			tb.assign(base, n, v)
			tb.noteAssign(base)
		}
	case "object_pattern", "array_pattern":
		tb.destructure(left, v, "")
	}
	return v
}

func (tb *tsBuilder) args(n *sitter.Node) []ir.VarID {
	var out []ir.VarID
	for _, a := range named(n) {
		if a.Type() == "comment" {
			continue
		}
		out = append(out, tb.expr(a))
	}
	return out
}

// staticPath resolves imports and globals: Sentry.setUser -> "@sentry/react",
// window.localStorage -> "localStorage", mixpanel.people -> "mixpanel-browser.people".
func (tb *tsBuilder) staticPath(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		name := tb.text(n)
		if _, local := tb.scope[name]; local {
			return ""
		}
		if q, ok := tb.f.imports[name]; ok {
			return q
		}
		if tsGlobals[name] {
			return name
		}
	case "member_expression":
		obj := n.ChildByFieldName("object")
		prop := tb.text(n.ChildByFieldName("property"))
		if obj.Type() == "identifier" {
			switch tb.text(obj) {
			case "window", "globalThis", "self", "global":
				if _, local := tb.scope[tb.text(obj)]; !local {
					if tsGlobals[prop] {
						return prop
					}
					return ""
				}
			}
		}
		if p := tb.staticPath(obj); p != "" {
			return p + "." + prop
		}
	}
	return ""
}

func (tb *tsBuilder) typeOf(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		if v, ok := tb.scope[tb.text(n)]; ok {
			return tb.fn.Vars[v].Type
		}
	case "this":
		if tb.cls != nil {
			return tb.cls.name
		}
	case "member_expression":
		if owner := tb.typeOf(n.ChildByFieldName("object")); owner != "" {
			return tb.tp.fieldType(owner, tb.text(n.ChildByFieldName("property")))
		}
	case "new_expression":
		return tb.tp.resolveType(tb.f, tb.text(n.ChildByFieldName("constructor")))
	case "parenthesized_expression", "non_null_expression", "await_expression":
		if k := named(n); len(k) > 0 {
			return tb.typeOf(k[0])
		}
	case "as_expression":
		k := named(n)
		if len(k) > 1 {
			return tb.tp.resolveType(tb.f, tb.text(k[len(k)-1]))
		}
	}
	return ""
}

func unwrapCallee(n *sitter.Node) *sitter.Node {
	for n != nil {
		switch n.Type() {
		case "await_expression", "parenthesized_expression", "non_null_expression":
			k := named(n)
			if len(k) == 0 {
				return n
			}
			n = k[0]
		default:
			return n
		}
	}
	return n
}

func (tb *tsBuilder) call(n *sitter.Node) ir.VarID {
	fn := unwrapCallee(n.ChildByFieldName("function"))
	switch fn.Type() {
	case "identifier":
		name := tb.text(fn)
		args := tb.args(n.ChildByFieldName("arguments"))
		if name == "require" {
			return tb.temp(n)
		}
		if v, local := tb.scope[name]; local {
			return tb.emitCall(n, &ir.Call{Name: name, HasRecv: true, RecvText: name}, append([]ir.VarID{v}, args...), "")
		}
		if id, ok := tb.tp.top[tb.f.pkg+"."+name]; ok {
			return tb.emitCall(n, &ir.Call{Callee: id, Name: name, Target: id}, args, "")
		}
		if q, ok := tb.f.imports[name]; ok {
			c := &ir.Call{Callee: q, Name: name}
			if i := strings.LastIndexByte(q, '.'); i > 0 {
				if id := q[:i] + ":" + q[i+1:]; tb.tp.known(id) {
					c.Target = id
				}
				c.Name = q[i+1:]
			}
			return tb.emitCall(n, c, args, "")
		}
		return tb.emitCall(n, &ir.Call{Callee: name, Name: name}, args, "")
	case "member_expression":
		obj := unwrapCallee(fn.ChildByFieldName("object"))
		m := tb.text(fn.ChildByFieldName("property"))
		if p := tb.staticPath(obj); p != "" {
			args := tb.args(n.ChildByFieldName("arguments"))
			c := &ir.Call{Callee: p + "." + m, Name: m, RecvText: trimText(tb.text(obj))}
			if i := strings.LastIndexByte(p, '.'); i < 0 && tb.tp.known(p+":"+m) {
				c.Target = p + ":" + m // namespace import of a local module
			}
			return tb.emitCall(n, c, args, "")
		}
		if obj.Type() == "call_expression" {
			// factory().method(): e.g. analytics().logEvent(...)
			inner := unwrapCallee(obj.ChildByFieldName("function"))
			if p := tb.staticPath(inner); p != "" {
				recv := tb.expr(obj)
				args := tb.args(n.ChildByFieldName("arguments"))
				c := &ir.Call{Callee: p + "()." + m, Name: m, HasRecv: true, RecvText: trimText(tb.text(obj))}
				return tb.emitCall(n, c, append([]ir.VarID{recv}, args...), "")
			}
		}
		typ := tb.typeOf(obj)
		recv := tb.expr(obj)
		args := tb.args(n.ChildByFieldName("arguments"))
		c := &ir.Call{Name: m, HasRecv: true, RecvType: typ, RecvText: trimText(tb.text(obj))}
		if typ != "" {
			if id := tb.tp.methodID(typ, m, 0); id != "" {
				c.Target, c.Callee = id, id
				if tb.tp.static[id] {
					c.HasRecv = false
					return tb.emitCall(n, c, args, "")
				}
			} else if strings.ContainsAny(typ, "./") {
				c.Callee = typ + "." + m
			}
		}
		return tb.emitCall(n, c, append([]ir.VarID{recv}, args...), "")
	}
	fv := tb.expr(fn)
	args := tb.args(n.ChildByFieldName("arguments"))
	return tb.emitCall(n, &ir.Call{Name: "call", HasRecv: true, RecvText: trimText(tb.text(fn))}, append([]ir.VarID{fv}, args...), "")
}
