// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/lang"
)

// NewJava returns the java frontend.
func NewJava(o frontend.Options) frontend.Frontend { return &javaFrontend{opts: o} }

type javaFrontend struct{ opts frontend.Options }

func (fe *javaFrontend) Lang() string { return lang.Java }

type jvProgram struct {
	*program
	static  map[string]bool   // method id -> static
	returns map[string]string // method id -> declared return type (as written)
}

func (fe *javaFrontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	jp := &jvProgram{program: newProgram(lang.Java, fe.opts), static: map[string]bool{}, returns: map[string]string{}}
	jp.parse(ctx, files, java.GetLanguage())
	for _, f := range jp.files {
		jp.header(f)
		for _, c := range named(f.root) {
			jp.collectType(f, c, f.pkg)
		}
	}
	for _, c := range jp.classes {
		for k, t := range c.fields {
			c.fields[k] = jp.resolveType(c.file, t)
		}
		for i, s := range c.supers {
			c.supers[i] = jp.resolveType(c.file, s)
		}
	}
	for _, f := range jp.files {
		for _, c := range named(f.root) {
			jp.lowerType(f, c, f.pkg)
		}
	}
	return jp.mod, nil
}

func (jp *jvProgram) header(f *srcFile) {
	for _, c := range named(f.root) {
		switch c.Type() {
		case "package_declaration":
			if id := firstOf(c, "scoped_identifier", "identifier"); id != nil {
				f.pkg = f.text(id)
			}
		case "import_declaration":
			id := firstOf(c, "scoped_identifier", "identifier")
			if id == nil {
				continue
			}
			q := f.text(id)
			if firstOf(c, "asterisk") != nil {
				f.wildcards = append(f.wildcards, q)
				continue
			}
			f.imports[shortName(q)] = q
		}
	}
}

func isTypeDecl(t string) bool {
	switch t {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		return true
	}
	return false
}

func javaTypeText(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	t := f.text(n)
	if i := strings.IndexByte(t, '<'); i > 0 {
		t = t[:i]
	}
	return strings.TrimSpace(strings.TrimSuffix(t, "[]"))
}

// javaAnnotations extracts annotation tags from a modifiers node.
func javaAnnotations(f *srcFile, mods *sitter.Node) (map[string]string, []string, bool) {
	tags := map[string]string{}
	var names []string
	static := false
	if mods == nil {
		return tags, nil, false
	}
	for i := 0; i < int(mods.ChildCount()); i++ {
		c := mods.Child(i)
		switch c.Type() {
		case "static":
			static = true
		case "marker_annotation", "annotation":
			name := shortName(f.text(c.ChildByFieldName("name")))
			names = append(names, name)
			val := ""
			if args := c.ChildByFieldName("arguments"); args != nil {
				for _, a := range named(args) {
					switch a.Type() {
					case "element_value_pair":
						k := f.text(a.ChildByFieldName("key"))
						if k == "name" || k == "value" {
							val = unquote(f.text(a.ChildByFieldName("value")))
						}
					case "string_literal":
						if val == "" {
							val = unquote(f.text(a))
						}
					}
				}
			}
			tags["@"+name] = val
		}
	}
	return tags, names, static
}

func (jp *jvProgram) collectType(f *srcFile, n *sitter.Node, scope string) {
	if !isTypeDecl(n.Type()) {
		return
	}
	name := f.text(n.ChildByFieldName("name"))
	if name == "" {
		return
	}
	qual := name
	if scope != "" {
		qual = scope + "." + name
	}
	ci := &classInfo{name: qual, short: name, file: f, fields: map[string]string{}, methods: map[string]string{}}
	_, annNames, _ := javaAnnotations(f, firstOf(n, "modifiers"))
	td := &ir.TypeDecl{Name: qual, Kind: "class", Lang: lang.Java, Annotations: annNames, Pos: posOf(f, n)}
	if isEntityAnnotation(annNames) {
		td.Kind = "entity"
	}
	if sc := n.ChildByFieldName("superclass"); sc != nil {
		for _, t := range named(sc) {
			ci.supers = append(ci.supers, javaTypeText(f, t))
		}
	}
	for _, fieldName := range []string{"interfaces"} {
		if si := n.ChildByFieldName(fieldName); si != nil {
			for _, tl := range named(si) {
				for _, t := range named(tl) {
					ci.supers = append(ci.supers, javaTypeText(f, t))
				}
			}
		}
	}
	if n.Type() == "record_declaration" {
		if ps := n.ChildByFieldName("parameters"); ps != nil {
			for _, p := range allOf(ps, "formal_parameter") {
				pn := f.text(p.ChildByFieldName("name"))
				typ := javaTypeText(f, p.ChildByFieldName("type"))
				ci.fields[pn] = typ
				tags, _, _ := javaAnnotations(f, firstOf(p, "modifiers"))
				td.Fields = append(td.Fields, ir.Field{Name: pn, Type: typ, Tags: tags, Pos: posOf(f, p)})
			}
		}
	}
	body := n.ChildByFieldName("body")
	var members []*sitter.Node
	for _, m := range named(body) {
		if m.Type() == "enum_body_declarations" {
			members = append(members, named(m)...)
		} else {
			members = append(members, m)
		}
	}
	for _, m := range members {
		switch m.Type() {
		case "field_declaration", "constant_declaration":
			typ := javaTypeText(f, m.ChildByFieldName("type"))
			tags, _, _ := javaAnnotations(f, firstOf(m, "modifiers"))
			for _, d := range allOf(m, "variable_declarator") {
				fn := f.text(d.ChildByFieldName("name"))
				ci.fields[fn] = typ
				td.Fields = append(td.Fields, ir.Field{Name: fn, Type: typ, Tags: tags, Pos: posOf(f, d)})
			}
		case "method_declaration":
			mn := f.text(m.ChildByFieldName("name"))
			id := qual + "." + mn
			if _, dup := ci.methods[mn]; !dup {
				ci.methods[mn] = id
			}
			jp.funcs[id] = true
			_, _, static := javaAnnotations(f, firstOf(m, "modifiers"))
			jp.static[id] = static
			jp.returns[id] = javaTypeText(f, m.ChildByFieldName("type"))
		case "constructor_declaration":
			jp.funcs[qual+".<init>"] = true
		default:
			if isTypeDecl(m.Type()) {
				jp.collectType(f, m, qual)
			}
		}
	}
	if td.Kind != "entity" && (n.Type() == "record_declaration" || !hasBehaviour(ci.methods)) {
		td.Kind = "data"
	}
	jp.addClass(ci)
	if len(td.Fields) > 0 {
		jp.mod.Types = append(jp.mod.Types, td)
	}
}

func (jp *jvProgram) lowerType(f *srcFile, n *sitter.Node, scope string) {
	if !isTypeDecl(n.Type()) {
		return
	}
	name := f.text(n.ChildByFieldName("name"))
	qual := name
	if scope != "" {
		qual = scope + "." + name
	}
	ci := jp.classes[qual]
	if ci == nil {
		return
	}
	body := n.ChildByFieldName("body")
	var members []*sitter.Node
	for _, m := range named(body) {
		if m.Type() == "enum_body_declarations" {
			members = append(members, named(m)...)
		} else {
			members = append(members, m)
		}
	}
	var init *jvBuilder
	getInit := func(at *sitter.Node) *jvBuilder {
		if init == nil {
			b := jp.newBuilder(f, ci, qual+".<init>", "<init>", at)
			b.addThis(qual, at)
			init = &jvBuilder{builder: b, jp: jp}
		}
		return init
	}
	for _, m := range members {
		switch m.Type() {
		case "method_declaration":
			id := qual + "." + f.text(m.ChildByFieldName("name"))
			b := jp.newBuilder(f, ci, id, f.text(m.ChildByFieldName("name")), m)
			if !jp.static[id] {
				b.addThis(qual, m)
			}
			jb := &jvBuilder{builder: b, jp: jp}
			jb.params(m.ChildByFieldName("parameters"))
			jb.stmt(m.ChildByFieldName("body"))
			b.finish()
		case "constructor_declaration", "compact_constructor_declaration":
			b := jp.newBuilder(f, ci, qual+".<init>", "<init>", m)
			b.addThis(qual, m)
			jb := &jvBuilder{builder: b, jp: jp}
			jb.params(m.ChildByFieldName("parameters"))
			jb.stmt(m.ChildByFieldName("body"))
			b.finish()
		case "field_declaration":
			for _, d := range allOf(m, "variable_declarator") {
				if v := d.ChildByFieldName("value"); v != nil {
					ib := getInit(m)
					val := ib.expr(v)
					ib.store(ib.this, f.text(d.ChildByFieldName("name")), qual, val, d)
				}
			}
		case "static_initializer", "block":
			getInit(m).stmt(m)
		default:
			if isTypeDecl(m.Type()) {
				jp.lowerType(f, m, qual)
			}
		}
	}
	if init != nil {
		init.finish()
	}
}

type jvBuilder struct {
	*builder
	jp *jvProgram
}

func (jb *jvBuilder) params(ps *sitter.Node) {
	for _, p := range named(ps) {
		switch p.Type() {
		case "formal_parameter", "spread_parameter":
			nameNode := p.ChildByFieldName("name")
			if nameNode == nil {
				if vd := firstOf(p, "variable_declarator"); vd != nil {
					nameNode = vd.ChildByFieldName("name")
				}
			}
			if nameNode == nil {
				continue
			}
			typ := javaTypeText(jb.f, p.ChildByFieldName("type"))
			if typ == "" {
				typ = javaTypeText(jb.f, firstOf(p, "type_identifier", "generic_type", "scoped_type_identifier"))
			}
			jb.param(jb.text(nameNode), jb.jp.resolveType(jb.f, typ), nameNode)
		}
	}
}

func (jb *jvBuilder) stmt(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "block", "constructor_body", "switch_block", "switch_block_statement_group", "switch_rule":
		last := ir.NoVar
		for _, c := range named(n) {
			last = jb.stmt(c)
		}
		return last
	case "local_variable_declaration":
		typ := jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type")))
		for _, d := range allOf(n, "variable_declarator") {
			var v ir.VarID = ir.NoVar
			if val := d.ChildByFieldName("value"); val != nil {
				v = jb.expr(val)
			}
			t := typ
			if (t == "var" || t == "") && v != ir.NoVar {
				t = jb.fn.Vars[v].Type
			}
			nameNode := d.ChildByFieldName("name")
			dst := jb.declare(jb.text(nameNode), t, nameNode)
			jb.assign(dst, d, v)
		}
		return ir.NoVar
	case "expression_statement":
		for _, c := range named(n) {
			return jb.expr(c)
		}
		return ir.NoVar
	case "return_statement":
		var v ir.VarID = ir.NoVar
		if k := named(n); len(k) > 0 {
			v = jb.expr(k[0])
		}
		jb.ret(n, v)
		return ir.NoVar
	case "enhanced_for_statement":
		iter := jb.expr(n.ChildByFieldName("value"))
		nameNode := n.ChildByFieldName("name")
		if nameNode != nil {
			dst := jb.declare(jb.text(nameNode), jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type"))), nameNode)
			jb.assign(dst, n, iter)
		}
		jb.stmt(n.ChildByFieldName("body"))
		return ir.NoVar
	case "catch_clause":
		if p := firstOf(n, "catch_formal_parameter"); p != nil {
			if nn := p.ChildByFieldName("name"); nn != nil {
				jb.declare(jb.text(nn), "", nn)
			}
		}
		jb.stmt(n.ChildByFieldName("body"))
		return ir.NoVar
	case "resource":
		var v ir.VarID = ir.NoVar
		if val := n.ChildByFieldName("value"); val != nil {
			v = jb.expr(val)
		}
		if nn := n.ChildByFieldName("name"); nn != nil {
			dst := jb.declare(jb.text(nn), jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type"))), nn)
			jb.assign(dst, n, v)
		}
		return ir.NoVar
	case "if_statement", "while_statement", "for_statement", "do_statement", "try_statement", "try_with_resources_statement",
		"synchronized_statement", "labeled_statement", "switch_expression", "switch_statement", "finally_clause", "resource_specification",
		"throw_statement", "yield_statement", "parenthesized_expression", "condition":
		last := ir.NoVar
		for _, c := range named(n) {
			last = jb.stmt(c)
		}
		return last
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "line_comment", "block_comment":
		return ir.NoVar
	}
	return jb.expr(n)
}

var jvBool = map[string]bool{"instanceof_expression": true}

func (jb *jvBuilder) expr(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "identifier":
		name := jb.text(n)
		if _, local := jb.scope[name]; !local {
			if q := jb.classRef(n); q != "" {
				return jb.fn.Named(shortName(q), q, jb.pos(n))
			}
		}
		return jb.ident(name, n)
	case "this", "super":
		if jb.this != ir.NoVar {
			return jb.this
		}
		return jb.ident("this", n)
	case "string_literal", "text_block":
		var sb strings.Builder
		frags := allOf(n, "string_fragment", "multiline_string_fragment")
		if len(frags) == 0 {
			sb.WriteString(unquote(jb.text(n)))
		}
		for _, c := range frags {
			sb.WriteString(jb.text(c))
		}
		return jb.constVar(sb.String(), n)
	case "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
		"decimal_floating_point_literal", "hex_floating_point_literal", "character_literal", "true", "false", "null_literal", "class_literal":
		return jb.constVar(jb.text(n), n)
	case "field_access":
		obj := n.ChildByFieldName("object")
		field := jb.text(n.ChildByFieldName("field"))
		if path := jb.staticPath(obj); path != "" {
			o := jb.fn.Named(shortName(path), path, jb.pos(obj))
			return jb.load(o, field, path, n)
		}
		owner := jb.typeOf(obj)
		return jb.load(jb.expr(obj), field, owner, n)
	case "method_invocation":
		return jb.call(n)
	case "object_creation_expression":
		typ := jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type")))
		args := jb.args(n.ChildByFieldName("arguments"))
		c := &ir.Call{Callee: typ, Name: shortName(typ), Construct: true}
		if cb := firstOf(n, "class_body"); cb != nil {
			anon := jb.lambda(cb, nil, nil, false, func() ir.VarID {
				for _, m := range allOf(cb, "method_declaration") {
					jb.params(m.ChildByFieldName("parameters"))
					jb.stmt(m.ChildByFieldName("body"))
				}
				return ir.NoVar
			})
			args = append(args, anon)
		}
		return jb.emitCall(n, c, args, typ)
	case "array_access":
		base := jb.expr(n.ChildByFieldName("array"))
		jb.expr(n.ChildByFieldName("index"))
		dst := jb.temp(n)
		jb.assign(dst, n, base)
		return dst
	case "assignment_expression":
		return jb.assignment(n)
	case "binary_expression":
		op := ""
		if o := n.ChildByFieldName("operator"); o != nil {
			op = jb.text(o)
		}
		l, r := jb.expr(n.ChildByFieldName("left")), jb.expr(n.ChildByFieldName("right"))
		dst := jb.temp(n)
		switch op {
		case "==", "!=", "<", ">", "<=", ">=", "&&", "||":
			return dst
		}
		jb.assign(dst, n, l, r)
		return dst
	case "ternary_expression":
		jb.expr(n.ChildByFieldName("condition"))
		a, b := jb.expr(n.ChildByFieldName("consequence")), jb.expr(n.ChildByFieldName("alternative"))
		dst := jb.temp(n)
		jb.assign(dst, n, a, b)
		return dst
	case "cast_expression":
		v := jb.expr(n.ChildByFieldName("value"))
		dst := jb.fn.Named("", jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type"))), jb.pos(n))
		jb.assign(dst, n, v)
		return dst
	case "parenthesized_expression":
		if k := named(n); len(k) > 0 {
			return jb.expr(k[0])
		}
	case "unary_expression", "update_expression":
		if k := named(n); len(k) > 0 {
			v := jb.expr(k[len(k)-1])
			if strings.HasPrefix(jb.text(n), "!") {
				return jb.temp(n)
			}
			return v
		}
	case "lambda_expression":
		return jb.lambdaExpr(n)
	case "method_reference":
		return jb.temp(n)
	case "switch_expression":
		return jb.stmt(n)
	default:
		if jvBool[n.Type()] {
			for _, c := range named(n) {
				jb.expr(c)
			}
			return jb.temp(n)
		}
	}
	var parts []ir.VarID
	for _, c := range named(n) {
		parts = append(parts, jb.expr(c))
	}
	dst := jb.temp(n)
	jb.assign(dst, n, parts...)
	return dst
}

func (jb *jvBuilder) lambdaExpr(n *sitter.Node) ir.VarID {
	var pnodes []*sitter.Node
	var pnames []string
	if ps := n.ChildByFieldName("parameters"); ps != nil {
		if ps.Type() == "identifier" {
			pnodes, pnames = append(pnodes, ps), append(pnames, jb.text(ps))
		}
		for _, p := range named(ps) {
			var id *sitter.Node
			switch p.Type() {
			case "identifier":
				id = p
			case "formal_parameter":
				id = p.ChildByFieldName("name")
			}
			if id != nil {
				pnodes, pnames = append(pnodes, id), append(pnames, jb.text(id))
			}
		}
	}
	body := n.ChildByFieldName("body")
	return jb.lambda(n, pnodes, pnames, false, func() ir.VarID {
		if body != nil && body.Type() == "block" {
			return jb.stmt(body)
		}
		return jb.expr(body)
	})
}

func (jb *jvBuilder) assignment(n *sitter.Node) ir.VarID {
	left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
	v := jb.expr(right)
	op := "="
	if o := n.ChildByFieldName("operator"); o != nil {
		op = jb.text(o)
	}
	switch left.Type() {
	case "identifier":
		name := jb.text(left)
		if dst, ok := jb.scope[name]; ok {
			if op != "=" {
				jb.assign(dst, n, dst, v)
			} else {
				jb.assign(dst, n, v)
			}
			jb.noteAssign(dst)
			return dst
		}
		if jb.cls != nil && jb.this != ir.NoVar {
			if _, ok := jb.cls.fields[name]; ok {
				jb.store(jb.this, name, jb.cls.name, v, n)
				return v
			}
		}
		dst := jb.declare(name, "", left)
		jb.assign(dst, n, v)
		return dst
	case "field_access":
		obj := left.ChildByFieldName("object")
		jb.store(jb.expr(obj), jb.text(left.ChildByFieldName("field")), jb.typeOf(obj), v, n)
	case "array_access":
		base := jb.expr(left.ChildByFieldName("array"))
		jb.assign(base, n, v)
		jb.noteAssign(base)
	}
	return v
}

func (jb *jvBuilder) args(n *sitter.Node) []ir.VarID {
	var out []ir.VarID
	for _, a := range named(n) {
		out = append(out, jb.expr(a))
	}
	return out
}

func (jb *jvBuilder) classRef(n *sitter.Node) string {
	if n == nil || n.Type() != "identifier" {
		return ""
	}
	name := jb.text(n)
	if _, local := jb.scope[name]; local || !isUpperStart(name) {
		return ""
	}
	if jb.cls != nil {
		if _, field := jb.cls.fields[name]; field {
			return ""
		}
	}
	return jb.jp.resolveType(jb.f, name)
}

// staticPath resolves a class reference or a static field chain on one
// (System.out) to a qualified path, or "".
func (jb *jvBuilder) staticPath(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		return jb.classRef(n)
	case "field_access":
		obj := n.ChildByFieldName("object")
		if p := jb.staticPath(obj); p != "" {
			return p + "." + jb.text(n.ChildByFieldName("field"))
		}
		// fully qualified: android.util.Log
		txt := strings.ReplaceAll(jb.text(n), " ", "")
		segs := strings.Split(txt, ".")
		if len(segs) >= 2 && !isUpperStart(segs[0]) && isUpperStart(segs[len(segs)-1]) {
			if _, local := jb.scope[segs[0]]; local {
				return ""
			}
			if jb.cls != nil {
				if _, f := jb.cls.fields[segs[0]]; f {
					return ""
				}
			}
			return txt
		}
	case "scoped_identifier":
		return jb.text(n)
	}
	return ""
}

func (jb *jvBuilder) typeOf(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		name := jb.text(n)
		if v, ok := jb.scope[name]; ok {
			return jb.fn.Vars[v].Type
		}
		if jb.cls != nil {
			return jb.jp.fieldType(jb.cls.name, name)
		}
	case "this":
		if jb.cls != nil {
			return jb.cls.name
		}
	case "field_access":
		if owner := jb.typeOf(n.ChildByFieldName("object")); owner != "" {
			return jb.jp.fieldType(owner, jb.text(n.ChildByFieldName("field")))
		}
	case "object_creation_expression":
		return jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type")))
	case "cast_expression":
		return jb.jp.resolveType(jb.f, javaTypeText(jb.f, n.ChildByFieldName("type")))
	case "parenthesized_expression":
		if k := named(n); len(k) > 0 {
			return jb.typeOf(k[0])
		}
	case "method_invocation":
		m := jb.text(n.ChildByFieldName("name"))
		obj := n.ChildByFieldName("object")
		owner := ""
		if obj == nil {
			if jb.cls != nil {
				owner = jb.cls.name
			}
		} else if p := jb.staticPath(obj); p != "" {
			switch m {
			case "getInstance", "getDefault", "instance", "get", "shared":
				if id := jb.jp.methodID(p, m, 0); id == "" {
					return p
				}
			}
			owner = p
		} else {
			owner = jb.typeOf(obj)
		}
		if owner != "" {
			if id := jb.jp.methodID(owner, m, 0); id != "" {
				cls := jb.jp.classes[id[:strings.LastIndexByte(id, '.')]]
				if cls != nil {
					return jb.jp.resolveType(cls.file, jb.jp.returns[id])
				}
			}
		}
	}
	return ""
}

func (jb *jvBuilder) call(n *sitter.Node) ir.VarID {
	m := jb.text(n.ChildByFieldName("name"))
	obj := n.ChildByFieldName("object")
	if obj == nil {
		args := jb.args(n.ChildByFieldName("arguments"))
		if jb.cls != nil {
			if id := jb.jp.methodID(jb.cls.name, m, 0); id != "" {
				c := &ir.Call{Callee: id, Name: m, Target: id, RecvType: jb.cls.name}
				rt := ""
				if cls := jb.jp.classes[id[:strings.LastIndexByte(id, '.')]]; cls != nil {
					rt = jb.jp.resolveType(cls.file, jb.jp.returns[id])
				}
				if !jb.jp.static[id] && jb.this != ir.NoVar {
					c.HasRecv = true
					return jb.emitCall(n, c, append([]ir.VarID{jb.this}, args...), rt)
				}
				return jb.emitCall(n, c, args, rt)
			}
		}
		c := &ir.Call{Name: m}
		if q, ok := jb.f.imports[m]; ok { // static import
			c.Callee = q
			if jb.jp.known(q) {
				c.Target = q
			}
		} else if jb.this != ir.NoVar {
			// Inherited instance method (Activity.startActivity, ...).
			c.HasRecv, c.RecvText = true, "this"
			return jb.emitCall(n, c, append([]ir.VarID{jb.this}, args...), "")
		}
		return jb.emitCall(n, c, args, "")
	}
	if p := jb.staticPath(obj); p != "" {
		args := jb.args(n.ChildByFieldName("arguments"))
		c := &ir.Call{Name: m, RecvType: p, RecvText: trimText(jb.text(obj))}
		if strings.Contains(p, ".") {
			c.Callee = p + "." + m
		}
		rt := ""
		if id := jb.jp.methodID(p, m, 0); id != "" {
			c.Target, c.Callee = id, id
			rt = jb.jp.resolveType(jb.f, jb.jp.returns[id])
		}
		return jb.emitCall(n, c, args, rt)
	}
	typ := jb.typeOf(obj)
	recv := jb.expr(obj)
	args := jb.args(n.ChildByFieldName("arguments"))
	c := &ir.Call{Name: m, HasRecv: true, RecvType: typ, RecvText: trimText(jb.text(obj))}
	if strings.Contains(typ, ".") {
		c.Callee = typ + "." + m
	}
	rt := ""
	if typ != "" {
		if id := jb.jp.methodID(typ, m, 0); id != "" {
			c.Target, c.Callee = id, id
			if cls := jb.jp.classes[id[:strings.LastIndexByte(id, '.')]]; cls != nil {
				rt = jb.jp.resolveType(cls.file, jb.jp.returns[id])
			}
		}
	}
	return jb.emitCall(n, c, append([]ir.VarID{recv}, args...), rt)
}
