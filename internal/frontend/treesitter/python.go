// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"path"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// NewPython returns the Python frontend.
func NewPython(o frontend.Options) frontend.Frontend { return &pyFrontend{opts: o} }

type pyFrontend struct{ opts frontend.Options }

func (fe *pyFrontend) Lang() string { return lang.Python }

// pyProgram lowers Python. Modules are dotted paths ("app.services.user"),
// functions are "<module>:<name>" and methods "<module>:<Class>.<name>";
// imported names resolve to "<module>.<name>" as rules are written
// ("sentry_sdk.set_user", "logging.info").
type pyProgram struct {
	*program
	static map[string]bool // static and class methods: called without self
}

func (fe *pyFrontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	pp := &pyProgram{program: newProgram(lang.Python, fe.opts), static: map[string]bool{}}
	pp.parse(ctx, files, python.GetLanguage())
	for _, f := range pp.files {
		f.pkg = pyModuleID(f.rel)
		pp.modules[f.pkg] = true
	}
	for _, f := range pp.files {
		pp.header(f)
	}
	for _, f := range pp.files {
		pp.collect(f)
	}
	for _, c := range pp.classes {
		for k, t := range c.fields {
			c.fields[k] = pp.resolveType(c.file, t)
		}
		for i, s := range c.supers {
			c.supers[i] = pp.resolveType(c.file, s)
		}
	}
	for _, f := range pp.files {
		pp.lowerFile(f)
	}
	return pp.mod, nil
}

// pyModuleID is the dotted module name of a file: app/models/user.py is
// app.models.user and app/models/__init__.py is app.models.
func pyModuleID(rel string) string {
	m := strings.TrimSuffix(rel, path.Ext(rel))
	m = strings.TrimSuffix(m, "/__init__")
	return strings.ReplaceAll(m, "/", ".")
}

// resolveModule maps a module name as written in an import to a module
// id, handling relative imports (from .models import User).
func (pp *pyProgram) resolveModule(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	if n.Type() != "relative_import" {
		return f.text(n)
	}
	dots, rest := 0, ""
	for _, c := range named(n) {
		switch c.Type() {
		case "import_prefix":
			dots = strings.Count(f.text(c), ".")
		case "dotted_name":
			rest = f.text(c)
		}
	}
	// "." is the file's own package; each further dot goes up one level.
	base := f.pkg
	if path.Base(f.rel) != "__init__.py" {
		base = pyParent(base)
	}
	for i := 1; i < dots; i++ {
		base = pyParent(base)
	}
	switch {
	case base == "":
		return rest
	case rest == "":
		return base
	}
	return base + "." + rest
}

func (pp *pyProgram) header(f *srcFile) {
	for _, st := range named(f.root) {
		switch st.Type() {
		case "import_statement":
			for _, c := range named(st) {
				switch c.Type() {
				case "dotted_name":
					full := f.text(c)
					head, _, _ := strings.Cut(full, ".")
					f.imports[head] = head
				case "aliased_import":
					f.imports[f.text(c.ChildByFieldName("alias"))] = f.text(c.ChildByFieldName("name"))
				}
			}
		case "import_from_statement":
			mod := pp.resolveModule(f, st.ChildByFieldName("module_name"))
			for i := 0; i < int(st.NamedChildCount()); i++ {
				c := st.NamedChild(i)
				if st.FieldNameForChild(pyChildIndex(st, c)) == "module_name" {
					continue
				}
				switch c.Type() {
				case "dotted_name":
					f.imports[f.text(c)] = mod + "." + f.text(c)
				case "aliased_import":
					f.imports[f.text(c.ChildByFieldName("alias"))] = mod + "." + f.text(c.ChildByFieldName("name"))
				case "wildcard_import":
					f.wildcards = append(f.wildcards, mod)
				}
			}
		}
	}
}

func pyParent(mod string) string {
	if i := strings.LastIndexByte(mod, '.'); i >= 0 {
		return mod[:i]
	}
	return ""
}

// pyChildIndex is the child index of a named child, for FieldNameForChild.
func pyChildIndex(parent, child *sitter.Node) int {
	for i := 0; i < int(parent.ChildCount()); i++ {
		if parent.Child(i).Equal(child) {
			return i
		}
	}
	return -1
}

// pyDefs yields the definitions in a block, unwrapping decorators.
func pyDefs(n *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for _, c := range named(n) {
		if c.Type() == "decorated_definition" {
			if d := c.ChildByFieldName("definition"); d != nil {
				out = append(out, d)
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// pyDecorators returns the decorator names of a definition (dataclass,
// staticmethod, app.route).
func pyDecorators(f *srcFile, def *sitter.Node) []string {
	p := def.Parent()
	if p == nil || p.Type() != "decorated_definition" {
		return nil
	}
	var out []string
	for _, d := range allOf(p, "decorator") {
		k := named(d)
		if len(k) == 0 {
			continue
		}
		e := k[0]
		if e.Type() == "call" {
			e = e.ChildByFieldName("function")
		}
		out = append(out, shortName(f.text(e)))
	}
	return out
}

// pyTypeName reduces an annotation to the type it holds: Optional[User],
// User | None and "User" are User; list[User] is list.
func pyTypeName(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	t := strings.Trim(strings.TrimSpace(f.text(n)), `"'`)
	if strings.HasPrefix(t, "Optional[") && strings.HasSuffix(t, "]") {
		t = t[len("Optional[") : len(t)-1]
	}
	if i := strings.Index(t, "|"); i > 0 {
		a, b := strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:])
		if a == "None" {
			a = b
		}
		t = a
	}
	if i := strings.IndexByte(t, '['); i > 0 {
		t = t[:i]
	}
	return strings.TrimSpace(t)
}

var pyEntityBases = map[string]bool{"Model": true, "Base": true, "DeclarativeBase": true, "Document": true, "SQLModel": true, "Entity": true}
var pyDataBases = map[string]bool{"BaseModel": true, "TypedDict": true, "NamedTuple": true, "Schema": true, "Struct": true}

func (pp *pyProgram) collect(f *srcFile) {
	for _, d := range pyDefs(f.root) {
		switch d.Type() {
		case "function_definition":
			name := f.text(d.ChildByFieldName("name"))
			id := f.pkg + ":" + name
			pp.funcs[id] = true
			pp.top[f.pkg+"."+name] = id
		case "class_definition":
			pp.collectClass(f, d)
		}
	}
}

func (pp *pyProgram) collectClass(f *srcFile, d *sitter.Node) {
	short := f.text(d.ChildByFieldName("name"))
	if short == "" {
		return
	}
	qname := f.pkg + "." + short
	ci := &classInfo{name: qname, short: short, file: f, fields: map[string]string{}, methods: map[string]string{}}
	decos := pyDecorators(f, d)
	td := &ir.TypeDecl{Name: qname, Kind: "class", Lang: lang.Python, Annotations: decos, Pos: posOf(f, d)}
	kind := ""
	for _, s := range named(d.ChildByFieldName("superclasses")) {
		if s.Type() == "keyword_argument" {
			if f.text(s.ChildByFieldName("name")) == "table" && f.text(s.ChildByFieldName("value")) == "True" {
				kind = "entity" // SQLModel(table=True)
			}
			continue
		}
		base := f.text(s)
		ci.supers = append(ci.supers, base)
		switch sb := shortName(base); {
		case pyEntityBases[sb] && kind == "":
			kind = "entity"
		case pyDataBases[sb] && kind == "":
			kind = "data"
		}
	}
	for _, dn := range decos {
		switch dn {
		case "dataclass", "define", "frozen", "attrs", "s", "dataclass_json":
			if kind == "" {
				kind = "data"
			}
		}
	}
	body := d.ChildByFieldName("body")
	for _, st := range pyDefs(body) {
		switch st.Type() {
		case "expression_statement":
			for _, a := range allOf(st, "assignment") {
				left := a.ChildByFieldName("left")
				if left == nil || left.Type() != "identifier" {
					continue
				}
				fn := f.text(left)
				typ := pyTypeName(f, a.ChildByFieldName("type"))
				tags := pyFieldTags(f, a.ChildByFieldName("right"))
				if typ == "" && a.ChildByFieldName("type") == nil && tags == nil && !pyIsFieldCall(f, a.ChildByFieldName("right")) {
					continue // a class constant, not a field
				}
				ci.fields[fn] = typ
				td.Fields = append(td.Fields, ir.Field{Name: fn, Type: typ, Tags: tags, Pos: posOf(f, a)})
			}
		case "function_definition":
			mn := f.text(st.ChildByFieldName("name"))
			id := f.pkg + ":" + short + "." + mn
			pp.funcs[id] = true
			ci.methods[mn] = id
			for _, dn := range pyDecorators(f, st) {
				if dn == "staticmethod" || dn == "classmethod" {
					pp.static[id] = true
				}
			}
			if mn == "__init__" {
				pp.initFields(f, ci, td, st)
			}
		}
	}
	methods := map[string]string{}
	for m, id := range ci.methods {
		if !strings.HasPrefix(m, "__") {
			methods[m] = id
		}
	}
	switch {
	case kind != "":
		td.Kind = kind
	case !hasBehaviour(methods) && len(td.Fields) > 0:
		td.Kind = "data"
	}
	pp.addClass(ci)
	if len(td.Fields) > 0 {
		pp.mod.Types = append(pp.mod.Types, td)
	}
}

// initFields records the fields __init__ assigns (self.email = email),
// typed from their annotation or the parameter they come from.
func (pp *pyProgram) initFields(f *srcFile, ci *classInfo, td *ir.TypeDecl, init *sitter.Node) {
	ptypes := map[string]string{}
	for _, p := range named(init.ChildByFieldName("parameters")) {
		if p.Type() == "typed_parameter" || p.Type() == "typed_default_parameter" {
			name := p.ChildByFieldName("name")
			if name == nil {
				name = firstOf(p, "identifier")
			}
			ptypes[f.text(name)] = pyTypeName(f, p.ChildByFieldName("type"))
		}
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		for _, c := range named(n) {
			switch c.Type() {
			case "function_definition", "class_definition", "lambda":
				continue
			case "assignment":
				left := c.ChildByFieldName("left")
				if left != nil && left.Type() == "attribute" && f.text(left.ChildByFieldName("object")) == "self" {
					fn := f.text(left.ChildByFieldName("attribute"))
					if _, seen := ci.fields[fn]; !seen {
						typ := pyTypeName(f, c.ChildByFieldName("type"))
						if r := c.ChildByFieldName("right"); typ == "" && r != nil && r.Type() == "identifier" {
							typ = ptypes[f.text(r)]
						}
						ci.fields[fn] = typ
						td.Fields = append(td.Fields, ir.Field{Name: fn, Type: typ, Pos: posOf(f, c)})
					}
				}
			}
			walk(c)
		}
	}
	walk(init.ChildByFieldName("body"))
}

// pyIsFieldCall reports ORM and schema field constructors:
// models.EmailField(), Column(String), mapped_column(), Field(...).
func pyIsFieldCall(f *srcFile, n *sitter.Node) bool {
	if n == nil || n.Type() != "call" {
		return false
	}
	name := shortName(f.text(n.ChildByFieldName("function")))
	return strings.HasSuffix(name, "Field") || name == "Column" || name == "mapped_column" || name == "field" || name == "attrib" || name == "ib"
}

// pyFieldTags reads schema hints from a field constructor: the column
// name (Django db_column, SQLAlchemy Column("name", ...)) and the
// serialized name (Pydantic alias).
func pyFieldTags(f *srcFile, n *sitter.Node) map[string]string {
	if !pyIsFieldCall(f, n) {
		return nil
	}
	tags := map[string]string{}
	args := named(n.ChildByFieldName("arguments"))
	for i, a := range args {
		switch a.Type() {
		case "string":
			if i == 0 && shortName(f.text(n.ChildByFieldName("function"))) != "Field" {
				tags["column"] = pyString(f, a)
			}
		case "keyword_argument":
			v := a.ChildByFieldName("value")
			if v == nil || v.Type() != "string" {
				continue
			}
			switch f.text(a.ChildByFieldName("name")) {
			case "db_column", "name":
				tags["column"] = pyString(f, v)
			case "alias", "serialization_alias", "validation_alias":
				tags["json"] = pyString(f, v)
			}
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// pyString is the value of a string literal without interpolations.
func pyString(f *srcFile, n *sitter.Node) string {
	var sb strings.Builder
	for _, c := range named(n) {
		if c.Type() == "string_content" {
			sb.WriteString(f.text(c))
		}
	}
	return sb.String()
}

func (pp *pyProgram) lowerFile(f *srcFile) {
	var init *pyBuilder
	getInit := func(n *sitter.Node) *pyBuilder {
		if init == nil {
			init = &pyBuilder{builder: pp.newBuilder(f, nil, f.pkg+":<init>", "<init>", n), pp: pp}
		}
		return init
	}
	for _, d := range pyDefs(f.root) {
		switch d.Type() {
		case "import_statement", "import_from_statement", "future_import_statement", "comment":
		case "function_definition":
			name := f.text(d.ChildByFieldName("name"))
			pp.lowerFunction(f, nil, f.pkg+":"+name, name, d, false)
		case "class_definition":
			pp.lowerClass(f, d)
		default:
			getInit(d).stmt(d)
		}
	}
	if init != nil && len(init.fn.Instrs) > 0 {
		init.finish()
	}
}

func (pp *pyProgram) lowerClass(f *srcFile, d *sitter.Node) {
	short := f.text(d.ChildByFieldName("name"))
	ci := pp.classes[f.pkg+"."+short]
	if ci == nil || ci.file != f {
		return
	}
	for _, st := range pyDefs(d.ChildByFieldName("body")) {
		if st.Type() == "function_definition" {
			mn := f.text(st.ChildByFieldName("name"))
			id := f.pkg + ":" + short + "." + mn
			pp.lowerFunction(f, ci, id, mn, st, pp.static[id])
		}
	}
}

func (pp *pyProgram) lowerFunction(f *srcFile, cls *classInfo, id, name string, n *sitter.Node, static bool) {
	b := pp.newBuilder(f, cls, id, name, n)
	pb := &pyBuilder{builder: b, pp: pp}
	params := named(n.ChildByFieldName("parameters"))
	if cls != nil && !static && len(params) > 0 {
		b.addThis(cls.name, params[0])
		b.scope[pyParamName(f, params[0])] = b.this
		params = params[1:]
	}
	for _, p := range params {
		pb.param(pyParamName(f, p), pp.resolveType(f, pyTypeName(f, p.ChildByFieldName("type"))), p)
	}
	pb.stmt(n.ChildByFieldName("body"))
	b.finish()
}

// pyParamName is the name a parameter binds (email, *args, **kwargs).
func pyParamName(f *srcFile, p *sitter.Node) string {
	switch p.Type() {
	case "identifier":
		return f.text(p)
	case "default_parameter", "typed_default_parameter":
		return f.text(p.ChildByFieldName("name"))
	case "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern":
		if id := firstOf(p, "identifier"); id != nil {
			return f.text(id)
		}
	}
	return ""
}

type pyBuilder struct {
	*builder
	pp *pyProgram
}

func (pb *pyBuilder) stmt(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "block", "module", "else_clause", "finally_clause", "elif_clause", "if_statement", "while_statement", "try_statement",
		"match_statement", "case_clause", "decorated_definition":
		last := ir.NoVar
		for _, c := range named(n) {
			last = pb.stmt(c)
		}
		return last
	case "expression_statement":
		last := ir.NoVar
		for _, c := range named(n) {
			last = pb.expr(c)
		}
		return last
	case "return_statement":
		var v ir.VarID = ir.NoVar
		if k := named(n); len(k) > 0 {
			v = pb.expr(k[0])
		}
		pb.ret(n, v)
		return ir.NoVar
	case "for_statement":
		iter := pb.expr(n.ChildByFieldName("right"))
		pb.bind(n.ChildByFieldName("left"), iter)
		pb.stmt(n.ChildByFieldName("body"))
		pb.stmt(n.ChildByFieldName("alternative"))
		return ir.NoVar
	case "except_clause":
		for _, c := range named(n) {
			switch c.Type() {
			case "as_pattern":
				if t := c.ChildByFieldName("alias"); t != nil {
					pb.bind(firstOf(t, "identifier"), pb.temp(c))
				}
			case "block":
				pb.stmt(c)
			}
		}
		return ir.NoVar
	case "with_statement":
		for _, item := range allOf(firstOf(n, "with_clause"), "with_item") {
			v := item.ChildByFieldName("value")
			if v != nil && v.Type() == "as_pattern" {
				k := named(v)
				val := pb.expr(k[0])
				if t := v.ChildByFieldName("alias"); t != nil {
					for _, id := range named(t) {
						pb.bind(id, val)
					}
				}
				continue
			}
			pb.expr(v)
		}
		pb.stmt(n.ChildByFieldName("body"))
		return ir.NoVar
	case "function_definition":
		fv := pb.lambdaFn(n.ChildByFieldName("parameters"), n.ChildByFieldName("body"), n)
		dst := pb.declare(pb.text(n.ChildByFieldName("name")), "", n)
		pb.assign(dst, n, fv)
		return ir.NoVar
	case "raise_statement", "assert_statement":
		for _, c := range named(n) {
			pb.expr(c)
		}
		return ir.NoVar
	case "class_definition", "comment", "pass_statement", "break_statement", "continue_statement", "import_statement",
		"import_from_statement", "global_statement", "nonlocal_statement", "delete_statement", "future_import_statement":
		return ir.NoVar
	}
	return pb.expr(n)
}

// bind assigns v to the names a target binds: x, (a, b), [a, *b], obj.attr.
func (pb *pyBuilder) bind(t *sitter.Node, v ir.VarID) {
	if t == nil {
		return
	}
	switch t.Type() {
	case "identifier":
		name := pb.text(t)
		dst, ok := pb.scope[name]
		if !ok {
			dst = pb.declare(name, "", t)
		}
		pb.assign(dst, t, v)
		pb.noteAssign(dst)
	case "pattern_list", "tuple_pattern", "list_pattern", "tuple", "list", "expression_list":
		for _, c := range named(t) {
			pb.bind(c, v)
		}
	case "list_splat_pattern", "parenthesized_expression":
		for _, c := range named(t) {
			pb.bind(c, v)
		}
	case "attribute":
		obj := t.ChildByFieldName("object")
		pb.store(pb.expr(obj), pb.text(t.ChildByFieldName("attribute")), pb.typeOf(obj), v, t)
	case "subscript":
		base := pb.expr(t.ChildByFieldName("value"))
		if k := t.ChildByFieldName("subscript"); k != nil && k.Type() == "string" {
			pb.store(base, pyString(pb.f, k), "", v, t)
			return
		}
		pb.assign(base, t, v)
		pb.noteAssign(base)
	}
}

func (pb *pyBuilder) assignment(n *sitter.Node) ir.VarID {
	right := n.ChildByFieldName("right")
	v := ir.NoVar
	if right != nil {
		v = pb.expr(right)
	}
	left := n.ChildByFieldName("left")
	if n.Type() == "augmented_assignment" {
		old := pb.expr(left)
		sum := pb.temp(n)
		pb.assign(sum, n, old, v)
		v = sum
	}
	if left != nil && left.Type() == "identifier" && v == ir.NoVar {
		// A bare annotation (x: str) declares without assigning.
		pb.declare(pb.text(left), pb.pp.resolveType(pb.f, pyTypeName(pb.f, n.ChildByFieldName("type"))), left)
		return ir.NoVar
	}
	pb.bind(left, v)
	if left != nil && left.Type() == "identifier" {
		dst := pb.scope[pb.text(left)]
		typ := pb.pp.resolveType(pb.f, pyTypeName(pb.f, n.ChildByFieldName("type")))
		if typ == "" && right != nil {
			typ = pb.typeOf(right)
		}
		if typ != "" {
			pb.fn.Vars[dst].Type = typ
		}
	}
	return v
}

func (pb *pyBuilder) expr(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "identifier":
		name := pb.text(n)
		if _, local := pb.scope[name]; !local {
			if q, ok := pb.f.imports[name]; ok {
				return pb.fn.Named(name, q, pb.pos(n))
			}
		}
		return pb.ident(name, n)
	case "string":
		subs := allOf(n, "interpolation")
		if len(subs) == 0 {
			return pb.constVar(pyString(pb.f, n), n)
		}
		var parts []ir.VarID
		for _, s := range subs {
			parts = append(parts, pb.expr(s.ChildByFieldName("expression")))
		}
		dst := pb.temp(n)
		pb.assign(dst, n, parts...)
		return dst
	case "integer", "float", "true", "false", "none", "ellipsis":
		return pb.constVar(pb.text(n), n)
	case "attribute":
		obj := n.ChildByFieldName("object")
		attr := pb.text(n.ChildByFieldName("attribute"))
		if p := pb.staticPath(obj); p != "" {
			o := pb.fn.Named(shortName(p), p, pb.pos(obj))
			return pb.load(o, attr, p, n)
		}
		owner := pb.typeOf(obj)
		return pb.load(pb.expr(obj), attr, owner, n)
	case "subscript":
		base := pb.expr(n.ChildByFieldName("value"))
		if k := n.ChildByFieldName("subscript"); k != nil && k.Type() == "string" {
			return pb.load(base, pyString(pb.f, k), "", n)
		}
		for _, k := range named(n)[1:] {
			pb.expr(k)
		}
		dst := pb.temp(n)
		pb.assign(dst, n, base)
		return dst
	case "call":
		return pb.call(n)
	case "assignment", "augmented_assignment":
		return pb.assignment(n)
	case "named_expression":
		v := pb.expr(n.ChildByFieldName("value"))
		pb.bind(n.ChildByFieldName("name"), v)
		return v
	case "await", "parenthesized_expression", "list_splat", "dictionary_splat", "unary_operator", "type", "keyword_argument":
		k := named(n)
		if len(k) == 0 {
			return pb.temp(n)
		}
		return pb.expr(k[len(k)-1])
	case "comparison_operator", "not_operator":
		for _, c := range named(n) {
			pb.expr(c)
		}
		return pb.temp(n)
	case "conditional_expression":
		k := named(n)
		var parts []ir.VarID
		for i, c := range k {
			v := pb.expr(c)
			if i != 1 { // a if cond else b
				parts = append(parts, v)
			}
		}
		dst := pb.temp(n)
		pb.assign(dst, n, parts...)
		return dst
	case "dictionary":
		var parts []ir.VarID
		for _, c := range named(n) {
			if c.Type() == "pair" {
				key := c.ChildByFieldName("key")
				v := pb.expr(c.ChildByFieldName("value"))
				if key != nil && key.Type() == "string" {
					nv := pb.fn.Named(pyString(pb.f, key), "", pb.pos(key))
					pb.assign(nv, c, v)
					parts = append(parts, nv)
					continue
				}
				parts = append(parts, v)
				continue
			}
			parts = append(parts, pb.expr(c))
		}
		dst := pb.temp(n)
		pb.assign(dst, n, parts...)
		return dst
	case "list_comprehension", "set_comprehension", "generator_expression", "dictionary_comprehension":
		for _, c := range named(n) {
			if c.Type() == "for_in_clause" {
				pb.bind(c.ChildByFieldName("left"), pb.expr(c.ChildByFieldName("right")))
			}
		}
		body := n.ChildByFieldName("body")
		v := pb.expr(body)
		dst := pb.temp(n)
		pb.assign(dst, n, v)
		return dst
	case "lambda":
		return pb.lambdaFn(n.ChildByFieldName("parameters"), n.ChildByFieldName("body"), n)
	case "comment":
		return pb.temp(n)
	}
	// binary_operator, boolean_operator, concatenated_string, list, tuple,
	// set, expression_list, pattern_list: the value carries every part.
	var parts []ir.VarID
	for _, c := range named(n) {
		parts = append(parts, pb.expr(c))
	}
	dst := pb.temp(n)
	pb.assign(dst, n, parts...)
	return dst
}

// lambdaFn lowers a lambda or a nested function inline.
func (pb *pyBuilder) lambdaFn(params, body, n *sitter.Node) ir.VarID {
	var nodes []*sitter.Node
	var names []string
	for _, p := range named(params) {
		if name := pyParamName(pb.f, p); name != "" {
			nodes, names = append(nodes, p), append(names, name)
		}
	}
	return pb.lambda(n, nodes, names, false, func() ir.VarID {
		if body == nil {
			return ir.NoVar
		}
		if body.Type() == "block" {
			return pb.stmt(body)
		}
		return pb.expr(body)
	})
}

// args lowers call arguments: positional ones in order, then each keyword
// argument as a value named after its keyword (email=x), so the keyword
// labels the value the way a dictionary key does.
func (pb *pyBuilder) args(n *sitter.Node) []ir.VarID {
	var out, kw []ir.VarID
	for _, a := range named(n) {
		switch a.Type() {
		case "comment":
		case "keyword_argument":
			v := pb.expr(a.ChildByFieldName("value"))
			nv := pb.fn.Named(pb.text(a.ChildByFieldName("name")), "", pb.pos(a))
			pb.assign(nv, a, v)
			kw = append(kw, nv)
		default:
			out = append(out, pb.expr(a))
		}
	}
	return append(out, kw...)
}

// staticPath resolves module references: logging.info is "logging.info",
// sentry_sdk.set_user is "sentry_sdk.set_user", rq.post (import requests
// as rq) is "requests.post".
func (pb *pyBuilder) staticPath(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		name := pb.text(n)
		if _, local := pb.scope[name]; local {
			return ""
		}
		if q, ok := pb.f.imports[name]; ok {
			if pb.pp.class(q) != nil {
				return "" // an imported class: its attributes are class members
			}
			return q
		}
	case "attribute":
		if p := pb.staticPath(n.ChildByFieldName("object")); p != "" {
			return p + "." + pb.text(n.ChildByFieldName("attribute"))
		}
	}
	return ""
}

func (pb *pyBuilder) typeOf(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		if v, ok := pb.scope[pb.text(n)]; ok {
			return pb.fn.Vars[v].Type
		}
		if c := pb.pp.class(pb.pp.resolveType(pb.f, pb.text(n))); c != nil {
			return c.name
		}
	case "attribute":
		if owner := pb.typeOf(n.ChildByFieldName("object")); owner != "" {
			return pb.pp.fieldType(owner, pb.text(n.ChildByFieldName("attribute")))
		}
	case "call":
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "identifier" {
			if _, local := pb.scope[pb.text(fn)]; !local {
				if c := pb.pp.class(pb.pp.resolveType(pb.f, pb.text(fn))); c != nil {
					return c.name
				}
			}
		}
	case "parenthesized_expression", "await":
		if k := named(n); len(k) > 0 {
			return pb.typeOf(k[0])
		}
	}
	return ""
}

func (pb *pyBuilder) call(n *sitter.Node) ir.VarID {
	fn := n.ChildByFieldName("function")
	argsNode := n.ChildByFieldName("arguments")
	if argsNode != nil && argsNode.Type() == "generator_expression" {
		// f(x for x in xs): one generator argument.
		wrapped := pb.expr(argsNode)
		return pb.callWith(n, fn, []ir.VarID{wrapped})
	}
	return pb.callWith(n, fn, nil)
}

func (pb *pyBuilder) callWith(n, fn *sitter.Node, pre []ir.VarID) ir.VarID {
	args := func() []ir.VarID {
		if pre != nil {
			return pre
		}
		return pb.args(n.ChildByFieldName("arguments"))
	}
	switch fn.Type() {
	case "identifier":
		name := pb.text(fn)
		if v, local := pb.scope[name]; local {
			return pb.emitCall(n, &ir.Call{Name: name, HasRecv: true, RecvText: name}, append([]ir.VarID{v}, args()...), "")
		}
		if id, ok := pb.pp.top[pb.f.pkg+"."+name]; ok {
			return pb.emitCall(n, &ir.Call{Callee: id, Name: name, Target: id}, args(), "")
		}
		if c := pb.pp.class(pb.pp.resolveType(pb.f, name)); c != nil {
			return pb.construct(n, c, args())
		}
		if q, ok := pb.f.imports[name]; ok {
			c := &ir.Call{Callee: q, Name: shortName(q)}
			if i := strings.LastIndexByte(q, '.'); i > 0 {
				if id := q[:i] + ":" + q[i+1:]; pb.pp.known(id) {
					c.Target = id
				}
			}
			return pb.emitCall(n, c, args(), "")
		}
		return pb.emitCall(n, &ir.Call{Callee: name, Name: name}, args(), "")
	case "attribute":
		obj := fn.ChildByFieldName("object")
		m := pb.text(fn.ChildByFieldName("attribute"))
		if p := pb.staticPath(obj); p != "" {
			c := &ir.Call{Callee: p + "." + m, Name: m, RecvText: trimText(pb.text(obj))}
			if pb.pp.modules[p] && pb.pp.known(p+":"+m) {
				c.Target = p + ":" + m // import app.util; app.util.helper()
			}
			return pb.emitCall(n, c, args(), "")
		}
		if obj.Type() == "call" {
			// factory().method(): logging.getLogger(__name__).info(...)
			if p := pb.staticPath(obj.ChildByFieldName("function")); p != "" {
				recv := pb.expr(obj)
				c := &ir.Call{Callee: p + "()." + m, Name: m, HasRecv: true, RecvText: trimText(pb.text(obj))}
				return pb.emitCall(n, c, append([]ir.VarID{recv}, args()...), "")
			}
		}
		typ := pb.typeOf(obj)
		if obj.Type() == "identifier" {
			if _, local := pb.scope[pb.text(obj)]; !local {
				if c := pb.pp.class(pb.pp.resolveType(pb.f, pb.text(obj))); c != nil {
					// Class.method(...): a static or class method.
					if id := pb.pp.methodID(c.name, m, 0); id != "" {
						return pb.emitCall(n, &ir.Call{Callee: id, Name: m, Target: id}, args(), "")
					}
				}
			}
		}
		recv := pb.expr(obj)
		c := &ir.Call{Name: m, HasRecv: true, RecvType: typ, RecvText: trimText(pb.text(obj))}
		if typ != "" {
			if id := pb.pp.methodID(typ, m, 0); id != "" {
				c.Target, c.Callee = id, id
				if pb.pp.static[id] {
					c.HasRecv = false
					return pb.emitCall(n, c, args(), "")
				}
			} else if strings.Contains(typ, ".") {
				c.Callee = typ + "." + m
			}
		}
		return pb.emitCall(n, c, append([]ir.VarID{recv}, args()...), "")
	}
	fv := pb.expr(fn)
	return pb.emitCall(n, &ir.Call{Name: "call", HasRecv: true, RecvText: trimText(pb.text(fn))}, append([]ir.VarID{fv}, args()...), "")
}

// construct lowers Class(...): like a constructor in the JVM frontends,
// the new object carries its arguments.
func (pb *pyBuilder) construct(n *sitter.Node, c *classInfo, args []ir.VarID) ir.VarID {
	return pb.emitCall(n, &ir.Call{Callee: c.name, Name: c.short, Construct: true}, args, c.name)
}
