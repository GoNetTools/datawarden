// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	tskotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// NewKotlin returns the kotlin frontend.
func NewKotlin(o frontend.Options) frontend.Frontend { return &ktFrontend{opts: o} }

type ktFrontend struct{ opts frontend.Options }

func (fe *ktFrontend) Lang() string { return lang.Kotlin }

// ktExtra is per-class Kotlin information not in classInfo.
type ktExtra struct {
	static  map[string]bool   // methods callable without a receiver (object/companion)
	returns map[string]string // method -> declared return type
	node    *sitter.Node
}

type ktProgram struct {
	*program
	extra map[string]*ktExtra
	// extension functions: id -> receiver type
	extRecv map[string]string
	topRet  map[string]string
}

func (fe *ktFrontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	kp := &ktProgram{program: newProgram(lang.Kotlin, fe.opts), extra: map[string]*ktExtra{}, extRecv: map[string]string{}, topRet: map[string]string{}}
	kp.parse(ctx, files, ktLanguage)
	for _, f := range kp.files {
		kp.header(f)
		kp.collect(f, f.root, f.pkg, nil)
	}
	for _, c := range kp.classes {
		for k, t := range c.fields {
			c.fields[k] = kp.resolveType(c.file, t)
		}
		for i, s := range c.supers {
			c.supers[i] = kp.resolveType(c.file, s)
		}
	}
	for _, f := range kp.files {
		kp.lowerDecls(f, f.root, nil)
	}
	kp.mod.Classes = kp.classTable()
	return kp.mod, nil
}

// ktLanguage is tree-sitter-kotlin 1.x (tree-sitter-grammars), which reads
// current Kotlin: fun interfaces, trailing commas in when conditions,
// function types with qualified receivers, assignments to properties of
// call results.
var ktLanguage = sitter.NewLanguage(tskotlin.Language())

func (kp *ktProgram) header(f *srcFile) {
	if ph := firstOf(f.root, "package_header"); ph != nil {
		if id := firstOf(ph, "qualified_identifier", "identifier"); id != nil {
			f.pkg = f.text(id)
		}
	}
	for _, ih := range allOf(f.root, "import") {
		id := firstOf(ih, "qualified_identifier", "identifier")
		if id == nil {
			continue
		}
		q := f.text(id)
		kids := named(ih)
		switch {
		case hasChildToken(ih, f.src, "*"):
			f.wildcards = append(f.wildcards, q)
		case len(kids) >= 2 && kids[len(kids)-1].Type() == "identifier":
			f.imports[f.text(kids[len(kids)-1])] = q // import a.b.C as D
		default:
			f.imports[shortName(q)] = q
		}
	}
}

func ktTypeText(f *srcFile, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "user_type":
		var parts []string
		for _, c := range named(n) {
			if c.Type() == "identifier" {
				parts = append(parts, f.text(c))
			}
		}
		return strings.Join(parts, ".")
	case "nullable_type", "parenthesized_type", "non_nullable_type":
		return ktTypeText(f, ktTypeChild(n))
	}
	return ""
}

// ktTypeNodes are the node types a type is written as.
var ktTypeNodes = []string{"user_type", "nullable_type", "function_type", "non_nullable_type", "parenthesized_type"}

func ktTypeChild(n *sitter.Node) *sitter.Node {
	return firstOf(n, ktTypeNodes...)
}

func isKtType(n *sitter.Node) bool {
	for _, t := range ktTypeNodes {
		if n.Type() == t {
			return true
		}
	}
	return false
}

// ktName is the name of a declaration: its name field, or its first
// identifier.
func ktName(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	if id := n.ChildByFieldName("name"); id != nil {
		return id
	}
	return firstOf(n, "identifier")
}

// ktIsProperty reports whether a primary constructor parameter declares a
// property (val or var).
func ktIsProperty(f *srcFile, cp *sitter.Node) bool {
	return hasChildToken(cp, f.src, "val") || hasChildToken(cp, f.src, "var")
}

// ktAnnotations returns tags ("@Column" -> "email") and bare annotation names.
func ktAnnotations(f *srcFile, mods *sitter.Node) (map[string]string, []string) {
	tags := map[string]string{}
	var names []string
	if mods == nil {
		return tags, nil
	}
	for _, a := range allOf(mods, "annotation") {
		var tn *sitter.Node
		var args *sitter.Node
		if ci := firstOf(a, "constructor_invocation"); ci != nil {
			tn = firstOf(ci, "user_type")
			args = firstOf(ci, "value_arguments")
		} else {
			tn = firstOf(a, "user_type")
		}
		name := shortName(ktTypeText(f, tn))
		if name == "" {
			continue
		}
		names = append(names, name)
		val := ""
		for _, va := range allOf(args, "value_argument") {
			kids := named(va)
			if len(kids) == 2 && kids[0].Type() == "identifier" {
				if f.text(kids[0]) == "name" || f.text(kids[0]) == "value" {
					val = unquote(f.text(kids[1]))
					break
				}
				continue
			}
			if len(kids) == 1 && val == "" {
				val = unquote(f.text(kids[0]))
			}
		}
		tags["@"+name] = val
	}
	return tags, names
}

func isEntityAnnotation(names []string) bool {
	for _, n := range names {
		switch n {
		case "Entity", "Table", "Document", "RealmClass", "Embeddable", "MappedSuperclass":
			return true
		}
	}
	return false
}

// collect indexes declarations (pass 1).
func (kp *ktProgram) collect(f *srcFile, n *sitter.Node, scope string, outer *classInfo) {
	for _, c := range named(n) {
		switch c.Type() {
		case "class_declaration", "object_declaration":
			kp.collectClass(f, c, scope, c.Type() == "object_declaration")
		case "function_declaration":
			if outer != nil {
				continue
			}
			name, recv := ktFuncName(f, c)
			if name == "" {
				continue
			}
			id := scope + "." + name
			if scope == "" {
				id = name
			}
			kp.funcs[id] = true
			kp.top[scope+"."+name] = id
			if recv != "" {
				kp.ext[name] = append(kp.ext[name], id)
				kp.extRecv[id] = recv
			}
			if rt := ktReturnType(f, c); rt != "" {
				kp.topRet[id] = rt
			}
		}
	}
}

// ktFuncName returns the function name and, for extension functions, the
// receiver type.
func ktFuncName(f *srcFile, fn *sitter.Node) (name, recv string) {
	id := fn.ChildByFieldName("name")
	if id == nil {
		return "", ""
	}
	var lastType *sitter.Node
	for _, c := range named(fn) {
		if c.StartByte() >= id.StartByte() {
			break
		}
		if isKtType(c) {
			lastType = c
		}
	}
	if lastType != nil {
		recv = ktTypeText(f, lastType)
	}
	return f.text(id), recv
}

func ktReturnType(f *srcFile, fn *sitter.Node) string {
	seenParams := false
	for _, c := range named(fn) {
		if c.Type() == "function_value_parameters" {
			seenParams = true
			continue
		}
		if seenParams && isKtType(c) {
			return ktTypeText(f, c)
		}
	}
	return ""
}

func (kp *ktProgram) collectClass(f *srcFile, n *sitter.Node, scope string, isObject bool) {
	nameNode := ktName(n)
	if nameNode == nil {
		return
	}
	qual := f.text(nameNode)
	if scope != "" {
		qual = scope + "." + qual
	}
	ci := &classInfo{name: qual, short: f.text(nameNode), file: f, fields: map[string]string{}, methods: map[string]string{}, isStatic: isObject}
	ex := &ktExtra{static: map[string]bool{}, returns: map[string]string{}, node: n}
	kp.extra[qual] = ex
	mods := firstOf(n, "modifiers")
	_, annNames := ktAnnotations(f, mods)
	td := &ir.TypeDecl{Name: qual, Kind: "class", Lang: lang.Kotlin, Annotations: annNames, Pos: posOf(f, n)}
	kp.funcs[qual+".<init>"] = true // every class gets an initializer function
	if isEntityAnnotation(annNames) {
		td.Kind = "entity"
	}
	if pc := firstOf(n, "primary_constructor"); pc != nil {
		for _, cp := range allOf(firstOf(pc, "class_parameters"), "class_parameter") {
			if !ktIsProperty(f, cp) {
				continue
			}
			id := firstOf(cp, "identifier")
			if id == nil {
				continue
			}
			typ := ktTypeText(f, ktTypeChild(cp))
			ci.fields[f.text(id)] = typ
			tags, _ := ktAnnotations(f, firstOf(cp, "modifiers"))
			td.Fields = append(td.Fields, ir.Field{Name: f.text(id), Type: typ, Tags: tags, Pos: posOf(f, id)})
		}
	}
	for _, ds := range allOf(firstOf(n, "delegation_specifiers"), "delegation_specifier") {
		if ut := ktTypeChild(ds); ut != nil {
			ci.supers = append(ci.supers, ktTypeText(f, ut))
		} else if ci2 := firstOf(ds, "constructor_invocation", "explicit_delegation"); ci2 != nil {
			ci.supers = append(ci.supers, ktTypeText(f, ktTypeChild(ci2)))
		}
	}
	body := firstOf(n, "class_body", "enum_class_body")
	var walkBody func(body *sitter.Node, static bool)
	walkBody = func(body *sitter.Node, static bool) {
		prop := "" // the property a following getter belongs to
		for _, m := range named(body) {
			switch m.Type() {
			case "getter":
				if prop != "" {
					kp.noteGetter(ci, prop)
				}
			case "property_declaration":
				vd := firstOf(m, "variable_declaration")
				if vd == nil {
					continue
				}
				id := firstOf(vd, "identifier")
				prop = f.text(id)
				if firstOf(m, "getter") != nil {
					kp.noteGetter(ci, prop)
				}
				typ := ktTypeText(f, ktTypeChild(vd))
				if typ == "" {
					typ = ktCtorType(f, m)
				}
				ci.fields[f.text(id)] = typ
				tags, _ := ktAnnotations(f, firstOf(m, "modifiers"))
				td.Fields = append(td.Fields, ir.Field{Name: f.text(id), Type: typ, Tags: tags, Pos: posOf(f, id)})
			case "function_declaration":
				name, _ := ktFuncName(f, m)
				if name == "" {
					continue
				}
				id := qual + "." + name
				if _, dup := ci.methods[name]; !dup {
					ci.methods[name] = id
				}
				kp.funcs[id] = true
				if static || isObject {
					ex.static[name] = true
				}
				if rt := ktReturnType(f, m); rt != "" {
					ex.returns[name] = rt
				}
			case "companion_object":
				walkBody(firstOf(m, "class_body"), true)
			case "class_declaration", "object_declaration":
				kp.collectClass(f, m, qual, m.Type() == "object_declaration")
			}
		}
	}
	walkBody(body, false)
	switch {
	case td.Kind == "entity":
	case isObject:
		td.Kind = "object"
	case mods != nil && strings.Contains(f.text(mods), "data"), !hasBehaviour(ci.methods):
		td.Kind = "data"
	}
	kp.addClass(ci)
	if len(td.Fields) > 0 {
		kp.mod.Types = append(kp.mod.Types, td)
	}
}

// ktCtorType guesses a property type from `= Foo(...)`.
func ktCtorType(f *srcFile, prop *sitter.Node) string {
	ce := firstOf(prop, "call_expression")
	if ce == nil {
		return ""
	}
	callee := named(ce)
	if len(callee) > 0 && callee[0].Type() == "identifier" && isUpperStart(f.text(callee[0])) {
		return f.text(callee[0])
	}
	return ""
}

func posOf(f *srcFile, n *sitter.Node) ir.Pos {
	sp := n.StartPoint()
	return ir.Pos{File: f.rel, Line: int(sp.Row) + 1, Col: int(sp.Column) + 1}
}

// lowerDecls lowers function bodies (pass 2).
func (kp *ktProgram) lowerDecls(f *srcFile, n *sitter.Node, cls *classInfo) {
	var topInit *builder
	for _, c := range named(n) {
		switch c.Type() {
		case "class_declaration", "object_declaration":
			kp.lowerClass(f, c, cls)
		case "function_declaration":
			kp.lowerFunc(f, c, nil, false)
		case "property_declaration":
			if topInit == nil {
				id := f.pkg + ".<init:" + shortName(tsModuleID(f.rel)) + ">"
				topInit = kp.newBuilder(f, nil, id, "<init>", c)
			}
			kb := &ktBuilder{builder: topInit, kp: kp}
			kb.stmt(c)
		}
	}
	if topInit != nil && len(topInit.fn.Instrs) > 0 {
		topInit.finish()
	}
}

func (kp *ktProgram) lowerClass(f *srcFile, n *sitter.Node, outer *classInfo) {
	nameNode := ktName(n)
	if nameNode == nil {
		return
	}
	qual := f.text(nameNode)
	if outer != nil {
		qual = outer.name + "." + qual
	} else if f.pkg != "" {
		qual = f.pkg + "." + qual
	}
	ci := kp.classes[qual]
	if ci == nil {
		return
	}
	isObject := n.Type() == "object_declaration"
	// Constructor / initializer: primary constructor params, property
	// initializers, init blocks.
	init := kp.newBuilder(f, ci, qual+".<init>", "<init>", n)
	ib := &ktBuilder{builder: init, kp: kp}
	if !isObject {
		init.addThis(qual, n)
	}
	if pc := firstOf(n, "primary_constructor"); pc != nil {
		for _, cp := range allOf(firstOf(pc, "class_parameters"), "class_parameter") {
			id := firstOf(cp, "identifier")
			if id == nil {
				continue
			}
			typ := kp.resolveType(f, ktTypeText(f, ktTypeChild(cp)))
			v := init.param(f.text(id), typ, id)
			if ktIsProperty(f, cp) && init.this != ir.NoVar {
				init.store(init.this, f.text(id), qual, v, id)
			}
		}
	}
	body := firstOf(n, "class_body", "enum_class_body")
	var walk func(body *sitter.Node, static bool)
	walk = func(body *sitter.Node, static bool) {
		prop := ""
		for _, m := range named(body) {
			switch m.Type() {
			case "getter":
				if prop != "" {
					kp.lowerGetter(f, ci, prop, m)
				}
			case "property_declaration":
				vd := firstOf(m, "variable_declaration")
				if vd != nil {
					prop = f.text(firstOf(vd, "identifier"))
					if g := firstOf(m, "getter"); g != nil {
						kp.lowerGetter(f, ci, prop, g)
					}
				}
				val := ktPropValue(m)
				if vd == nil || val == nil {
					continue
				}
				v := ib.expr(val)
				if init.this != ir.NoVar {
					init.store(init.this, f.text(firstOf(vd, "identifier")), qual, v, m)
				}
			case "anonymous_initializer":
				ib.block(firstOf(m, "block"))
			case "function_declaration":
				kp.lowerFunc(f, m, ci, static || isObject)
			case "secondary_constructor":
				sb := kp.newBuilder(f, ci, qual+".<init>", "<init>", m)
				sb.addThis(qual, m)
				skb := &ktBuilder{builder: sb, kp: kp}
				skb.params(firstOf(m, "function_value_parameters"))
				skb.block(firstOf(m, "block"))
				sb.finish()
			case "companion_object":
				walk(firstOf(m, "class_body"), true)
			case "class_declaration", "object_declaration":
				kp.lowerClass(f, m, ci)
			}
		}
	}
	walk(body, false)
	if len(init.fn.Instrs) > 0 || len(init.fn.Params) > 1 {
		init.finish()
	}
}

// callableRef lowers a Kotlin callable reference: User::class is the class
// (for reflection), User::email a property handle whose get(obj) reads the
// field, and Sender::send or sender::send a function value that calls the
// method with its arguments.
func (kb *ktBuilder) callableRef(n *sitter.Node) ir.VarID {
	kids := named(n)
	text := kb.text(n)
	if len(kids) == 1 && strings.HasSuffix(text, "::class") {
		return kb.constVar(kb.kp.resolveType(kb.f, kb.text(kids[0]))+".class", n)
	}
	if len(kids) < 2 {
		return kb.temp(n)
	}
	owner, member := kids[0], kb.text(kids[len(kids)-1])
	cls := kb.kp.resolveType(kb.f, kb.text(owner))
	if c := kb.kp.class(cls); c != nil {
		if _, isField := c.fields[member]; isField {
			v := kb.temp(n)
			kb.markRefl(v, reflHandle{kind: 'f', class: c.name, member: member})
			return v
		}
	}
	return kb.lambda(n, nil, nil, true, func() ir.VarID {
		it, _ := kb.lookup("it")
		if c := kb.kp.class(cls); c != nil {
			// Unbound: the first argument is the receiver.
			call := &ir.Call{Callee: c.name + "." + member, Name: member, HasRecv: true, RecvType: c.name}
			if id := kb.kp.methodID(c.name, member, 0); id != "" {
				call.Callee, call.Target = id, id
			}
			return kb.emitCall(n, call, []ir.VarID{it, it}, "")
		}
		if _, local := kb.lookup(kb.text(owner)); local || kb.this != ir.NoVar {
			// Bound: obj::send, this::send. The grammar parses the
			// receiver as a type name, so it is looked up by name.
			recv := kb.ident(kb.text(owner), owner)
			if kb.text(owner) == "this" {
				recv = kb.this
			}
			typ := kb.fn.Vars[recv].Type
			call := &ir.Call{Callee: typ + "." + member, Name: member, HasRecv: true, RecvType: typ, RecvText: trimText(kb.text(owner))}
			if id := kb.kp.methodID(typ, member, 0); id != "" {
				call.Callee, call.Target = id, id
			}
			return kb.emitCall(n, call, []ir.VarID{recv, it}, "")
		}
		// A top-level function: ::send.
		return kb.emitCall(n, &ir.Call{Callee: member, Name: member}, []ir.VarID{it}, "")
	})
}

// noteGetter records that property prop of ci has a custom getter, lowered
// as the JVM accessor getProp.
func (kp *ktProgram) noteGetter(ci *classInfo, prop string) {
	id := ci.name + ".get" + strings.ToUpper(prop[:1]) + prop[1:]
	kp.funcs[id] = true
	kp.getters[ci.name+"."+prop] = id
}

// lowerGetter lowers a custom property getter (get() = expr, or a block).
func (kp *ktProgram) lowerGetter(f *srcFile, ci *classInfo, prop string, g *sitter.Node) {
	id := kp.getters[ci.name+"."+prop]
	if id == "" {
		return
	}
	b := kp.newBuilder(f, ci, id, shortName(id), g)
	b.addThis(ci.name, g)
	kb := &ktBuilder{builder: b, kp: kp}
	if body := firstOf(g, "function_body"); body != nil {
		if st := firstOf(body, "block"); st != nil {
			kb.block(st)
		} else if k := named(body); len(k) > 0 {
			kb.ret(k[0], kb.expr(k[0]))
		}
	}
	b.finish()
}

func ktPropValue(prop *sitter.Node) *sitter.Node {
	kids := named(prop)
	for i := len(kids) - 1; i >= 0; i-- {
		switch kids[i].Type() {
		case "modifiers", "variable_declaration", "multi_variable_declaration", "type_constraints", "getter", "setter", "type_parameters",
			"line_comment", "block_comment":
			continue
		case "property_delegate":
			return firstOf(kids[i], "call_expression", "lambda_literal", "annotated_lambda")
		}
		if isKtType(kids[i]) {
			continue // the receiver type of an extension property
		}
		return kids[i]
	}
	return nil
}

func (kp *ktProgram) lowerFunc(f *srcFile, n *sitter.Node, cls *classInfo, static bool) {
	name, recv := ktFuncName(f, n)
	if name == "" {
		return
	}
	var id string
	switch {
	case cls != nil:
		id = cls.name + "." + name
	case f.pkg != "":
		id = f.pkg + "." + name
	default:
		id = name
	}
	b := kp.newBuilder(f, cls, id, name, n)
	kb := &ktBuilder{builder: b, kp: kp}
	switch {
	case recv != "":
		b.this = b.param("this", kp.resolveType(f, recv), n)
	case cls != nil && !static:
		b.addThis(cls.name, n)
	}
	kb.params(firstOf(n, "function_value_parameters"))
	if body := firstOf(n, "function_body"); body != nil {
		kids := named(body)
		if len(kids) == 1 && kids[0].Type() != "block" {
			b.ret(kids[0], kb.expr(kids[0]))
		} else {
			for _, k := range kids {
				kb.block(k)
			}
		}
	}
	b.finish()
}

type ktBuilder struct {
	*builder
	kp *ktProgram
	// hoisted is a prefix operator the grammar attached to the receiver
	// of a call or member chain (!a.b() read as (!a).b()): lowering the
	// chain sees through it, and the operator applies to the chain.
	hoisted *sitter.Node
}

// ktChains are the expressions a member or call chain is built from.
var ktChains = map[string]bool{"call_expression": true, "navigation_expression": true, "index_expression": true}

// ktMisboundPrefix returns the prefix operator expression at the start of
// chain n, when there is one: tree-sitter-kotlin binds a prefix operator
// tighter than member access, so !consents.hasConsent() is read as
// (!consents).hasConsent().
func ktMisboundPrefix(n *sitter.Node) *sitter.Node {
	if !ktChains[n.Type()] {
		return nil
	}
	c := n
	for ktChains[c.Type()] {
		kids := named(c)
		if len(kids) == 0 {
			return nil
		}
		c = kids[0]
	}
	if c.Type() != "unary_expression" || c.StartByte() != n.StartByte() {
		return nil
	}
	if op := c.ChildByFieldName("operator"); op == nil || op.StartByte() != c.StartByte() {
		return nil // a postfix operator (a!!.b) is bound correctly
	}
	return c
}

// seeThrough returns n, or the operand of the hoisted prefix operator
// when n is that operator's expression.
func (kb *ktBuilder) seeThrough(n *sitter.Node) *sitter.Node {
	if n != nil && kb.hoisted != nil && n.Equal(kb.hoisted) {
		return n.ChildByFieldName("argument")
	}
	return n
}

func (kb *ktBuilder) params(fvp *sitter.Node) {
	for _, p := range allOf(fvp, "parameter") {
		id := firstOf(p, "identifier")
		if id == nil {
			continue
		}
		kb.param(kb.text(id), kb.kp.resolveType(kb.f, ktTypeText(kb.f, ktTypeChild(p))), id)
	}
}

// block lowers statements and returns the value of the last expression.
func (kb *ktBuilder) block(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	switch n.Type() {
	case "block", "function_body", "lambda_literal", "source_file":
		last := ir.NoVar
		for _, c := range named(n) {
			switch c.Type() {
			case "lambda_parameters", "label":
				continue
			}
			last = kb.stmt(c)
		}
		return last
	}
	return kb.stmt(n)
}

// ktBody is the body of a control structure: its block, or the statement
// written without braces. It is the last named child that is not the
// condition, a label or a comment.
func ktBody(n *sitter.Node, skip ...*sitter.Node) *sitter.Node {
	kids := named(n)
	for i := len(kids) - 1; i >= 0; i-- {
		k := kids[i]
		switch k.Type() {
		case "label", "line_comment", "block_comment", "annotation":
			continue
		}
		skipped := false
		for _, s := range skip {
			skipped = skipped || (s != nil && s.Equal(k))
		}
		if !skipped {
			return k
		}
		return nil
	}
	return nil
}

// ktLabel is the label of a loop (outer@ for ...), without the @.
func (kb *ktBuilder) ktLabel(n *sitter.Node) string {
	if l := firstOf(n, "label"); l != nil {
		return strings.TrimSuffix(kb.text(l), "@")
	}
	return ""
}

// ktJump reports whether n is break or continue, possibly labelled
// (break@outer): the grammar reads them as an identifier, or as a label
// "break@" applied to the target's name.
func (kb *ktBuilder) ktJump(n *sitter.Node) (isJump, isContinue bool, label string) {
	switch n.Type() {
	case "identifier":
		switch kb.text(n) {
		case "break":
			return true, false, ""
		case "continue":
			return true, true, ""
		}
	case "labeled_expression":
		l := firstOf(n, "label")
		kids := named(n)
		if l == nil || len(kids) != 2 || kids[1].Type() != "identifier" {
			return false, false, ""
		}
		switch kb.text(l) {
		case "break@":
			return true, false, kb.text(kids[1])
		case "continue@":
			return true, true, kb.text(kids[1])
		}
	}
	return false, false, ""
}

func (kb *ktBuilder) stmt(n *sitter.Node) ir.VarID {
	if ok, cont, label := kb.ktJump(n); ok {
		kb.jump(cont, label)
		return ir.NoVar
	}
	switch n.Type() {
	case "block":
		return kb.block(n)
	case "property_declaration":
		val := ktPropValue(n)
		var v ir.VarID = ir.NoVar
		if val != nil {
			v = kb.expr(val)
		}
		if vd := firstOf(n, "variable_declaration"); vd != nil {
			id := firstOf(vd, "identifier")
			typ := kb.kp.resolveType(kb.f, ktTypeText(kb.f, ktTypeChild(vd)))
			if typ == "" && v != ir.NoVar {
				typ = kb.fn.Vars[v].Type
			}
			dst := kb.declare(kb.text(id), typ, id)
			kb.assign(dst, n, v)
		} else if mv := firstOf(n, "multi_variable_declaration"); mv != nil {
			for _, vd := range allOf(mv, "variable_declaration") {
				id := firstOf(vd, "identifier")
				dst := kb.declare(kb.text(id), "", id)
				kb.assign(dst, n, v)
			}
		}
		return ir.NoVar
	case "assignment":
		kb.assignment(n)
		return ir.NoVar
	case "return_expression":
		var v ir.VarID = ir.NoVar
		if e := ktBody(n, n.ChildByFieldName("label")); e != nil {
			v = kb.expr(e)
		}
		kb.ret(n, v)
		return ir.NoVar
	case "throw_expression":
		if kids := named(n); len(kids) > 0 {
			kb.throwValue(kb.expr(kids[len(kids)-1]), n)
		}
		return ir.NoVar
	case "for_statement":
		var iter ir.VarID = ir.NoVar
		var vars []*sitter.Node
		var iterNode, body *sitter.Node
		for _, c := range named(n) {
			switch c.Type() {
			case "variable_declaration":
				vars = append(vars, c)
			case "multi_variable_declaration":
				vars = append(vars, allOf(c, "variable_declaration")...)
			case "label", "annotation", "line_comment", "block_comment":
			default:
				if iterNode == nil {
					iterNode = c
				} else {
					body = c
				}
			}
		}
		iter = kb.expr(iterNode)
		kb.label = kb.ktLabel(n)
		kb.loop(n, func() {
			for _, vd := range vars {
				id := firstOf(vd, "identifier")
				dst := kb.declare(kb.text(id), kb.kp.resolveType(kb.f, ktTypeText(kb.f, ktTypeChild(vd))), id)
				kb.assign(dst, vd, iter)
			}
			kb.block(body)
		})
		return ir.NoVar
	case "while_statement", "do_while_statement":
		cond := n.ChildByFieldName("condition")
		body := ktBody(n, cond)
		v, known := kb.truth(cond)
		if known && !v && n.Type() == "while_statement" {
			kb.expr(cond) // while (false): the body never runs
			return ir.NoVar
		}
		test := func() ir.VarID { return kb.expr(cond) }
		spec := loopSpec{infinite: known && v, body: func() { kb.block(body) }}
		if n.Type() == "do_while_statement" {
			spec.post = test
		} else {
			spec.cond = test
		}
		kb.label = kb.ktLabel(n)
		kb.loopWith(n, spec)
		return ir.NoVar
	case "function_declaration":
		// Local function: a closure bound to its name, so calls of it run it.
		var pnodes []*sitter.Node
		var pnames []string
		for _, p := range allOf(firstOf(n, "function_value_parameters"), "parameter") {
			if id := firstOf(p, "identifier"); id != nil {
				pnodes, pnames = append(pnodes, id), append(pnames, kb.text(id))
			}
		}
		body := firstOf(n, "function_body")
		fn := kb.lambda(n, pnodes, pnames, false, func() ir.VarID {
			last := ir.NoVar
			for _, k := range named(body) {
				last = kb.block(k)
			}
			return last
		})
		if id := n.ChildByFieldName("name"); id != nil {
			kb.scope[kb.text(id)] = fn
		}
		return ir.NoVar
	case "class_declaration", "object_declaration", "type_alias", "line_comment", "block_comment":
		return ir.NoVar
	}
	return kb.expr(n)
}

func (kb *ktBuilder) assignment(n *sitter.Node) {
	target, valNode := n.ChildByFieldName("left"), n.ChildByFieldName("right")
	if target == nil || valNode == nil {
		return
	}
	v := kb.expr(valNode)
	augmented := kb.text(n.ChildByFieldName("operator")) != "="
	switch target.Type() {
	case "identifier":
		name := kb.text(target)
		if old, ok := kb.lookup(name); ok {
			dst := kb.redefine(name, old, "", target)
			if augmented {
				kb.assign(dst, n, old, v)
			} else {
				kb.assign(dst, n, v)
			}
			return
		}
		if kb.cls != nil && kb.this != ir.NoVar {
			if _, ok := kb.cls.fields[name]; ok {
				kb.store(kb.this, name, kb.cls.name, v, n)
				return
			}
		}
		if it, ok := kb.scope["it"]; ok && kb.outer != nil && kb.fn.Vars[it].Param >= 0 {
			// A property of the lambda's receiver: User().apply { email = x }.
			kb.store(it, name, "", v, n)
			return
		}
		dst := kb.declare(name, "", target)
		kb.assign(dst, n, v)
	case "navigation_expression":
		// a.b.c = v: the object is a.b.
		tk := named(target)
		if len(tk) < 2 || tk[len(tk)-1].Type() != "identifier" {
			kb.expr(target)
			return
		}
		obj, owner := kb.expr(tk[0]), kb.typeOf(tk[0])
		kb.store(obj, kb.text(tk[len(tk)-1]), owner, v, n)
	case "index_expression":
		tk := named(target)
		obj := kb.expr(tk[0])
		idx := tk[1:]
		if len(idx) == 1 && idx[0].Type() == "string_literal" {
			if key, ok := kb.ktStaticString(idx[0]); ok {
				kb.store(obj, key, "", v, n)
				return
			}
		}
		for _, i := range idx {
			kb.expr(i)
		}
		kb.assign(obj, n, v)
		kb.cell(obj)
	default:
		kb.expr(target)
	}
}

// ktStringPart is a piece of a string template: literal text, or an
// expression whose value is interpolated.
type ktStringPart struct {
	text string
	expr *sitter.Node
	name *sitter.Node // $name, whose node covers the text after the $
	id   string
}

// ktStringParts splits a string literal into text and interpolations.
// tree-sitter-kotlin reads "$name" in a single-line string as a "$"
// string_content followed by text starting with the name, so a "$" before
// an identifier is an interpolation of that identifier.
func (kb *ktBuilder) ktStringParts(n *sitter.Node) []ktStringPart {
	var parts []ktStringPart
	kids := named(n)
	for i := 0; i < len(kids); i++ {
		c := kids[i]
		switch c.Type() {
		case "string_content", "escape_sequence":
			t := kb.text(c)
			if t == "$" && i+1 < len(kids) && kids[i+1].Type() == "string_content" {
				next := kb.text(kids[i+1])
				if id := ktLeadingIdent(next); id != "" {
					parts = append(parts, ktStringPart{name: kids[i+1], id: id})
					parts = append(parts, ktStringPart{text: next[len(id):]})
					i++
					continue
				}
			}
			parts = append(parts, ktStringPart{text: t})
		case "interpolation":
			if e := named(c); len(e) > 0 {
				if e[0].Type() == "identifier" && !strings.HasPrefix(kb.text(c), "${") {
					parts = append(parts, ktStringPart{name: e[0], id: kb.text(e[0])})
				} else {
					parts = append(parts, ktStringPart{expr: e[0]})
				}
			}
		}
	}
	return parts
}

// ktLeadingIdent is the identifier s starts with, or "".
func ktLeadingIdent(s string) string {
	end := 0
	for end < len(s) && (isWordByte(s[end])) {
		end++
	}
	if end == 0 || s[0] >= '0' && s[0] <= '9' {
		return ""
	}
	return s[:end]
}

// ktStaticString returns the text of a string literal without
// interpolations.
func (kb *ktBuilder) ktStaticString(n *sitter.Node) (string, bool) {
	var sb strings.Builder
	for _, p := range kb.ktStringParts(n) {
		if p.expr != nil || p.name != nil {
			return "", false
		}
		sb.WriteString(p.text)
	}
	return sb.String(), true
}

var ktLiterals = map[string]bool{"true": true, "false": true, "null": true}

func (kb *ktBuilder) expr(n *sitter.Node) ir.VarID {
	if n == nil {
		return ir.NoVar
	}
	n = kb.seeThrough(n)
	if u := ktMisboundPrefix(n); u != nil && kb.hoisted == nil {
		// !a.b(): the chain's value, then the operator.
		kb.hoisted = u
		v := kb.expr(n)
		kb.hoisted = nil
		switch kb.text(u.ChildByFieldName("operator")) {
		case "!":
			return kb.logic(u, v)
		case "-", "+":
			dst := kb.temp(u)
			kb.compute(dst, u, v)
			return dst
		}
		return v
	}
	if ok, _, _ := kb.ktJump(n); ok {
		kb.stmt(n)
		return kb.temp(n)
	}
	switch t := n.Type(); t {
	case "identifier":
		name := kb.text(n)
		if ktLiterals[name] {
			if _, local := kb.lookup(name); !local {
				return kb.constVar(name, n)
			}
		}
		if _, local := kb.lookup(name); !local {
			if q := kb.classRef(n); q != "" {
				v := kb.fn.Named(shortName(q), q, kb.pos(n))
				return v
			}
		}
		return kb.ident(name, n)
	case "this_expression", "super_expression":
		if kb.this != ir.NoVar {
			return kb.this
		}
		return kb.ident("this", n)
	case "string_literal", "multiline_string_literal":
		if s, ok := kb.ktStaticString(n); ok {
			return kb.constVar(s, n)
		}
		var parts []ir.VarID
		for _, p := range kb.ktStringParts(n) {
			switch {
			case p.name != nil:
				parts = append(parts, kb.ident(p.id, p.name))
			case p.expr != nil:
				parts = append(parts, kb.expr(p.expr))
			}
		}
		dst := kb.temp(n)
		kb.compute(dst, n, parts...)
		return dst
	case "number_literal", "float_literal", "character_literal":
		return kb.constVar(kb.text(n), n)
	case "navigation_expression":
		kids := named(n)
		if len(kids) < 2 {
			return kb.temp(n)
		}
		fieldNode := kids[len(kids)-1]
		if fieldNode.Type() != "identifier" {
			return kb.expr(kids[0])
		}
		if hasChildToken(n, kb.f.src, "::") {
			return kb.callableRef(n) // User::email read as a navigation
		}
		if q := kb.classRef(kids[0]); q != "" {
			// Static field / enum constant: Build.SERIAL, R.string.x
			obj := kb.fn.Named(shortName(q), q, kb.pos(kids[0]))
			return kb.load(obj, kb.text(fieldNode), q, n)
		}
		owner := kb.typeOf(kids[0])
		obj := kb.expr(kids[0])
		field := kb.text(fieldNode)
		switch field {
		case "java", "kotlin", "javaObjectType":
			if _, ok := kb.handle(obj); ok {
				return obj // User::class.java is still the class
			}
		case "javaClass":
			if owner != "" {
				v := kb.temp(n)
				kb.markRefl(v, reflHandle{kind: 'c', class: owner})
				return v
			}
		}
		if strings.Contains(owner, ".") && kb.kp.class(owner) == nil && field != "" {
			// A property of a Java class (telephony.line1Number) is its
			// getter, getLine1Number(), which is what rules name.
			getter := "get" + strings.ToUpper(field[:1]) + field[1:]
			c := &ir.Call{Callee: owner + "." + getter, Name: getter, HasRecv: true, RecvType: owner, RecvText: trimText(kb.text(kids[0]))}
			return kb.emitCall(n, c, []ir.VarID{obj}, "")
		}
		return kb.load(obj, field, owner, n)
	case "call_expression":
		return kb.call(n)
	case "index_expression":
		kids := named(n)
		base := kb.expr(kids[0])
		idx := kids[1:]
		if len(idx) == 1 && idx[0].Type() == "string_literal" {
			if key, ok := kb.ktStaticString(idx[0]); ok {
				return kb.load(base, key, "", n)
			}
		}
		for _, i := range idx {
			kb.expr(i)
		}
		dst := kb.temp(n)
		kb.assign(dst, n, base)
		return dst
	case "parenthesized_expression", "annotated_expression", "labeled_expression", "spread_expression":
		kids := named(n)
		for i := len(kids) - 1; i >= 0; i-- {
			if kids[i].Type() != "label" && kids[i].Type() != "annotation" {
				return kb.expr(kids[i])
			}
		}
		return kb.temp(n)
	case "as_expression":
		v := kb.expr(n.ChildByFieldName("left"))
		if r := n.ChildByFieldName("right"); r != nil {
			dst := kb.fn.Named("", kb.kp.resolveType(kb.f, ktTypeText(kb.f, r)), kb.pos(n))
			kb.assign(dst, n, v)
			return dst
		}
		return v
	case "unary_expression":
		arg := n.ChildByFieldName("argument")
		if arg == nil {
			return kb.temp(n)
		}
		if kb.text(n.ChildByFieldName("operator")) == "!" {
			return kb.logic(n, kb.expr(arg))
		}
		return kb.expr(arg)
	case "binary_expression":
		l, r := kb.expr(n.ChildByFieldName("left")), kb.expr(n.ChildByFieldName("right"))
		switch op := kb.text(n.ChildByFieldName("operator")); {
		case ir.Logical(op):
			return kb.logic(n, l, r)
		case op == "?:":
			// a ?: b is one of them.
			dst := kb.temp(n)
			kb.assign(dst, n, l, r)
			return dst
		}
		dst := kb.temp(n)
		kb.compute(dst, n, l, r)
		return dst
	case "is_expression", "in_expression":
		var vs []ir.VarID
		for _, c := range named(n) {
			if !isKtType(c) {
				vs = append(vs, kb.expr(c))
			}
		}
		return kb.logic(n, vs...)
	case "range_expression":
		var parts []ir.VarID
		for _, c := range named(n) {
			parts = append(parts, kb.expr(c))
		}
		dst := kb.temp(n)
		kb.compute(dst, n, parts...)
		return dst
	case "infix_expression":
		kids := named(n)
		if len(kids) == 3 && kids[1].Type() == "identifier" {
			l, r := kb.expr(kids[0]), kb.expr(kids[2])
			op := kb.text(kids[1])
			if op == "to" {
				return kb.emitCall(n, &ir.Call{Callee: "kotlin.to", Name: "to"}, []ir.VarID{l, r}, "kotlin.Pair")
			}
			return kb.emitCall(n, &ir.Call{Name: op, HasRecv: true, RecvText: trimText(kb.text(kids[0]))}, []ir.VarID{l, r}, "")
		}
	case "if_expression", "when_expression", "try_expression":
		return kb.conditional(n)
	case "lambda_literal", "annotated_lambda":
		return kb.lambdaLit(n)
	case "anonymous_function":
		return kb.lambda(n, nil, nil, false, func() ir.VarID {
			for _, p := range allOf(firstOf(n, "function_value_parameters"), "parameter") {
				if id := firstOf(p, "identifier"); id != nil {
					kb.declare(kb.text(id), "", id)
				}
			}
			return kb.block(firstOf(n, "function_body"))
		})
	case "object_literal":
		return kb.lambda(n, nil, nil, false, func() ir.VarID {
			for _, fd := range allOf(firstOf(n, "class_body"), "function_declaration") {
				for _, p := range allOf(firstOf(fd, "function_value_parameters"), "parameter") {
					if id := firstOf(p, "identifier"); id != nil {
						kb.declare(kb.text(id), "", id)
					}
				}
				if body := firstOf(fd, "function_body"); body != nil {
					for _, k := range named(body) {
						kb.block(k)
					}
				}
			}
			return ir.NoVar
		})
	case "return_expression", "throw_expression", "assignment", "property_declaration", "for_statement", "while_statement", "do_while_statement":
		kb.stmt(n)
		return kb.temp(n)
	case "callable_reference":
		return kb.callableRef(n)
	case "type_test", "range_test", "line_comment", "block_comment":
		return kb.temp(n)
	}
	// Generic: the value depends on every child (collection literals, ...).
	var parts []ir.VarID
	for _, c := range named(n) {
		parts = append(parts, kb.expr(c))
	}
	dst := kb.temp(n)
	kb.assign(dst, n, parts...)
	return dst
}

// conditional lowers if, when and try expressions: each arm is a separate
// path from the scope before it, and the expression's value is the value of
// whichever arm ran.
func (kb *ktBuilder) conditional(n *sitter.Node) ir.VarID {
	return kb.valued(n, func() { kb.conditionalArms(n) })
}

func (kb *ktBuilder) conditionalArms(n *sitter.Node) {
	set := kb.setResult
	arm := func(body *sitter.Node) func() {
		return func() { set(kb.block(body)) }
	}
	switch n.Type() {
	case "if_expression":
		cond := n.ChildByFieldName("condition")
		cv := kb.expr(cond)
		var bodies []*sitter.Node
		for _, c := range named(n) {
			switch {
			case cond != nil && c.Equal(cond):
			case c.Type() == "line_comment" || c.Type() == "block_comment":
			default:
				bodies = append(bodies, c)
			}
		}
		if len(bodies) == 0 {
			break
		}
		var els func()
		if len(bodies) > 1 {
			els = arm(bodies[1])
		}
		kb.ifElse(n, cond, cv, arm(bodies[0]), els)
	case "when_expression":
		// Each entry is entered when its test passes: subject == value
		// (is, in: a type or range test), or with no subject the
		// condition itself; else when every test failed.
		var arms []func()
		var tests []func() ir.VarID
		exhaustive := false
		subject := ir.NoVar
		for _, c := range named(n) {
			switch c.Type() {
			case "when_subject":
				var vd *sitter.Node
				for _, k := range named(c) {
					switch k.Type() {
					case "variable_declaration":
						vd = k
						continue
					case "annotation":
						continue
					}
					subject = kb.expr(k)
					if vd != nil {
						id := firstOf(vd, "identifier")
						kb.assign(kb.declare(kb.text(id), "", id), k, subject)
					}
				}
			case "when_entry":
				conds := fieldChildren(c, "condition")
				body := ktBody(c, conds...)
				if body == nil {
					continue
				}
				arms = append(arms, arm(body))
				if len(conds) == 0 {
					exhaustive = true
					tests = append(tests, nil)
					continue
				}
				tests = append(tests, func() ir.VarID {
					var vs []ir.VarID
					for _, k := range conds {
						switch k.Type() {
						case "range_test", "type_test":
							v := ir.NoVar
							for _, x := range named(k) {
								if !isKtType(x) {
									v = kb.expr(x)
								}
							}
							t := kb.temp(k)
							op := "in"
							if k.Type() == "type_test" {
								op = "is"
								v = kb.constVar(ktTypeText(kb.f, ktTypeChild(k)), k)
							}
							if subject != ir.NoVar && v != ir.NoVar {
								kb.fn.Compute(t, kb.pos(k), op, subject, v)
							} else {
								t = ir.NoVar
							}
							vs = append(vs, t)
						default:
							vs = append(vs, kb.expr(k))
						}
					}
					return kb.matches(c, subject, vs...)
				})
			}
		}
		kb.switchCases(n, switchSpec{exhaustive: exhaustive, noBreak: true, cases: arms, tests: tests})
	case "try_expression":
		var body *sitter.Node
		var handlers []func()
		var finally func()
		for _, c := range named(n) {
			switch c.Type() {
			case "catch_block":
				handlers = append(handlers, func() {
					if id := firstOf(c, "identifier"); id != nil {
						kb.assign(kb.declare(kb.text(id), "", id), id, kb.caughtValue(id))
					}
					if b := firstOf(c, "block"); b != nil {
						set(kb.block(b))
					}
				})
			case "finally_block":
				finally = func() { kb.block(firstOf(c, "block")) }
			default:
				if body == nil {
					body = c
				}
			}
		}
		kb.tryCatch(n, func() {
			if body != nil {
				set(kb.block(body))
			}
		}, handlers, finally)
	}
}

func (kb *ktBuilder) lambdaLit(n *sitter.Node) ir.VarID {
	if n.Type() == "annotated_lambda" {
		if l := firstOf(n, "lambda_literal"); l != nil {
			n = l
		}
	}
	var pnodes []*sitter.Node
	var pnames []string
	if lp := firstOf(n, "lambda_parameters"); lp != nil {
		for _, vd := range named(lp) {
			switch vd.Type() {
			case "variable_declaration":
				if id := firstOf(vd, "identifier"); id != nil {
					pnodes = append(pnodes, id)
					pnames = append(pnames, kb.text(id))
				}
			case "multi_variable_declaration":
				for _, v := range allOf(vd, "variable_declaration") {
					if id := firstOf(v, "identifier"); id != nil {
						pnodes = append(pnodes, id)
						pnames = append(pnames, kb.text(id))
					}
				}
			}
		}
	}
	return kb.lambda(n, pnodes, pnames, true, func() ir.VarID {
		return kb.block(n)
	})
}

var ktBuiltins = map[string]string{
	"println": "kotlin.io.println", "print": "kotlin.io.print",
	"mapOf": "kotlin.collections.mapOf", "mutableMapOf": "kotlin.collections.mutableMapOf", "hashMapOf": "kotlin.collections.hashMapOf",
	"listOf": "kotlin.collections.listOf", "mutableListOf": "kotlin.collections.mutableListOf", "setOf": "kotlin.collections.setOf",
	"arrayOf": "kotlin.arrayOf", "bundleOf": "androidx.core.os.bundleOf", "Pair": "kotlin.Pair",
}

// classRef resolves an expression that names a class or object (Sentry,
// android.util.Log, FirebaseCrashlytics) to its qualified name.
func (kb *ktBuilder) classRef(n *sitter.Node) string {
	n = kb.seeThrough(n)
	switch n.Type() {
	case "identifier":
		name := kb.text(n)
		if _, local := kb.lookup(name); local {
			return ""
		}
		if kb.cls != nil {
			if _, field := kb.cls.fields[name]; field {
				return ""
			}
		}
		if q, ok := kb.f.imports[name]; ok && isUpperStart(name) {
			return q
		}
		if isUpperStart(name) {
			if q := kb.kp.resolveType(kb.f, name); q != name || kb.kp.class(name) != nil {
				return q
			}
			if kb.cls != nil && kb.kp.class(kb.cls.name+"."+name) != nil {
				return kb.cls.name + "." + name
			}
			return name
		}
	case "navigation_expression":
		txt := strings.ReplaceAll(kb.text(n), " ", "")
		segs := strings.Split(txt, ".")
		if len(segs) < 2 || strings.ContainsAny(txt, "()?![]:") {
			return ""
		}
		if q, ok := kb.f.imports[segs[0]]; ok && isUpperStart(segs[0]) && isUpperStart(segs[len(segs)-1]) {
			return q + "." + strings.Join(segs[1:], ".")
		}
		// Fully qualified: android.util.Log
		if !isUpperStart(segs[0]) && isUpperStart(segs[len(segs)-1]) {
			if _, local := kb.lookup(segs[0]); local {
				return ""
			}
			for _, s := range segs[:len(segs)-1] {
				if isUpperStart(s) {
					return ""
				}
			}
			return txt
		}
	}
	return ""
}

// typeOf returns the best-known static type of an expression.
func (kb *ktBuilder) typeOf(n *sitter.Node) string {
	n = kb.seeThrough(n)
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		name := kb.text(n)
		if v, ok := kb.lookup(name); ok {
			return kb.fn.Vars[v].Type
		}
		if kb.cls != nil {
			if t := kb.kp.fieldType(kb.cls.name, name); t != "" {
				return t
			}
		}
	case "this_expression":
		if kb.cls != nil {
			return kb.cls.name
		}
	case "navigation_expression":
		kids := named(n)
		if len(kids) >= 2 && kids[len(kids)-1].Type() == "identifier" {
			if owner := kb.typeOf(kids[0]); owner != "" {
				return kb.kp.fieldType(owner, kb.text(kids[len(kids)-1]))
			}
		}
	case "call_expression":
		kids := named(n)
		if len(kids) == 0 {
			return ""
		}
		callee := kids[0]
		switch callee.Type() {
		case "identifier":
			name := kb.text(callee)
			if isUpperStart(name) {
				return kb.kp.resolveType(kb.f, name)
			}
		case "navigation_expression":
			ck := named(callee)
			if len(ck) < 2 {
				return ""
			}
			m := kb.text(ck[len(ck)-1])
			if q := kb.classRef(ck[0]); q != "" {
				if ex := kb.kp.extra[q]; ex != nil {
					if rt, ok := ex.returns[m]; ok {
						return kb.kp.resolveType(kb.f, rt)
					}
				}
				switch m {
				case "getInstance", "getDefault", "instance", "get", "shared", "getInstanceFor":
					return q
				}
				return ""
			}
			if owner := kb.typeOf(ck[0]); owner != "" {
				if ex := kb.kp.extra[owner]; ex != nil {
					if rt, ok := ex.returns[m]; ok {
						return kb.kp.resolveType(kb.kp.classes[owner].file, rt)
					}
				}
			}
		}
	case "parenthesized_expression":
		if k := named(n); len(k) > 0 {
			return kb.typeOf(k[0])
		}
	case "as_expression":
		return kb.kp.resolveType(kb.f, ktTypeText(kb.f, n.ChildByFieldName("right")))
	}
	return ""
}

// args lowers the arguments of a call: its value arguments and a
// trailing lambda.
func (kb *ktBuilder) args(call *sitter.Node) []ir.VarID {
	var out []ir.VarID
	for i, c := range named(call) {
		if i == 0 {
			continue // the callee
		}
		switch c.Type() {
		case "value_arguments":
			for _, va := range allOf(c, "value_argument") {
				kids := named(va)
				if len(kids) == 0 {
					out = append(out, kb.constVar(kb.text(va), va))
					continue
				}
				if len(kids) >= 2 && kids[0].Type() == "identifier" && hasChildToken(va, kb.f.src, "=") {
					// Named argument: User(email = x) — keep the name.
					out = append(out, kb.kwarg(kb.text(kids[0]), kb.expr(kids[len(kids)-1]), va))
					continue
				}
				out = append(out, kb.expr(kids[len(kids)-1]))
			}
		case "annotated_lambda", "lambda_literal":
			out = append(out, kb.lambdaLit(c))
		}
	}
	return out
}

func (kb *ktBuilder) call(n *sitter.Node) ir.VarID {
	kids := named(n)
	if len(kids) == 0 {
		return kb.temp(n)
	}
	calleeNode := kids[0]
	switch calleeNode.Type() {
	case "identifier":
		name := kb.text(calleeNode)
		args := kb.args(n)
		if v, local := kb.lookup(name); local {
			return kb.emitCall(n, &ir.Call{Name: "invoke", HasRecv: true, RecvText: name}, append([]ir.VarID{v}, args...), "")
		}
		// Method of the enclosing class (or its companion/object).
		if kb.cls != nil {
			if id := kb.kp.methodID(kb.cls.name, name, 0); id != "" {
				owner := id[:strings.LastIndexByte(id, '.')]
				static := false
				if ex := kb.kp.extra[owner]; ex != nil && ex.static[name] {
					static = true
				}
				c := &ir.Call{Callee: id, Name: name, Target: id, RecvType: owner}
				rt := ""
				if ex := kb.kp.extra[owner]; ex != nil {
					rt = kb.kp.resolveType(kb.f, ex.returns[name])
				}
				if !static && kb.this != ir.NoVar {
					c.HasRecv = true
					return kb.emitCall(n, c, append([]ir.VarID{kb.this}, args...), rt)
				}
				return kb.emitCall(n, c, args, rt)
			}
		}
		// Top-level function in this package or imported.
		for _, cand := range []string{kb.f.imports[name], kb.f.pkg + "." + name} {
			if cand == "" || cand == "."+name {
				continue
			}
			if kb.kp.known(cand) {
				return kb.emitCall(n, &ir.Call{Callee: cand, Name: name, Target: cand}, args, kb.kp.resolveType(kb.f, kb.kp.topRet[cand]))
			}
		}
		// Constructor.
		if isUpperStart(name) {
			q := kb.kp.resolveType(kb.f, name)
			return kb.newObject(n, q, args, q)
		}
		c := &ir.Call{Name: name}
		if q, ok := kb.f.imports[name]; ok {
			c.Callee = q
		} else if q, ok := ktBuiltins[name]; ok {
			c.Callee = q
		} else if kb.this != ir.NoVar {
			// Implicit receiver: inherited member or extension on this.
			c.HasRecv, c.RecvText = true, "this"
			return kb.emitCall(n, c, append([]ir.VarID{kb.this}, args...), "")
		}
		return kb.emitCall(n, c, args, "")
	case "navigation_expression":
		ck := named(calleeNode)
		if len(ck) < 2 || ck[len(ck)-1].Type() != "identifier" || hasChildToken(calleeNode, kb.f.src, "::") {
			break
		}
		m := kb.text(ck[len(ck)-1])
		recvNode := ck[0]
		if q := kb.classRef(recvNode); q != "" {
			args := kb.args(n)
			c := &ir.Call{Name: m, RecvType: q, RecvText: trimText(kb.text(recvNode))}
			if strings.Contains(q, ".") {
				c.Callee = q + "." + m
			}
			rt := ""
			if id := kb.kp.methodID(q, m, 0); id != "" {
				c.Target = id
				if ex := kb.kp.extra[q]; ex != nil {
					rt = kb.kp.resolveType(kb.f, ex.returns[m])
				}
			} else if kb.kp.known(q + "." + m) {
				c.Target = q + "." + m
			}
			return kb.emitCall(n, c, args, rt)
		}
		typ := kb.typeOf(recvNode)
		recv := kb.expr(recvNode)
		args := kb.args(n)
		c := &ir.Call{Name: m, HasRecv: true, RecvType: typ, RecvText: trimText(kb.text(recvNode))}
		rt := ""
		if typ != "" && strings.Contains(typ, ".") {
			c.Callee = typ + "." + m
		}
		if typ != "" {
			if id := kb.kp.methodID(typ, m, 0); id != "" {
				c.Target, c.Callee = id, id
				owner := id[:strings.LastIndexByte(id, '.')]
				if ex := kb.kp.extra[owner]; ex != nil {
					rt = kb.kp.resolveType(kb.kp.classes[owner].file, ex.returns[m])
				}
			}
		}
		if c.Target == "" {
			if ids := kb.kp.ext[m]; len(ids) == 1 {
				c.Target, c.Callee = ids[0], ids[0]
				rt = kb.kp.resolveType(kb.f, kb.kp.topRet[ids[0]])
			}
		}
		return kb.emitCall(n, c, append([]ir.VarID{recv}, args...), rt)
	}
	// Invocation of an arbitrary expression (lambda variable, factory()()).
	fv := kb.expr(calleeNode)
	args := kb.args(n)
	return kb.emitCall(n, &ir.Call{Name: "invoke", HasRecv: true, RecvText: trimText(kb.text(calleeNode))}, append([]ir.VarID{fv}, args...), "")
}
