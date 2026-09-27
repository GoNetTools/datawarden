// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"slices"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// closure is a closure value: its function, the function that created it
// and the variables of that function it binds to the capture parameters.
// A closure that reached the variable through a parameter of the function
// holding it is marked param: the caller passing it already runs it with
// the call's other arguments (see analyzer.call), and running it again
// with whatever the callee has would mix up what different callers pass.
type closure struct {
	fn    string
	in    string
	binds []ir.VarID
	param bool
}

func (c closure) same(o closure) bool {
	return c.fn == o.fn && c.in == o.in && c.param == o.param && slices.Equal(c.binds, o.binds)
}

// closureFlow is a whole-program, flow-insensitive analysis of where
// closure values go: through assignments and phis, into and out of fields
// (by owner type and field name), into collections and out again, into
// the parameters of the functions they are passed to, and out of the
// functions that return them. The engine runs the closures a call may
// call: a closure held in a variable, in the receiver of a method call
// (h.accept(v), h.invoke(v)), or in the field the method is named after
// (this.onSend(v)).
type closureFlow struct {
	a      *analyzer
	vars   map[string]map[ir.VarID][]closure
	fields map[string]map[string][]closure // field name -> owner (short name, "" unknown) -> closures
	rets   map[string][]closure
	deps   *fileDeps
	grew   bool
}

// maxClosureRounds bounds the fixpoint over the whole program.
const maxClosureRounds = 32

func newClosureFlow(a *analyzer, funcs []*ir.Func) *closureFlow {
	cf := &closureFlow{a: a, vars: map[string]map[ir.VarID][]closure{}, fields: map[string]map[string][]closure{}, rets: map[string][]closure{}}
	has := false
	for _, f := range funcs {
		for i := range f.Instrs {
			has = has || f.Instrs[i].Op == ir.OpClosure
		}
	}
	if !has {
		return cf
	}
	cf.deps = newFileDeps(a, funcs)
	for round := 0; round < maxClosureRounds; round++ {
		cf.grew = false
		for _, f := range funcs {
			for i := range f.Instrs {
				cf.transfer(f, &f.Instrs[i])
			}
		}
		if !cf.grew {
			break
		}
	}
	return cf
}

// of returns the closures variable v of function fn may hold.
func (cf *closureFlow) of(fn string, v ir.VarID) []closure {
	if v < 0 {
		return nil
	}
	return cf.vars[fn][v]
}

// local returns the closures each variable of fn may hold, without those
// that came in through a parameter.
func (cf *closureFlow) local(fn string) map[ir.VarID][]closure {
	out := map[ir.VarID][]closure{}
	for v, cls := range cf.vars[fn] {
		for _, c := range cls {
			if !c.param {
				out[v] = append(out[v], c)
			}
		}
	}
	return out
}

func (cf *closureFlow) addAll(dst []closure, src []closure, param bool, keep func(closure) closure) ([]closure, bool) {
	grew := false
	for _, c := range src {
		if keep != nil {
			c = keep(c)
		}
		if param {
			c.param = true
		}
		if slices.ContainsFunc(dst, c.same) || len(dst) >= maxTargets {
			continue
		}
		dst = append(dst, c)
		grew = true
	}
	return dst, grew
}

func (cf *closureFlow) addVar(fn string, v ir.VarID, src []closure, param bool) {
	if v < 0 || len(src) == 0 {
		return
	}
	m := cf.vars[fn]
	if m == nil {
		m = map[ir.VarID][]closure{}
		cf.vars[fn] = m
	}
	var grew bool
	m[v], grew = cf.addAll(m[v], src, param, nil)
	cf.grew = cf.grew || grew
}

func unparam(c closure) closure {
	c.param = false
	return c
}

func (cf *closureFlow) addField(owner, field string, src []closure) {
	if field == "" || len(src) == 0 {
		return
	}
	m := cf.fields[field]
	if m == nil {
		m = map[string][]closure{}
		cf.fields[field] = m
	}
	var grew bool
	m[owner], grew = cf.addAll(m[owner], src, false, unparam)
	cf.grew = cf.grew || grew
}

// field returns the closures stored in field of objects of type owner,
// its supertypes, or of unknown type; with owner unknown, of any type; as
// seen by code in function fn. Code in one language does not read
// another's objects, and code in one program does not read another's: a
// server's res.render(...) does not run the render closures of a copy of
// three.js shipped to browsers (#55). See fileDeps.
func (cf *closureFlow) field(owner, field string, fn *ir.Func) []closure {
	m := cf.fields[field]
	if len(m) == 0 {
		return nil
	}
	var ownerFiles []string
	for _, c := range cf.a.cha.byShort[owner] {
		ownerFiles = append(ownerFiles, c.File)
	}
	var out []closure
	add := func(src []closure) {
		for _, c := range src {
			f := cf.a.funcs[c.fn]
			if f != nil && f.Lang != fn.Lang {
				continue
			}
			if f != nil && cf.deps != nil && !cf.deps.related(fn.File, f.File, ownerFiles) {
				continue
			}
			out, _ = cf.addAll(out, []closure{c}, false, nil)
		}
	}
	if owner == "" {
		for _, k := range sortedKeys(m) {
			add(m[k])
		}
		return out
	}
	add(m[""])
	for _, o := range cf.a.cha.ancestors(owner) {
		add(m[o])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// ownerKey normalizes a type name to the short class name fields are
// indexed by: *pkg.T, T?, List<T> → T, List.
func ownerKey(t string) string {
	t = strings.TrimSuffix(strings.TrimLeft(t, "*&"), "?")
	if i := strings.IndexAny(t, "<["); i > 0 {
		t = t[:i]
	}
	return shortClass(t)
}

// ownerOf is the type of object v in fn: its declared type, or for a
// method's receiver, the class the method is declared in.
func ownerOf(fn *ir.Func, v ir.VarID) string {
	if v < 0 || int(v) >= len(fn.Vars) {
		return ""
	}
	if t := fn.Vars[v].Type; t != "" {
		return ownerKey(t)
	}
	if len(fn.Params) > 0 && fn.Params[0] == v && fn.Parent == "" && isSelf(fn.Vars[v].Name) {
		if i := strings.LastIndexAny(fn.ID, "."); i > 0 {
			return ownerKey(fn.ID[:i])
		}
	}
	return ""
}

func isSelf(name string) bool {
	return name == "this" || name == "self"
}

// containerOps are methods that read, add to or inspect a collection or
// holder rather than call it: a call of one on a receiver holding
// closures (handlers.add(h), handlers.get(0)) does not run them.
var containerOps = map[string]bool{
	"add": true, "addall": true, "append": true, "extend": true, "push": true, "unshift": true, "insert": true,
	"put": true, "putall": true, "putifabsent": true, "set": true, "offer": true, "enqueue": true, "remove": true,
	"removeat": true, "removefirst": true, "removelast": true, "pop": true, "poll": true, "peek": true,
	"clear": true, "getordefault": true, "getornull": true, "getorelse": true, "elementat": true,
	"iterator": true, "listiterator": true, "next": true, "hasnext": true, "values": true, "keys": true,
	"keyset": true, "entries": true, "entryset": true, "items": true, "tolist": true, "tomutablelist": true,
	"toarray": true, "totypedarray": true, "aslist": true, "stream": true, "iter": true, "copy": true,
	"slice": true, "sublist": true, "size": true, "count": true, "length": true, "isempty": true,
	"isnotempty": true, "contains": true, "containskey": true, "indexof": true, "first": true, "last": true,
	"firstornull": true, "lastornull": true, "reversed": true, "reverse": true, "equals": true,
	"hashcode": true, "tostring": true, "compareto": true, "subscribe": true, "register": true,
	"addlistener": true, "addeventlistener": true, "on": true, "once": true, "off": true, "removelistener": true,
	"removeeventlistener": true, "unsubscribe": true, "unregister": true,
}

// runsReceiver reports whether a call of an unresolved method on a
// receiver holding closures runs them: h.accept(v), h.invoke(v), r.run(),
// supplier.get(), or a local called as a function (h(v)); not an
// operation on a collection of them (handlers.add(h), handlers.get(0)).
func runsReceiver(c *ir.Call, nargs int, closureArg bool) bool {
	n := strings.ToLower(c.Name)
	switch {
	case n == "get":
		return nargs == 0
	case containerOps[n]:
		return false
	case closureArg && immediateCallbacks[n]:
		return false
	}
	return true
}

// invoked lists the closures call in may run, and the index of the call's
// first argument that the closure's first parameter receives: a closure
// held in the variable called, in the receiver of an unresolved method
// call or in the field of the receiver that the method is named after.
func (cf *closureFlow) invoked(fn *ir.Func, in *ir.Instr, of func(ir.VarID) []closure) ([]closure, int) {
	c := in.Call
	if in.Op != ir.OpCall || c == nil {
		return nil, 0
	}
	if c.Indirect {
		if len(in.Args) == 0 {
			return nil, 0
		}
		return of(in.Args[0]), 1
	}
	if c.Target != "" || len(cf.a.cha.targets(c, fn.Lang)) > 0 {
		return nil, 0
	}
	if c.HasRecv && len(in.Args) > 0 {
		recv := in.Args[0]
		owner := ownerKey(c.RecvType)
		if owner == "" {
			owner = ownerOf(fn, recv)
		}
		out := cf.field(owner, c.Name, fn)
		if held := of(recv); len(held) > 0 {
			closureArg := false
			for _, a := range in.Args[1:] {
				closureArg = closureArg || len(of(a)) > 0
			}
			if runsReceiver(c, len(in.Args)-1, closureArg) {
				out, _ = cf.addAll(out, held, false, nil)
			}
		}
		return out, 1
	}
	// A method calling a closure-typed property of its own class without
	// writing the receiver (onSend(v) in Swift).
	if c.Name != "" && len(fn.Params) > 0 && fn.Parent == "" && isSelf(fn.Vars[fn.Params[0]].Name) {
		return cf.field(ownerOf(fn, fn.Params[0]), c.Name, fn), 0
	}
	return nil, 0
}

// containerBuilders build a collection or holder from their arguments.
var containerBuilders = map[string]bool{
	"listof": true, "mutablelistof": true, "arraylistof": true, "arrayof": true, "setof": true,
	"mutablesetof": true, "hashsetof": true, "mapof": true, "mutablemapof": true, "hashmapof": true,
	"of": true, "aslist": true, "singletonlist": true, "list": true, "tuple": true, "set": true, "dict": true,
	"to": true, "pair": true, "array": true, "from": true, "ofnullable": true, "just": true,
}

func (cf *closureFlow) transfer(fn *ir.Func, in *ir.Instr) {
	of := func(v ir.VarID) []closure { return cf.of(fn.ID, v) }
	switch in.Op {
	case ir.OpClosure:
		cf.addVar(fn.ID, in.Dst, []closure{{fn: in.Func, in: fn.ID, binds: in.Args}}, false)
	case ir.OpAssign, ir.OpPhi:
		for _, a := range in.Args {
			cf.addVar(fn.ID, in.Dst, of(a), false)
		}
	case ir.OpLoad:
		if len(in.Args) == 0 {
			return
		}
		owner := ownerKey(in.Owner)
		if owner == "" {
			owner = ownerOf(fn, in.Args[0])
		}
		cf.addVar(fn.ID, in.Dst, cf.field(owner, in.Field, fn), false)
		// An element of a collection holding closures (a map read by key,
		// a property of an object of unknown shape). A field of a declared
		// type holds only what is stored in it: a handler struct that runs
		// closures does not make its database handle one, and the load
		// below would otherwise put them into that field of every object
		// of the type (#32).
		if in.Owner == "" || !cf.a.opts.Schema.KnownType(in.Owner) {
			cf.addVar(fn.ID, in.Dst, of(in.Args[0]), false)
		}
		// The loaded object is the one in the field: what is added to it
		// (this.handlers.add(h)) is in the field. Only for an owner of
		// known type: with an unknown one, the field would stand for that
		// field of every object, and what one local object holds would
		// reach every read of a field of that name.
		if owner != "" {
			cf.addField(owner, in.Field, of(in.Dst))
		}
	case ir.OpStore:
		if len(in.Args) < 2 {
			return
		}
		owner := ownerKey(in.Owner)
		if owner == "" {
			owner = ownerOf(fn, in.Args[0])
		}
		cf.addField(owner, in.Field, of(in.Args[1]))
	case ir.OpReturn, ir.OpYield:
		for _, a := range in.Args {
			var grew bool
			cf.rets[fn.ID], grew = cf.addAll(cf.rets[fn.ID], of(a), false, nil)
			cf.grew = cf.grew || grew
		}
	case ir.OpCall, ir.OpNew:
		cf.call(fn, in, of)
	}
}

func (cf *closureFlow) call(fn *ir.Func, in *ir.Instr, of func(ir.VarID) []closure) {
	c := in.Call
	if c == nil {
		return
	}
	// Into the parameters of the functions called, out of what they return.
	var targets []string
	args := in.Args
	switch {
	case in.Op == ir.OpNew:
		if c.Target != "" {
			targets = []string{c.Target}
			args = append([]ir.VarID{in.Dst}, in.Args...)
		}
	case !c.Indirect:
		targets = cf.a.cha.targets(c, fn.Lang)
	}
	for _, t := range targets {
		tf := cf.a.funcs[t]
		if tf == nil {
			continue
		}
		names := c.ArgNames
		if in.Op == ir.OpNew && names != nil {
			names = append([]string{""}, names...)
		}
		arranged, _ := cf.a.arrange(t, args, names)
		for j, p := range tf.Params {
			if j < len(arranged) && j < len(tf.Params)-tf.Captures {
				cf.addVar(t, p, of(arranged[j]), true)
			}
		}
		if in.Op == ir.OpCall {
			cf.addVar(fn.ID, in.Dst, cf.rets[t], false)
		}
	}
	// Into the parameters of the closures called, out of what they return.
	cls, first := cf.invoked(fn, in, of)
	for _, cl := range cls {
		tf := cf.a.funcs[cl.fn]
		if tf == nil {
			continue
		}
		nIn := len(tf.Params) - tf.Captures
		for j := 0; j < nIn && first+j < len(in.Args); j++ {
			cf.addVar(cl.fn, tf.Params[j], of(in.Args[first+j]), true)
		}
		cf.addVar(fn.ID, in.Dst, cf.rets[cl.fn], false)
	}
	if len(targets) > 0 || len(cls) > 0 || in.Op == ir.OpNew {
		return
	}
	// A callback run by the callee gets the call's other arguments, the
	// receiver first: handlers.forEach { it(v) } calls each handler.
	if runsCallbackNow(c) {
		for i, a := range in.Args {
			for _, cl := range of(a) {
				tf := cf.a.funcs[cl.fn]
				if tf == nil || tf.Captures >= len(tf.Params) {
					continue
				}
				for j, o := range in.Args {
					if j != i {
						cf.addVar(cl.fn, tf.Params[0], of(o), false)
					}
				}
			}
		}
	}
	// Unknown code: a collection read gives its elements
	// (handlers.get(0)), a builder holds its arguments (listOf(h)), and a
	// mutating method puts its arguments into the receiver
	// (handlers.add(h)).
	if c.HasRecv && len(in.Args) > 0 {
		cf.addVar(fn.ID, in.Dst, of(in.Args[0]), false)
		if isMutator(c.Name) {
			for _, a := range in.Args[1:] {
				cf.addVar(fn.ID, in.Args[0], of(a), false)
			}
		}
	}
	if containerBuilders[strings.ToLower(c.Name)] {
		for _, a := range in.Args {
			cf.addVar(fn.ID, in.Dst, of(a), false)
		}
	}
}
