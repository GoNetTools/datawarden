// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package analysis runs an inter-procedural taint analysis over IR.
//
// Each function is analyzed to a fixpoint over its code property graph:
// the SSA variables the frontends produce (every assignment its own
// variable) order values, and the control-flow graph orders mutations of
// objects. A fact an instruction puts on an object (a field store,
// list.add, a callee writing into an argument) carries that instruction,
// and only instructions it can run before (order.go) see it; copies keep
// the mark, so an alias sees the object's later mutations. A variable
// named after personal data is a source unless it is a new version of a
// same-named value (email = sha256(email)). Parameters
// carry symbolic labels so that the same pass produces both concrete flows
// (source and sink known) and a Summary that callers apply without
// re-analyzing the callee. Functions are processed callees-first by
// strongly connected component; recursive components iterate until their
// summaries stop changing.
package analysis

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// Options configures an analysis run.
type Options struct {
	Rules  RuleMatcher
	Schema SchemaIndex
	Names  NameClassifier
	// Lookup returns a cached summary for a function that is not part of
	// this run (PR mode), or nil.
	Lookup func(id string) *Summary
	// FirstPartyDomains turns network sinks to matching hosts first-party.
	FirstPartyDomains []string
	// MinConf drops facts and flows below this confidence.
	MinConf float64
}

// RuleMatcher finds sink, source and transform rules for a call
// (implemented by *rules.Set).
type RuleMatcher interface {
	Match(lang, kind string, c *ir.Call) []rules.Hit
}

// SchemaIndex answers schema questions (implemented by *detect.Schema).
type SchemaIndex interface {
	Field(owner, field string) (detect.Hint, detect.FieldState)
	TypeDataTypes(typ string) []string
	KnownType(typ string) bool
}

// NameClassifier recognises PII names (implemented by *detect.Classifier).
type NameClassifier interface {
	Ident(name string) (detect.Match, bool)
	Field(owner, field string) (detect.Match, bool)
	Key(s string) (detect.Match, bool)
	Getter(name string) (detect.Match, bool)
	FuncTransform(name string) string
}

// Input is the per-run part of Options, supplied by the scanner.
type Input struct {
	Rules             RuleMatcher
	Schema            SchemaIndex
	Lookup            func(id string) *Summary
	FirstPartyDomains []string
}

// Engine is the analysis service. Its name classifier and threshold are
// configured once; rules, schema and cached summaries vary per run.
type Engine struct {
	Names   NameClassifier
	MinConf float64
}

// Analyze runs the analysis for one scan.
func (e Engine) Analyze(ctx context.Context, funcs []*ir.Func, in Input) (*Result, error) {
	return Analyze(ctx, funcs, Options{Rules: in.Rules, Schema: in.Schema, Names: e.Names, Lookup: in.Lookup, FirstPartyDomains: in.FirstPartyDomains, MinConf: e.MinConf})
}

// Result is the output of Analyze.
type Result struct {
	Flows     []*finding.Flow
	Summaries map[string]*Summary
	// CallGraph maps each analyzed function to the in-program functions it calls.
	CallGraph map[string][]string
}

type fact struct {
	dt    string // data type; "" for symbolic parameter facts
	param int    // parameter index for symbolic facts, else -1
	// field narrows a symbolic fact to one field of the parameter
	// (this.addr), so callers use what they stored there.
	field string
	src   ir.Pos
	desc  string
	path  []ir.Pos
	xf    []string
	conf  float64
	seed  bool // seeded on this very variable (by its own name/type)
	// at is 1 + the index of the instruction that put this fact on an
	// object by mutating it (a field store, list.add, a callee writing
	// into an argument), or 0 for a fact the value has from its
	// definition. A mutation is seen only by instructions it can run
	// before.
	at int
}

func (f *fact) key() string {
	k := fmt.Sprintf("#%d.%s|%s", f.param, f.field, xfKey(f.xf))
	if f.dt != "" {
		k = f.dt + "|" + xfKey(f.xf)
	}
	if f.at > 0 {
		k += fmt.Sprintf("@%d", f.at)
	}
	return k
}

type state struct {
	facts  []map[string]*fact
	stores map[ir.VarID]map[string]map[string]*fact
	minC   float64
	order  *order
	cur    int    // index of the instruction being analyzed
	multi  []bool // variables with more than one definition
}

// visible reports whether f can be seen by the current instruction.
func (s *state) visible(f *fact) bool {
	return f.at == 0 || s.order.before(f.at-1, s.cur)
}

// mutation marks a fact as put on an object by the current instruction.
func (s *state) mutation(f *fact) *fact {
	f.at = s.cur + 1
	return f
}

func (s *state) add(v ir.VarID, f *fact) bool {
	if v < 0 || int(v) >= len(s.facts) || f == nil || f.conf < s.minC {
		return false
	}
	m := s.facts[v]
	if m == nil {
		m = map[string]*fact{}
		s.facts[v] = m
	}
	k := f.key()
	if old, ok := m[k]; ok && old.conf >= f.conf {
		return false
	}
	m[k] = f
	return true
}

func (s *state) addStore(obj ir.VarID, field string, f *fact) bool {
	if f.conf < s.minC {
		return false
	}
	fm := s.stores[obj]
	if fm == nil {
		fm = map[string]map[string]*fact{}
		s.stores[obj] = fm
	}
	m := fm[field]
	if m == nil {
		m = map[string]*fact{}
		fm[field] = m
	}
	k := f.key()
	if old, ok := m[k]; ok && old.conf >= f.conf {
		return false
	}
	m[k] = f
	return true
}

// of returns the facts of v the current instruction can see.
func (s *state) of(v ir.VarID) []*fact {
	if v < 0 || int(v) >= len(s.facts) {
		return nil
	}
	m := s.facts[v]
	if len(m) == 0 {
		return nil
	}
	out := make([]*fact, 0, len(m))
	for _, f := range m {
		if s.visible(f) {
			out = append(out, f)
		}
	}
	return out
}

// all returns every fact of v, wherever the mutations behind them happen.
func (s *state) all(v ir.VarID) []*fact {
	if v < 0 || int(v) >= len(s.facts) {
		return nil
	}
	out := make([]*fact, 0, len(s.facts[v]))
	for _, f := range s.facts[v] {
		out = append(out, f)
	}
	return out
}

const maxPath = 16

func appendPath(p []ir.Pos, extra ...ir.Pos) []ir.Pos {
	out := make([]ir.Pos, len(p), len(p)+len(extra))
	copy(out, p)
	for _, e := range extra {
		if !e.IsValid() {
			continue
		}
		if n := len(out); n > 0 && out[n-1].File == e.File && out[n-1].Line == e.Line {
			continue
		}
		out = append(out, e)
	}
	if len(out) > maxPath {
		out = append(out[:4:4], out[len(out)-(maxPath-4):]...)
	}
	return out
}

func mergeXf(a []string, extra ...string) []string {
	if len(extra) == 0 {
		return a
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	changed := false
	for _, x := range extra {
		if x != "" && !set[x] {
			set[x] = true
			changed = true
		}
	}
	if !changed {
		return a
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func derive(f *fact, pos ir.Pos, decay float64, xf ...string) *fact {
	return &fact{dt: f.dt, param: f.param, field: f.field, src: f.src, desc: f.desc, path: appendPath(f.path, pos), xf: mergeXf(f.xf, xf...), conf: f.conf * decay}
}

type analyzer struct {
	opts      Options
	summaries map[string]*Summary
	digests   map[string]string
	funcs     map[string]*ir.Func
	flows     map[string]*finding.Flow
}

// Analyze runs the analysis over funcs.
func Analyze(ctx context.Context, funcs []*ir.Func, opts Options) (*Result, error) {
	if opts.MinConf == 0 {
		opts.MinConf = 0.2
	}
	if opts.Rules == nil || opts.Schema == nil || opts.Names == nil {
		return nil, errors.New("analysis: Rules, Schema and Names are required")
	}
	a := &analyzer{opts: opts, summaries: map[string]*Summary{}, digests: map[string]string{}, funcs: map[string]*ir.Func{}, flows: map[string]*finding.Flow{}}
	for _, f := range funcs {
		a.funcs[f.ID] = f
	}
	cg := map[string][]string{}
	for _, f := range funcs {
		seen := map[string]bool{}
		for _, in := range f.Instrs {
			if in.Op != ir.OpCall || in.Call == nil {
				continue
			}
			// Every function the call may run: its static target, the
			// overrides and implementations, and a constructor.
			for _, t := range append([]string{in.Call.Target, in.Call.Ctor}, in.Call.Targets...) {
				if t != "" && !seen[t] {
					seen[t] = true
					cg[f.ID] = append(cg[f.ID], t)
				}
			}
		}
		sort.Strings(cg[f.ID])
	}
	for _, scc := range tarjan(funcs, cg, a.funcs) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recursive := len(scc) > 1
		if len(scc) == 1 {
			for _, c := range cg[scc[0].ID] {
				if c == scc[0].ID {
					recursive = true
				}
			}
		}
		for iter := 0; iter < 8; iter++ {
			changed := false
			for _, fn := range scc {
				s := a.analyzeFunc(fn)
				d := s.Digest()
				if d != a.digests[fn.ID] {
					a.digests[fn.ID] = d
					a.summaries[fn.ID] = s
					changed = true
				}
			}
			if !recursive || !changed {
				break
			}
		}
	}
	res := &Result{Summaries: a.summaries, CallGraph: cg}
	keys := make([]string, 0, len(a.flows))
	for k := range a.flows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Flows = append(res.Flows, a.flows[k])
	}
	return res, nil
}

func (a *analyzer) summaryFor(id string) *Summary {
	if s, ok := a.summaries[id]; ok {
		return s
	}
	if _, inProgram := a.funcs[id]; inProgram {
		return nil // not analyzed yet (recursion): treated as unknown for now
	}
	if a.opts.Lookup != nil {
		return a.opts.Lookup(id)
	}
	return nil
}

func isBoolOrFunc(t string) bool {
	switch t {
	case "bool", "boolean", "Boolean", "kotlin.Boolean", "java.lang.Boolean", "untyped bool":
		return true
	}
	return strings.HasPrefix(t, "func(") || strings.HasPrefix(t, "(")
}

func (a *analyzer) seed(st *state, fn *ir.Func) {
	redef := redefinitions(fn)
	for i, pid := range fn.Params {
		v := fn.Vars[pid]
		st.add(pid, &fact{dt: "", param: i, src: v.Pos, desc: "parameter " + v.Name, path: []ir.Pos{v.Pos}, conf: 1})
	}
	for id := range fn.Vars {
		v := &fn.Vars[id]
		if v.IsConst() {
			continue
		}
		vid := ir.VarID(id)
		if v.Name != "" && !isBoolOrFunc(v.Type) && !redef[vid] {
			if m, ok := a.opts.Names.Ident(v.Name); ok {
				f := &fact{dt: m.DataType, param: -1, src: v.Pos, desc: fmt.Sprintf("identifier %q", v.Name), path: []ir.Pos{v.Pos}, conf: m.Conf, seed: true}
				if m.Transform != "" {
					f.xf = []string{m.Transform}
				}
				st.add(vid, f)
			}
		}
		if v.Type != "" {
			if dts := a.opts.Schema.TypeDataTypes(v.Type); len(dts) > 0 {
				desc := fmt.Sprintf("value of type %s", shortType(v.Type))
				if v.Name != "" {
					desc = fmt.Sprintf("%s (%s)", v.Name, desc)
				}
				for _, dt := range dts {
					st.add(vid, &fact{dt: dt, param: -1, src: v.Pos, desc: desc, path: []ir.Pos{v.Pos}, conf: 0.7, seed: true})
				}
			}
		}
	}
}

// redefinitions marks variables whose value is computed from an earlier
// variable of the same name: email = sha256(email), x = x.strip(), or the
// merged version of x after an if. Such a variable is a new version of the
// same source value, not a new source: whatever it holds reaches it through
// its definition, transforms included, so it is not seeded by its name.
// email = request.get("email") has no such dependency and is seeded.
func redefinitions(fn *ir.Func) []bool {
	defs := make([][]ir.VarID, len(fn.Vars))
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		if in.Dst < 0 || int(in.Dst) >= len(fn.Vars) {
			continue
		}
		switch in.Op {
		case ir.OpAssign, ir.OpCall:
			defs[in.Dst] = append(defs[in.Dst], in.Args...)
		case ir.OpLoad:
			if len(in.Args) > 0 {
				defs[in.Dst] = append(defs[in.Dst], in.Args[0])
			}
		}
	}
	out := make([]bool, len(fn.Vars))
	for id := range fn.Vars {
		name := fn.Vars[id].Name
		if name == "" || len(defs[id]) == 0 {
			continue
		}
		seen := map[ir.VarID]bool{ir.VarID(id): true}
		work := append([]ir.VarID(nil), defs[id]...)
		for len(work) > 0 && len(seen) < 256 {
			v := work[len(work)-1]
			work = work[:len(work)-1]
			if v < 0 || int(v) >= len(fn.Vars) || seen[v] {
				continue
			}
			seen[v] = true
			if fn.Vars[v].Name == name {
				out[id] = true
				break
			}
			work = append(work, defs[v]...)
		}
	}
	return out
}

// multiDefined marks variables with more than one definition: several
// instructions write them, or a parameter is also assigned. Writes to them
// are weak updates (arr[i] = v, a Go store through a pointer), which the
// analysis orders like other mutations.
func multiDefined(fn *ir.Func) []bool {
	n := make([]int, len(fn.Vars))
	for _, p := range fn.Params {
		if p >= 0 && int(p) < len(n) {
			n[p]++
		}
	}
	for i := range fn.Instrs {
		if d := fn.Instrs[i].Dst; d >= 0 && int(d) < len(n) {
			n[d]++
		}
	}
	out := make([]bool, len(n))
	for v, c := range n {
		out[v] = c > 1
	}
	return out
}

func shortType(t string) string {
	t = strings.TrimLeft(t, "*&[]")
	if i := strings.LastIndexAny(t, "/"); i >= 0 {
		t = t[i+1:]
	}
	return t
}

func (a *analyzer) analyzeFunc(fn *ir.Func) *Summary {
	st := &state{facts: make([]map[string]*fact, len(fn.Vars)), stores: map[ir.VarID]map[string]map[string]*fact{}, minC: a.opts.MinConf,
		order: newOrder(fn), multi: multiDefined(fn)}
	a.seed(st, fn)
	sum := &Summary{}
	for iter := 0; iter < 40; iter++ {
		changed := false
		for i := range fn.Instrs {
			st.cur = i
			if a.step(st, fn, &fn.Instrs[i], sum) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	// Returns and parameter side effects, read off the final state.
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		if in.Op != ir.OpReturn {
			continue
		}
		st.cur = i
		for _, arg := range in.Args {
			for _, f := range st.of(arg) {
				t := Transfer{Xf: f.xf, Conf: f.conf, Path: appendPath(f.path, in.Pos), Field: f.field}
				rf := RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf}
				switch {
				case in.Throw && f.dt == "":
					sum.addParamThrow(f.param, t)
				case in.Throw:
					sum.addThrowFact(rf)
				case f.dt == "":
					sum.addParamReturn(f.param, t)
				default:
					sum.addReturnFact(rf)
				}
			}
		}
	}
	for i, pid := range fn.Params {
		for _, f := range st.all(pid) {
			switch {
			case f.dt == "" && (f.param != i || f.at > 0):
				if f.param == i && f.field == "" {
					continue
				}
				sum.addParamParam(i, f.param, Transfer{Xf: f.xf, Conf: f.conf, Path: f.path, Field: f.field})
			case f.dt != "" && !f.seed:
				sum.addParamOut(i, RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: f.path, Xf: f.xf, Conf: f.conf})
			}
		}
		// What the function stored into fields of the parameter
		// (this.addr = email): callers put it in the same field.
		fm := st.stores[pid]
		for _, field := range slices.Sorted(maps.Keys(fm)) {
			for _, f := range fm[field] {
				switch {
				case f.dt == "":
					if f.param == i && f.field == field {
						continue // the field keeps its own value
					}
					sum.addParamParam(i, f.param, Transfer{Xf: f.xf, Conf: f.conf, Path: f.path, Field: f.field, DstField: field})
				case !f.seed:
					sum.addParamOut(i, RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: f.path, Xf: f.xf, Conf: f.conf, DstField: field})
				}
			}
		}
	}
	return sum
}

// fieldFacts returns what reading field of obj yields at the current
// instruction: a schema or name hint for the field, what was stored there,
// the whole object's facts when its type is unknown, and, when obj is a
// parameter of a known type, a symbolic fact for that field of it, so
// callers answer with what they put in the field.
func (a *analyzer) fieldFacts(st *state, fn *ir.Func, obj ir.VarID, owner, field string, pos ir.Pos) []*fact {
	if owner == "" && obj >= 0 && int(obj) < len(fn.Vars) {
		owner = fn.Vars[obj].Type
	}
	ctxName := owner
	if ctxName == "" && obj >= 0 && int(obj) < len(fn.Vars) {
		ctxName = fn.Vars[obj].Name
	}
	var out []*fact
	h, fs := a.opts.Schema.Field(owner, field)
	switch fs {
	case detect.FieldPII:
		f := &fact{dt: h.DataType, param: -1, src: pos, desc: fmt.Sprintf("field %s (%s)", fieldLabel(owner, field), h.Via), path: []ir.Pos{pos}, conf: h.Conf}
		if h.Transform != "" {
			f.xf = []string{h.Transform}
		}
		out = append(out, f)
	case detect.FieldUnknown:
		if m, ok := a.opts.Names.Field(ctxName, field); ok {
			f := &fact{dt: m.DataType, param: -1, src: pos, desc: fmt.Sprintf("field %s", fieldLabel(owner, field)), path: []ir.Pos{pos}, conf: m.Conf}
			if m.Transform != "" {
				f.xf = []string{m.Transform}
			}
			out = append(out, f)
		}
	}
	if fm := st.stores[obj]; fm != nil {
		for _, f := range fm[field] {
			if st.visible(f) {
				out = append(out, derive(f, pos, 1))
			}
		}
	}
	if fs == detect.FieldNotPII {
		return out
	}
	known := a.opts.Schema.KnownType(owner)
	for _, f := range st.of(obj) {
		switch {
		case !known:
			out = append(out, derive(f, pos, 0.8))
		case f.dt == "" && f.at == 0:
			// obj is (an alias of) a parameter: this field of it.
			d := derive(f, pos, 1)
			if d.field == "" {
				d.field = field
			}
			out = append(out, d)
		}
	}
	return out
}

func (a *analyzer) step(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) bool {
	changed := false
	switch in.Op {
	case ir.OpAssign:
		for _, arg := range in.Args {
			if in.Snapshot {
				// A new value built from what the argument holds now.
				for _, f := range st.of(arg) {
					changed = st.add(in.Dst, derive(f, in.Pos, 1)) || changed
				}
				continue
			}
			if in.Dst >= 0 && int(in.Dst) < len(st.multi) && st.multi[in.Dst] {
				// One of several definitions (arr[i] = v, an assignment
				// inside a lambda): a mutation at this point.
				for _, f := range st.of(arg) {
					changed = st.add(in.Dst, st.mutation(derive(f, in.Pos, 1))) || changed
				}
				continue
			}
			// A copy or merge aliases its arguments: the object's
			// mutations stay ordered where they happen, and what was
			// stored in its fields is in the alias's fields too.
			for _, f := range st.all(arg) {
				d := derive(f, in.Pos, 1)
				d.at = f.at
				changed = st.add(in.Dst, d) || changed
			}
			for field, m := range st.stores[arg] {
				for _, f := range m {
					d := derive(f, in.Pos, 1)
					d.at = f.at
					changed = st.addStore(in.Dst, field, d) || changed
				}
			}
		}
	case ir.OpLoad:
		if len(in.Args) == 0 {
			return false
		}
		for _, f := range a.fieldFacts(st, fn, in.Args[0], in.Owner, in.Field, in.Pos) {
			changed = st.add(in.Dst, f) || changed
		}
	case ir.OpStore:
		if len(in.Args) < 2 {
			return false
		}
		obj, val := in.Args[0], in.Args[1]
		for _, f := range st.of(val) {
			d := st.mutation(derive(f, in.Pos, 1))
			changed = st.addStore(obj, in.Field, d) || changed
			changed = st.add(obj, d) || changed
		}
		// A store without a declared owner type is a map or object literal
		// ({"email": v}): the key names the value, whatever other types say
		// about fields of the same name. For typed owners the schema decides.
		untyped := in.Owner == ""
		if _, fs := a.opts.Schema.Field(in.Owner, in.Field); untyped || (fs == detect.FieldUnknown && !a.opts.Schema.KnownType(in.Owner)) {
			if m, ok := a.opts.Names.Key(in.Field); ok {
				changed = st.add(obj, st.mutation(&fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("key %q", in.Field), path: []ir.Pos{in.Pos}, conf: m.Conf})) || changed
			}
		}
	case ir.OpCall:
		changed = a.call(st, fn, in, sum)
	}
	return changed
}

func fieldLabel(owner, field string) string {
	if owner == "" {
		return field
	}
	return shortType(owner) + "." + field
}

// keyLabels applies the "key names its value" heuristic: in
// put("email", x), setCustomKey("phone", x), zap.String("phone", x) or
// mapOf("ssn" to x) the literal key says what the next argument is.
func (a *analyzer) keyLabels(fn *ir.Func, in *ir.Instr, recvOff int) map[int][]*fact {
	var out map[int][]*fact
	for i := recvOff; i+1 < len(in.Args); i++ {
		v := in.Args[i]
		if v < 0 || !fn.Vars[v].IsConst() {
			continue
		}
		if m, ok := a.opts.Names.Key(*fn.Vars[v].Const); ok {
			if out == nil {
				out = map[int][]*fact{}
			}
			f := &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("key %q", *fn.Vars[v].Const), path: []ir.Pos{in.Pos}, conf: m.Conf}
			out[i+1] = append(out[i+1], f)
		}
	}
	return out
}

var getterVerbs = []string{"get", "opt", "form", "postform", "query", "param", "header", "lookup", "read", "cookie", "extra"}

func isGetterName(name string) bool {
	n := strings.ToLower(name)
	for _, v := range getterVerbs {
		if strings.HasPrefix(n, v) {
			return true
		}
	}
	return false
}

func calleeLabel(c *ir.Call) string {
	switch {
	case c.Callee != "":
		return c.Callee
	case c.RecvText != "":
		return c.RecvText + "." + c.Name
	case c.RecvType != "":
		return shortType(c.RecvType) + "." + c.Name
	}
	return c.Name
}

func (a *analyzer) call(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) bool {
	c := in.Call
	if c == nil {
		return false
	}
	changed := false
	recvOff := 0
	if c.HasRecv && len(in.Args) > 0 {
		recvOff = 1
	}
	keyed := a.keyLabels(fn, in, recvOff)
	factsOf := func(i int) []*fact {
		fs := st.of(in.Args[i])
		if k := keyed[i]; len(k) > 0 {
			fs = append(fs, k...)
		}
		return fs
	}
	label := calleeLabel(c)

	// Sinks.
	remote := false
	for _, hit := range a.opts.Rules.Match(fn.Lang, rules.KindSink, c) {
		r := hit.Rule
		remote = remote || r.Category == "network"
		dest := a.dest(r, fn, in, recvOff)
		for i := recvOff; i < len(in.Args); i++ {
			if !r.Arg.Selects(i - recvOff) {
				continue
			}
			for _, f := range factsOf(i) {
				if f.dt == "" {
					sum.addParamSink(f.param, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: fn.ID, Call: label, Lang: fn.Lang,
						Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf * hit.Conf, Field: f.field})
					continue
				}
				a.emit(f, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: fn.ID, Call: label, Lang: fn.Lang, Conf: hit.Conf}, nil)
			}
		}
	}

	// Sources.
	for _, hit := range a.opts.Rules.Match(fn.Lang, rules.KindSource, c) {
		f := &fact{dt: hit.Rule.DataType, param: -1, src: in.Pos, desc: "call " + label, path: []ir.Pos{in.Pos}, conf: 0.9 * hit.Conf}
		changed = st.add(in.Dst, f) || changed
		for _, cb := range c.Callbacks {
			changed = st.add(cb, f) || changed
		}
	}

	// Transforms (sanitizers): the result carries the input's data types
	// with the transform recorded; no default propagation.
	if hits := a.opts.Rules.Match(fn.Lang, rules.KindTransform, c); len(hits) > 0 {
		x := hits[0].Rule.Transform
		for i := range in.Args {
			for _, f := range factsOf(i) {
				changed = st.add(in.Dst, derive(f, in.Pos, 1, x)) || changed
			}
		}
		return changed
	}

	nameXf := a.opts.Names.FuncTransform(c.Name)

	// Calls into analyzed code: apply the callee summaries. A dynamically
	// dispatched call may run Target or any of Targets (its overrides and
	// implementations); a construction runs Ctor on the new object.
	if c.Ctor != "" {
		if s := a.summaryFor(c.Ctor); s != nil {
			// The constructor's first parameter is the new object.
			base := append([]ir.VarID{in.Dst}, in.Args...)
			var names []string
			if c.ArgNames != nil {
				names = append([]string{""}, c.ArgNames...)
			}
			args, idx := a.arrange(c.Ctor, base, names)
			factsAt := func(i int) []*fact {
				switch {
				case idx[i] < 0:
					return nil
				case idx[i] == 0:
					return st.of(in.Dst)
				}
				return factsOf(idx[i] - 1)
			}
			changed = a.apply(st, fn, in, s, args, factsAt, "", ir.NoVar, sum) || changed
		}
	}
	applied := false
	for _, t := range append([]string{c.Target}, c.Targets...) {
		if t == "" {
			continue
		}
		if s := a.summaryFor(t); s != nil {
			args, idx := a.arrange(t, in.Args, c.ArgNames)
			factsAt := func(i int) []*fact {
				if idx[i] < 0 {
					return nil
				}
				return factsOf(idx[i])
			}
			changed = a.apply(st, fn, in, s, args, factsAt, nameXf, in.Dst, sum) || changed
			applied = true
		}
	}
	if applied {
		return changed
	}

	// Unknown code: conservative propagation. A getter on a value whose
	// type the schema knows (profile.getBio()) is answered from the schema
	// instead of smearing every field of the object onto the result.
	nonRecv := len(in.Args) - recvOff
	skipRecv := false
	if recvOff == 1 && nonRecv == 0 && in.Args[0] >= 0 {
		if owner := fn.Vars[in.Args[0]].Type; owner != "" && a.opts.Schema.KnownType(owner) {
			if field, ok := getterField(c.Name); ok {
				skipRecv = true
				if h, fs := a.opts.Schema.Field(owner, field); fs == detect.FieldPII {
					f := &fact{dt: h.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("%s.%s() (%s)", shortType(owner), c.Name, h.Via), path: []ir.Pos{in.Pos}, conf: h.Conf}
					changed = st.add(in.Dst, f) || changed
				}
			}
		}
	}
	for i := range in.Args {
		if skipRecv && i == 0 {
			continue
		}
		for _, f := range factsOf(i) {
			if remote {
				// A network call answers with the remote's response,
				// which is not derived from what was sent: a login
				// request's reply is not the password.
				continue
			}
			changed = st.add(in.Dst, derive(f, in.Pos, 0.95, nameXf)) || changed
			if i >= recvOff && recvOff == 1 && !c.Construct && isMutator(c.Name) {
				changed = st.add(in.Args[0], st.mutation(derive(f, in.Pos, 0.9))) || changed
			}
			for _, cb := range c.Callbacks {
				changed = st.add(cb, derive(f, in.Pos, 0.9)) || changed
			}
		}
	}
	if nonRecv == 0 && in.Dst >= 0 && !skipRecv {
		if m, ok := a.opts.Names.Getter(c.Name); ok {
			f := &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("getter %s()", c.Name), path: []ir.Pos{in.Pos}, conf: m.Conf}
			if m.Transform != "" {
				f.xf = []string{m.Transform}
			}
			changed = st.add(in.Dst, f) || changed
		}
	}
	if nonRecv >= 1 && in.Dst >= 0 && isGetterName(c.Name) {
		if v := in.Args[recvOff]; v >= 0 && fn.Vars[v].IsConst() {
			if m, ok := a.opts.Names.Key(*fn.Vars[v].Const); ok {
				changed = st.add(in.Dst, &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("%s(%q)", c.Name, *fn.Vars[v].Const), path: []ir.Pos{in.Pos}, conf: m.Conf}) || changed
			}
		}
	}
	return changed
}

// apply applies a callee summary at a call. args are the callee's
// parameters in order and factsAt(i) what parameter i receives; dst takes
// the return value.
func (a *analyzer) apply(st *state, fn *ir.Func, in *ir.Instr, s *Summary, args []ir.VarID, factsAt func(int) []*fact, nameXf string, dst ir.VarID, sum *Summary) bool {
	changed := false
	// facts of parameter i, or of one field of it.
	of := func(i int, field string) []*fact {
		switch {
		case field == "":
			return factsAt(i)
		case args[i] < 0:
			return nil
		}
		return a.fieldFacts(st, fn, args[i], "", field, in.Pos)
	}
	put := func(target ir.VarID, field string, f *fact) {
		if target < 0 {
			return
		}
		f = st.mutation(f)
		if field != "" {
			changed = st.addStore(target, field, f) || changed
		}
		changed = st.add(target, f) || changed
	}
	for i := range args {
		for _, t := range s.ParamReturn[i] {
			for _, f := range of(i, t.Field) {
				d := derive(f, in.Pos, t.Conf, append(append([]string{}, t.Xf...), nameXf)...)
				d.path = appendPath(d.path, t.Path...)
				changed = st.add(dst, d) || changed
			}
		}
		for _, h := range s.ParamSink[i] {
			for _, f := range of(i, h.Field) {
				if f.dt == "" {
					h2 := h
					h2.Field = f.field
					h2.Path = appendPath(appendPath(f.path, in.Pos), h.Path...)
					h2.Xf = mergeXf(f.xf, h.Xf...)
					h2.Conf = f.conf * h.Conf
					sum.addParamSink(f.param, h2)
					continue
				}
				a.emit(f, h, []ir.Pos{in.Pos})
			}
		}
	}
	for dstParam, m := range s.ParamParam {
		if dstParam >= len(args) {
			continue
		}
		for src, ts := range m {
			if src >= len(args) {
				continue
			}
			for _, t := range ts {
				for _, f := range of(src, t.Field) {
					put(args[dstParam], t.DstField, derive(f, in.Pos, t.Conf, t.Xf...))
				}
			}
		}
	}
	for dstParam, rfs := range s.ParamOut {
		if dstParam >= len(args) {
			continue
		}
		for _, rf := range rfs {
			put(args[dstParam], rf.DstField, realToFact(rf, in.Pos))
		}
	}
	for _, rf := range s.ReturnFacts {
		f := realToFact(rf, in.Pos)
		f.xf = mergeXf(f.xf, nameXf)
		changed = st.add(dst, f) || changed
	}
	// What the callee throws reaches the handler (or escapes further).
	for _, cv := range in.Call.Catch {
		for i := range args {
			for _, t := range s.ParamThrow[i] {
				for _, f := range of(i, t.Field) {
					d := derive(f, in.Pos, t.Conf, t.Xf...)
					d.path = appendPath(d.path, t.Path...)
					put(cv, "", d)
				}
			}
		}
		for _, rf := range s.ThrowFacts {
			put(cv, "", realToFact(rf, in.Pos))
		}
	}
	return changed
}

// arrange maps call arguments onto the callee's parameters: positional
// ones in order, keyword ones (names[i] != "") to the parameter of that
// name. It returns, per parameter, the argument variable and its index in
// args (-1 when no argument fills it).
func (a *analyzer) arrange(callee string, args []ir.VarID, names []string) ([]ir.VarID, []int) {
	f := a.funcs[callee]
	if f == nil || len(names) != len(args) {
		idx := make([]int, len(args))
		for i := range idx {
			idx[i] = i
		}
		return args, idx
	}
	n := max(len(f.Params), len(args))
	idx := make([]int, n)
	for i := range idx {
		idx[i] = -1
	}
	next := 0
	for i, name := range names {
		if name == "" && next < n {
			idx[next] = i
			next++
		}
	}
	for i, name := range names {
		if name == "" {
			continue
		}
		placed := false
		for j, p := range f.Params {
			if f.Vars[p].Name == name && idx[j] < 0 {
				idx[j], placed = i, true
				break
			}
		}
		// No parameter of that name: Python's **kwargs, the last one.
		if last := len(f.Params) - 1; !placed && last >= 0 && idx[last] < 0 {
			idx[last] = i
		}
	}
	out := make([]ir.VarID, n)
	for i, k := range idx {
		out[i] = ir.NoVar
		if k >= 0 {
			out[i] = args[k]
		}
	}
	return out, idx
}

func realToFact(rf RealFact, pos ir.Pos) *fact {
	return &fact{dt: rf.DataType, param: -1, src: rf.Src, desc: rf.Desc, path: appendPath(rf.Path, pos), xf: rf.Xf, conf: rf.Conf}
}

func (a *analyzer) dest(r *rules.Rule, fn *ir.Func, in *ir.Instr, recvOff int) finding.Destination {
	d := finding.Destination{Host: r.Dest.Host, Kind: r.Dest.Kind, Region: r.Dest.Region, Vendor: r.Dest.Vendor}
	if r.HostArg != nil {
		i := *r.HostArg + recvOff
		if i < len(in.Args) && in.Args[i] >= 0 {
			if v := fn.Vars[in.Args[i]]; v.IsConst() {
				if h := hostOf(*v.Const); h != "" {
					d.Host = h
				}
			}
		}
	}
	if d.Kind == rules.DestNetwork && d.Host != "" {
		for _, dom := range a.opts.FirstPartyDomains {
			dom = strings.ToLower(strings.TrimPrefix(dom, "."))
			if h := strings.ToLower(d.Host); h == dom || strings.HasSuffix(h, "."+dom) {
				d.Kind = rules.DestFirstParty
			}
		}
	}
	d.FirstParty = d.Kind == rules.DestFirstParty
	return d
}

func hostOf(s string) string {
	if !strings.Contains(s, "://") {
		if strings.HasPrefix(s, "/") {
			return ""
		}
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (a *analyzer) emit(f *fact, h SinkHit, via []ir.Pos) {
	conf := f.conf * h.Conf
	if conf < a.opts.MinConf {
		return
	}
	path := appendPath(f.path, via...)
	path = appendPath(path, h.Path...)
	path = appendPath(path, h.Sink)
	xf := mergeXf(f.xf, h.Xf...)
	fl := &finding.Flow{
		DataType: f.dt, Source: f.src, Sink: h.Sink, SinkRule: h.Rule, Dest: h.Dest, Path: path,
		Transforms: xf, Confidence: round2(conf), Function: h.Func, Lang: h.Lang, SourceDesc: f.desc, SinkCall: h.Call,
	}
	k := strings.Join([]string{f.dt, h.Rule, h.Func, h.Sink.String(), xfKey(xf)}, "|")
	if old, ok := a.flows[k]; ok && old.Confidence >= fl.Confidence {
		return
	}
	a.flows[k] = fl
}

func round2(f float64) float64 {
	if f > 1 {
		f = 1
	}
	return float64(int(f*100+0.5)) / 100
}

// getterField maps getEmail/isVerified/email() style accessors to the
// field they read.
func getterField(name string) (string, bool) {
	for _, p := range []string{"get", "is", "Get"} {
		if len(name) > len(p) && strings.HasPrefix(name, p) && name[len(p)] >= 'A' && name[len(p)] <= 'Z' {
			rest := name[len(p):]
			return strings.ToLower(rest[:1]) + rest[1:], true
		}
	}
	return "", false
}

var mutatorPrefixes = []string{"put", "add", "append", "set", "insert", "push", "write", "with", "field", "param", "header",
	"body", "extra", "attr", "merge", "concat", "plus", "unshift", "enqueue", "offer", "store", "json", "form", "query", "arg", "str",
	"int", "any", "object", "value", "update", "fill", "copy", "emit", "send", "post", "next", "resolve", "complete", "apply", "also", "let", "run"}

// isMutator reports whether a method on an unknown receiver plausibly
// stores its arguments into the receiver (builders, collections, bundles).
func isMutator(name string) bool {
	n := strings.ToLower(name)
	for _, p := range mutatorPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
