// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package analysis runs an inter-procedural taint analysis over IR.
//
// Each function is analyzed to a fixpoint over its code property graph:
// the SSA variables the frontends produce (every assignment its own
// variable) order values, and the control-flow graph orders mutations of
// objects. A fact an instruction puts on an object (a field store,
// list.add, a callee writing into an argument) carries that instruction,
// and only the instructions it reaches without a strong update of the
// same field in between see it (order.go, reaching definitions); every
// variable that may refer to the object gets it (pointsto.go), and copies
// keep the mark, so an alias sees the object's later mutations. A variable
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
	"strconv"
	"strings"
	"unicode"

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
	// Classes is the class table that dynamically dispatched calls are
	// resolved against.
	Classes []*ir.Class
	// Callers returns the callers of a function known from earlier runs,
	// when only part of the program is analysed (PR mode), or is nil.
	Callers func(id string) []string
}

// RuleMatcher finds sink, source and transform rules for a call, and
// source rules for a field read or a parameter's annotations (implemented
// by *rules.Set).
type RuleMatcher interface {
	Match(lang, kind string, c *ir.Call) []rules.Hit
	MatchField(lang, owner, field, recv string) []rules.Hit
	MatchParam(lang string, annotations []string) []rules.Hit
}

// requestData is the data type of what a client sent to a web handler
// (req.body, request.POST, @RequestBody). Read under a known key or field
// name (form["email"], req.body.page), the name says what the value is:
// the part does not carry requestData.
const requestData = "request_data"

// sourceConf is the confidence of what a source rule hit produces.
func sourceConf(h rules.Hit) float64 {
	c := h.Rule.Confidence
	if c == 0 {
		c = 1
	}
	return 0.9 * h.Conf * c
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
	Classes           []*ir.Class
	Callers           func(id string) []string
}

// Engine is the analysis service. Its name classifier and threshold are
// configured once; rules, schema and cached summaries vary per run.
type Engine struct {
	Names   NameClassifier
	MinConf float64
}

// Analyze runs the analysis for one scan.
func (e Engine) Analyze(ctx context.Context, funcs []*ir.Func, in Input) (*Result, error) {
	return Analyze(ctx, funcs, Options{Rules: in.Rules, Schema: in.Schema, Names: e.Names, Lookup: in.Lookup, FirstPartyDomains: in.FirstPartyDomains, MinConf: e.MinConf, Classes: in.Classes, Callers: in.Callers})
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
	// stored is the field a store put this fact into, when the fact is
	// on the object itself because one of its fields holds it: reading
	// another field of an object of unknown type does not give it.
	stored string
	// at is 1 + the index of the instruction that put this fact on an
	// object by mutating it (a field store, list.add, a callee writing
	// into an argument), or 0 for a fact the value has from its
	// definition. A mutation is seen only by instructions it can run
	// before.
	at int
}

func (f *fact) key() string {
	var b strings.Builder
	if f.dt != "" {
		b.WriteString(f.dt)
	} else {
		b.WriteByte('#')
		b.WriteString(strconv.Itoa(f.param))
		b.WriteByte('.')
		b.WriteString(f.field)
	}
	b.WriteByte('|')
	for i, x := range f.xf {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(x)
	}
	if f.at > 0 {
		b.WriteByte('@')
		b.WriteString(strconv.Itoa(f.at))
	}
	if f.stored != "" {
		b.WriteByte('^')
		b.WriteString(f.stored)
	}
	return b.String()
}

type state struct {
	facts  []map[string]*fact
	stores map[ir.VarID]map[string]map[string]*fact
	minC   float64
	order  *order
	cur    int    // index of the instruction being analyzed
	multi  []bool // variables with more than one definition
	// fluent maps the result of a mutating call to its receiver:
	// sb.append(a).append(b) mutates sb through the first call's result.
	fluent map[ir.VarID]ir.VarID
	// thrown holds, per call instruction, what the callee throws.
	thrown map[int]map[string]*fact
	// closures are the closures each variable may hold (closureFlow),
	// without those that came in through a parameter.
	closures map[ir.VarID][]closure
	// loads maps the result of a load to the object and field it was
	// read from, so that a store into it is also a store into a longer
	// access path of that object (user.addr.city = email).
	loads map[ir.VarID]loadRef
	// guards lists, per block, the consent checks guarding it.
	guards [][]string
	// checks are the values a branch on a check refined (checks.go).
	checks map[ir.VarID]check
	// defs maps each variable to its defining instruction (definitions).
	defs []int
	// pt is the points-to result: which variables may refer to the same
	// object (pointsto.go).
	pt *pointsTo
	// kills lists, per field store, the strong updates that overwrite
	// what it stored: later stores into the same field of the same
	// single object. reached caches reachesAvoiding.
	kills   map[int][]int
	reached map[[2]int]bool
	// last is the index of each block's last instruction, or -1.
	last []int
}

type loadRef struct {
	obj   ir.VarID
	field string
}

// maxFieldDepth bounds access paths: a.b.c is tracked, a.b.c.d is
// collapsed to a.b.c.
const maxFieldDepth = 3

func fieldDepth(path string) int {
	if path == "" {
		return 0
	}
	return strings.Count(path, ".") + 1
}

// joinField appends field to an access path, keeping the path bounded.
func joinField(path, field string) string {
	switch {
	case path == "":
		return field
	case fieldDepth(path) >= maxFieldDepth:
		return path
	}
	return path + "." + field
}

func (s *state) addThrown(i int, f *fact) bool {
	if f == nil || f.conf < s.minC {
		return false
	}
	if s.thrown == nil {
		s.thrown = map[int]map[string]*fact{}
	}
	m := s.thrown[i]
	if m == nil {
		m = map[string]*fact{}
		s.thrown[i] = m
	}
	k := f.key()
	if old, ok := m[k]; ok && !betterFact(f, old) {
		return false
	}
	m[k] = f
	return true
}

// guardsAt lists the consent checks guarding the current instruction.
func (s *state) guardsAt(fn *ir.Func) []string {
	if s.guards == nil || s.cur < 0 || s.cur >= len(fn.Instrs) {
		return nil
	}
	b := fn.Instrs[s.cur].Block
	if b < 0 || int(b) >= len(s.guards) {
		return nil
	}
	return s.guards[b]
}

// visible reports whether f can be seen by the current instruction: the
// mutation that put it there can run before it, on a path where no strong
// update overwrites what it stored (a reaching-definitions question over
// the control-flow graph).
func (s *state) visible(f *fact) bool {
	if f.at == 0 {
		return true
	}
	q := f.at - 1
	ks := s.kills[q]
	if len(ks) == 0 {
		return s.order.before(q, s.cur)
	}
	k := [2]int{q, s.cur}
	if r, ok := s.reached[k]; ok {
		return r
	}
	r := s.order.reachesAvoiding(q, s.cur, func(i int) bool { return slices.Contains(ks, i) })
	if s.reached == nil {
		s.reached = map[[2]int]bool{}
	}
	s.reached[k] = r
	return r
}

// atExit keeps the facts that are still there when the function returns:
// those no strong update overwrites on some path to an exit.
func (s *state) atExit(fn *ir.Func, fs []*fact) []*fact {
	var out []*fact
	for _, f := range fs {
		ks := s.kills[f.at-1]
		if f.at == 0 || len(ks) == 0 {
			out = append(out, f)
			continue
		}
		for b := range fn.Blocks {
			if len(fn.Blocks[b].Succs) == 0 && s.order.reachesEnd(f.at-1, int32(b), func(i int) bool { return slices.Contains(ks, i) }) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// strongUpdates finds, for each field store, the later stores that
// overwrite it: stores into the same field of the same object, through
// variables that refer to that single object only.
func strongUpdates(fn *ir.Func, pt *pointsTo) map[int][]int {
	type key struct {
		o     objectID
		field string
	}
	byKey := map[key][]int{}
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		if in.Op != ir.OpStore || len(in.Args) != 2 || in.Field == "" {
			continue
		}
		if o, ok := pt.only(in.Args[0]); ok {
			byKey[key{o, in.Field}] = append(byKey[key{o, in.Field}], i)
		}
	}
	var out map[int][]int
	for _, stores := range byKey {
		if len(stores) < 2 {
			continue
		}
		if out == nil {
			out = map[int][]int{}
		}
		for _, i := range stores {
			for _, j := range stores {
				if j != i {
					out[i] = append(out[i], j)
				}
			}
		}
	}
	return out
}

// mutate puts f on the object v refers to, in field when it is set, as a
// mutation of the object: every variable that may refer to it gets it.
func (s *state) mutate(v ir.VarID, field string, f *fact) bool {
	changed := false
	for _, w := range s.pt.mutated(v) {
		if field != "" {
			changed = s.addStore(w, field, f) || changed
			g := *f
			g.stored = field
			changed = s.add(w, &g) || changed
			continue
		}
		changed = s.add(w, f) || changed
	}
	return changed
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
	if old, ok := m[k]; ok && !betterFact(f, old) {
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
	if old, ok := m[k]; ok && !betterFact(f, old) {
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
		if j := slices.Index(out, e); j >= 0 {
			// Back where the path already was: drop the loop (a value
			// going round a recursive call or a callback).
			out = out[:j+1]
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
	cha  *hierarchy
	flow *closureFlow
	// guards are, per function, the consent checks guarding each block:
	// its own branches and those every caller passed (guard.go).
	guards map[string][][]string
	// checks are, per function, the checked values (refineChecks).
	checks    map[string]map[ir.VarID]check
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
	a := &analyzer{cha: newHierarchy(opts.Classes), opts: opts, summaries: map[string]*Summary{}, digests: map[string]string{}, funcs: map[string]*ir.Func{}, flows: map[string]*finding.Flow{},
		checks: map[string]map[ir.VarID]check{}}
	// Branches on checks (isMasked(v), isValidEmail(v)) give the checked
	// value a new version where they pass; the caller's functions are not
	// changed.
	funcs = slices.Clone(funcs)
	for i, f := range funcs {
		if rf, cks := a.refineChecks(f); cks != nil {
			funcs[i], a.checks[f.ID] = rf, cks
		}
	}
	for _, f := range funcs {
		a.funcs[f.ID] = f
	}
	a.flow = newClosureFlow(a, funcs)
	cg := map[string][]string{}
	for _, f := range funcs {
		seen := map[string]bool{}
		for i := range f.Instrs {
			in := &f.Instrs[i]
			// Every function the instruction may run: a call's static
			// target, overrides and implementations, a constructor, and
			// the closures it creates (which calls may run).
			var ts []string
			switch {
			case in.Op == ir.OpClosure:
				ts = []string{in.Func}
			case in.Op == ir.OpNew && in.Call != nil:
				ts = []string{in.Call.Target}
			case in.Op == ir.OpCall && in.Call != nil:
				ts = a.cha.targets(in.Call, f.Lang)
				// The closures it may call (held in a field, returned
				// by a function).
				cls, _ := a.flow.invoked(f, in, func(v ir.VarID) []closure { return a.flow.of(f.ID, v) })
				for _, cl := range cls {
					if !cl.param {
						ts = append(ts, cl.fn)
					}
				}
			}
			for _, t := range ts {
				if t != "" && !seen[t] {
					seen[t] = true
					cg[f.ID] = append(cg[f.ID], t)
				}
			}
		}
		sort.Strings(cg[f.ID])
	}
	a.guards = a.consentGuards(funcs)
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
	a.callChains(res.Flows, cg)
	return res, nil
}

// consentGuards computes the consent checks guarding each block of each
// function: branches on a consent check (or on a helper returning one) in
// the function, and the checks guarding every call of it.
func (a *analyzer) consentGuards(funcs []*ir.Func) map[string][][]string {
	helpers := consentHelpers(funcs)
	blocks := map[string][][]string{}
	sites := map[string][]callSite{}
	for _, f := range funcs {
		blocks[f.ID] = guards(f, helpers)
		for i := range f.Instrs {
			in := &f.Instrs[i]
			var ts []string
			switch {
			case in.Op == ir.OpClosure:
				ts = []string{in.Func}
			case in.Op == ir.OpNew && in.Call != nil:
				ts = []string{in.Call.Target}
			case in.Op == ir.OpCall && in.Call != nil:
				ts = a.cha.targets(in.Call, f.Lang)
			}
			for _, t := range ts {
				if _, ok := a.funcs[t]; ok && t != f.ID {
					sites[t] = append(sites[t], callSite{fn: f.ID, block: in.Block})
				}
			}
		}
	}
	if a.opts.Callers != nil {
		// A function with a caller outside this run may be called
		// without the check.
		for t := range sites {
			for _, c := range a.opts.Callers(t) {
				if _, ok := a.funcs[c]; !ok {
					sites[t] = append(sites[t], callSite{fn: c, block: -1})
					break
				}
			}
		}
	}
	inherited := inheritedGuards(sites, blocks)
	out := map[string][][]string{}
	for _, f := range funcs {
		bg := blocks[f.ID]
		if inh := inherited[f.ID]; len(inh) > 0 {
			merged := make([][]string, len(f.Blocks))
			for b := range merged {
				if b < len(bg) {
					merged[b] = append(merged[b], bg[b]...)
				}
				merged[b] = mergeXf(merged[b], inh...)
			}
			bg = merged
		}
		out[f.ID] = bg
	}
	return out
}

// reportFunc is the function a flow is reported in: for a closure, the
// named function it is written in, so that findings and their baseline
// fingerprints name the code a reader looks for.
func (a *analyzer) reportFunc(fn *ir.Func) string {
	for depth := 0; fn.Parent != "" && depth < 16; depth++ {
		p, ok := a.funcs[fn.Parent]
		if !ok {
			return fn.Parent
		}
		fn = p
	}
	return fn.ID
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
	// A variable defined by a transform (hashed = sha256(x), token =
	// encrypt(pw)) holds the transformed value whatever its name says.
	defs := definitions(fn)
	definedBy := func(v ir.VarID) []string {
		var in *ir.Instr
		for depth := 0; depth < 4; depth++ {
			if v < 0 || int(v) >= len(defs) || defs[v] < 0 {
				return nil
			}
			in = &fn.Instrs[defs[v]]
			if in.Op != ir.OpAssign || len(in.Args) != 1 {
				break
			}
			v = in.Args[0] // a copy: what it copies
		}
		if in.Op != ir.OpCall || in.Call == nil {
			return nil
		}
		if x := a.opts.Names.FuncTransform(in.Call.Name); x != "" {
			return []string{x}
		}
		if hits := a.opts.Rules.Match(fn.Lang, rules.KindTransform, in.Call); len(hits) > 0 {
			return []string{hits[0].Rule.Transform}
		}
		return nil
	}
	for i, pid := range fn.Params {
		v := fn.Vars[pid]
		st.add(pid, &fact{dt: "", param: i, src: v.Pos, desc: "parameter " + v.Name, path: []ir.Pos{v.Pos}, conf: 1})
		if len(v.Annotations) > 0 {
			// @RequestBody Map body, @Body() dto: what the client sent.
			for _, h := range a.opts.Rules.MatchParam(fn.Lang, v.Annotations) {
				st.add(pid, &fact{dt: h.Rule.DataType, param: -1, src: v.Pos, desc: fmt.Sprintf("parameter %s (%s)", v.Name, h.How), path: []ir.Pos{v.Pos}, conf: sourceConf(h), seed: true})
			}
		}
	}
	for id := range fn.Vars {
		v := &fn.Vars[id]
		if v.IsConst() {
			continue
		}
		vid := ir.VarID(id)
		if v.Name != "" && !isBoolOrFunc(v.Type) && !redef[vid] && !errorValue(fn, defs, vid) {
			if m, ok := a.opts.Names.Ident(v.Name); ok {
				f := &fact{dt: m.DataType, param: -1, src: v.Pos, desc: fmt.Sprintf("identifier %q", v.Name), path: []ir.Pos{v.Pos}, conf: m.Conf, seed: true}
				f.xf = mergeXf(nil, append(definedBy(vid), m.Transform)...)
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
		case ir.OpAssign, ir.OpCall, ir.OpPhi, ir.OpCompute, ir.OpNew:
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

// multiDefined marks cells and variables with more than one definition:
// several instructions write them, or a parameter is also assigned. Writes
// to them are weak updates (arr[i] = v, a Go store through a pointer, a
// closure assigning a captured variable), which the analysis orders like
// other mutations.
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
		out[v] = c > 1 || fn.Vars[v].Cell
	}
	return out
}

// lastInstrs returns the index of each block's last instruction.
func lastInstrs(fn *ir.Func) []int {
	out := make([]int, len(fn.Blocks))
	for b := range out {
		out[b] = -1
	}
	for i := range fn.Instrs {
		if b := fn.Instrs[i].Block; b >= 0 && int(b) < len(out) {
			out[b] = i
		}
	}
	return out
}

// loadsOf maps each load's result to the object and field it reads.
func loadsOf(fn *ir.Func) map[ir.VarID]loadRef {
	out := map[ir.VarID]loadRef{}
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		if in.Op == ir.OpLoad && len(in.Args) == 1 && in.Dst >= 0 && in.Field != "" {
			out[in.Dst] = loadRef{in.Args[0], in.Field}
		}
	}
	return out
}

// fluentResults maps the result of each mutating method call to its
// receiver: builders return themselves (StringBuilder.append, put, add).
func fluentResults(fn *ir.Func) map[ir.VarID]ir.VarID {
	out := map[ir.VarID]ir.VarID{}
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		if in.Op == ir.OpCall && in.Call != nil && in.Call.HasRecv && len(in.Args) > 0 && in.Dst >= 0 && isMutator(in.Call.Name) {
			out[in.Dst] = in.Args[0]
		}
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
		order: newOrder(fn), multi: multiDefined(fn), fluent: fluentResults(fn), loads: loadsOf(fn), guards: a.guards[fn.ID], last: lastInstrs(fn),
		closures: a.flow.local(fn.ID), checks: a.checks[fn.ID]}
	st.pt = newPointsTo(fn, st.fluent, st.checks, st.order)
	st.defs = definitions(fn)
	st.kills = strongUpdates(fn, st.pt)
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
	// Returns, escaping exceptions and parameter side effects, read off
	// the final state.
	for i := range fn.Instrs {
		in := &fn.Instrs[i]
		st.cur = i
		escapes := !handled(fn, in)
		if in.Op == ir.OpCall && escapes {
			// What a callee throws outside any handler leaves this function.
			for _, f := range st.thrown[i] {
				t := Transfer{Xf: f.xf, Conf: f.conf, Path: appendPath(f.path, in.Pos), Field: f.field}
				if f.dt == "" {
					sum.addParamThrow(f.param, t)
				} else {
					sum.addThrowFact(RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: t.Path, Xf: f.xf, Conf: f.conf})
				}
			}
			continue
		}
		throw := in.Op == ir.OpThrow
		if !(in.Op == ir.OpReturn || in.Op == ir.OpYield || throw && escapes) {
			continue
		}
		for _, arg := range in.Args {
			// What the returned object holds in its fields (a factory
			// returning &mailbox{addr: email}): callers get it in the
			// same fields of the result.
			if !throw {
				fm := st.stores[arg]
				for _, field := range slices.Sorted(maps.Keys(fm)) {
					for _, f := range fm[field] {
						if !st.visible(f) {
							continue
						}
						if f.dt == "" {
							sum.addParamReturn(f.param, Transfer{Xf: f.xf, Conf: f.conf, Path: appendPath(f.path, in.Pos), Field: f.field, DstField: field})
						} else if !f.seed {
							sum.addReturnFact(RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf, DstField: field})
						}
					}
				}
			}
			for _, f := range st.of(arg) {
				if f.stored != "" && !throw {
					continue // one field's value, returned in that field above
				}
				t := Transfer{Xf: f.xf, Conf: f.conf, Path: appendPath(f.path, in.Pos), Field: f.field}
				rf := RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf}
				switch {
				case throw && f.dt == "":
					sum.addParamThrow(f.param, t)
				case throw:
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
		for _, f := range st.atExit(fn, st.all(pid)) {
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
			for _, f := range st.atExit(fn, slices.Collect(maps.Values(fm[field]))) {
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

// handled reports whether an exception raised by in goes to a handler in
// the function: in ends a block with exceptional successors.
func handled(fn *ir.Func, in *ir.Instr) bool {
	b := in.Block
	return b >= 0 && int(b) < len(fn.Blocks) && len(fn.Blocks[b].Exc) > 0
}

// fieldFacts returns what reading field of obj yields at the current
// instruction: a schema or name hint for the field, what was stored there,
// the whole object's facts when its type is unknown, and, when obj is a
// parameter of a known type, a symbolic fact for that field of it, so
// callers answer with what they put in the field. field may be an access
// path (addr.city); hints then come from its last field.
func (a *analyzer) fieldFacts(st *state, fn *ir.Func, obj ir.VarID, owner, field string, pos ir.Pos) []*fact {
	name := field
	if i := strings.LastIndexByte(field, '.'); i >= 0 {
		name, owner = field[i+1:], "?"
	}
	if owner == "" && obj >= 0 && int(obj) < len(fn.Vars) {
		owner = copiedType(fn, st.defs, obj)
	}
	ctxName := owner
	if ctxName == "" && obj >= 0 && int(obj) < len(fn.Vars) {
		ctxName = fn.Vars[obj].Name
	}
	if owner == "?" {
		owner, ctxName = "", ""
	}
	var out []*fact
	h, fs := a.opts.Schema.Field(owner, name)
	switch fs {
	case detect.FieldPII:
		f := &fact{dt: h.DataType, param: -1, src: pos, desc: fmt.Sprintf("field %s (%s)", fieldLabel(owner, field), h.Via), path: []ir.Pos{pos}, conf: h.Conf}
		if h.Transform != "" {
			f.xf = []string{h.Transform}
		}
		out = append(out, f)
	case detect.FieldUnknown:
		if m, ok := a.opts.Names.Field(ctxName, name); ok {
			f := &fact{dt: m.DataType, param: -1, src: pos, desc: fmt.Sprintf("field %s", fieldLabel(owner, field)), path: []ir.Pos{pos}, conf: m.Conf}
			if m.Transform != "" {
				f.xf = []string{m.Transform}
			}
			out = append(out, f)
		}
	}
	if fm := st.stores[obj]; fm != nil {
		// What was stored in the field, and in fields of the object it
		// holds (user.addr holds what user.addr.city was given).
		for key, m := range fm {
			if key != field && !strings.HasPrefix(key, field+".") {
				continue
			}
			for _, f := range m {
				if st.visible(f) {
					out = append(out, derive(f, pos, 1))
				}
			}
		}
	}
	if fs == detect.FieldNotPII {
		return out
	}
	known := a.opts.Schema.KnownType(owner)
	for _, f := range st.of(obj) {
		switch {
		case f.stored != "" && !wholeValueFields[name]:
			// Held by one of the object's fields: read from st.stores
			// above when it is this one.
		case f.dt == "" && f.at == 0:
			// obj is (an alias of) a parameter or a field of one: this
			// field of it. Callers answer with what they hold there, or
			// with the whole argument when its type is unknown to them.
			d := derive(f, pos, 1)
			for _, part := range strings.Split(field, ".") {
				d.field = joinField(d.field, part)
			}
			out = append(out, d)
		case f.dt == requestData && name != "":
			// req.body.page: the field name says what it holds.
		case !known:
			out = append(out, derive(f, pos, 0.8))
		}
	}
	return out
}

func (a *analyzer) step(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) bool {
	changed := false
	switch in.Op {
	case ir.OpCompute:
		// A new value built from what the arguments hold now; a boolean
		// operation carries no data.
		if ir.Logical(in.Operator) {
			return false
		}
		for _, arg := range in.Args {
			for _, f := range st.of(arg) {
				changed = st.add(in.Dst, derive(f, in.Pos, 1)) || changed
			}
		}
		// "credit card: " + cc: the text names the value after it.
		for _, fs := range a.textLabels(fn, st.defs, in.Args, in.Pos) {
			for _, f := range fs {
				changed = st.add(in.Dst, f) || changed
			}
		}
	case ir.OpAssign, ir.OpPhi:
		if ck, ok := st.checks[in.Dst]; ok {
			return a.checkedValue(st, in, ck)
		}
		if in.Dst >= 0 && dataFreeName(fn.Vars[in.Dst].Name) && !fn.Vars[in.Dst].Cell {
			return false // a status or count computed from the data
		}
		for _, arg := range in.Args {
			if in.Dst >= 0 && int(in.Dst) < len(st.multi) && st.multi[in.Dst] {
				// One of several definitions of a cell (arr[i] = v, a
				// closure assigning a captured variable): a mutation at
				// this point.
				for _, f := range st.of(arg) {
					changed = st.add(in.Dst, st.mutation(derive(f, in.Pos, 1))) || changed
				}
				continue
			}
			changed = a.alias(st, in, in.Dst, arg) || changed
		}
	case ir.OpCatch:
		changed = a.catch(st, fn, in)
	case ir.OpLoad:
		if len(in.Args) == 0 {
			return false
		}
		obj := in.Args[0]
		for _, f := range a.fieldFacts(st, fn, obj, in.Owner, in.Field, in.Pos) {
			changed = st.add(in.Dst, f) || changed
		}
		// A field read that is a source: r.Body, req.body, request.POST.
		owner := in.Owner
		if owner == "" {
			owner = copiedType(fn, st.defs, obj)
		}
		for _, h := range a.opts.Rules.MatchField(fn.Lang, owner, in.Field, accessPath(fn, st.defs, obj)) {
			f := &fact{dt: h.Rule.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("field %s (%s)", in.Field, h.How), path: []ir.Pos{in.Pos}, conf: sourceConf(h)}
			changed = st.add(in.Dst, f) || changed
		}
		// The loaded object's own fields: what was stored under
		// obj.field.x is in x of the result.
		for key, m := range st.stores[obj] {
			rest, ok := strings.CutPrefix(key, in.Field+".")
			if !ok {
				continue
			}
			for _, f := range m {
				if st.visible(f) {
					d := derive(f, in.Pos, 1)
					d.at = f.at
					changed = st.addStore(in.Dst, rest, d) || changed
				}
			}
		}
	case ir.OpStore:
		if len(in.Args) < 2 {
			return false
		}
		obj, val := in.Args[0], in.Args[1]
		for _, f := range st.of(val) {
			d := st.mutation(derive(f, in.Pos, 1))
			changed = st.mutate(obj, in.Field, d) || changed
			// A store into an object read from another one's field is a
			// store into a longer access path of that one: t = user.addr;
			// t.city = email stores user.addr.city.
			path, base := in.Field, obj
			for depth := 0; depth < maxFieldDepth; depth++ {
				ref, ok := st.loads[base]
				if !ok || fieldDepth(path) >= maxFieldDepth {
					break
				}
				path, base = ref.field+"."+path, ref.obj
				changed = st.mutate(base, path, d) || changed
			}
		}
		// A store without a declared owner type is a map or object literal
		// ({"email": v}): the key names the value, whatever other types say
		// about fields of the same name. For typed owners the schema decides.
		// An error keyed by the field it is about ({"email":
		// ValidationError("Email is required")}) does not hold that data.
		untyped := in.Owner == ""
		if _, fs := a.opts.Schema.Field(in.Owner, in.Field); !errorValue(fn, st.defs, val) && (untyped || (fs == detect.FieldUnknown && !a.opts.Schema.KnownType(in.Owner))) {
			if m, ok := a.opts.Names.Key(in.Field); ok && !a.keyContradicted(fn, st.defs, val, m.DataType) {
				f := st.mutation(&fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("key %q", in.Field), path: []ir.Pos{in.Pos}, conf: m.Conf, stored: in.Field})
				for _, w := range st.pt.mutated(obj) {
					changed = st.add(w, f) || changed
				}
			}
		}
	case ir.OpCall, ir.OpNew:
		changed = a.call(st, fn, in, sum)
	}
	switch in.Op {
	case ir.OpStore:
		if len(in.Args) == 2 {
			changed = a.escape(st, fn, in, in.Args[1], sum) || changed
		}
	case ir.OpReturn:
		for _, arg := range in.Args {
			changed = a.escape(st, fn, in, arg, sum) || changed
		}
	}
	return changed
}

// escape runs the closures v holds that capture variables of fn, when they
// leave it (stored in a field, returned): wherever they are called later,
// they read their captures, with every mutation made to them.
func (a *analyzer) escape(st *state, fn *ir.Func, in *ir.Instr, v ir.VarID, sum *Summary) bool {
	changed := false
	for _, cl := range st.closures[v] {
		if cl.in != fn.ID || len(cl.binds) == 0 {
			continue
		}
		_, ch := a.runClosure(st, fn, in, cl, nil, func(int) []*fact { return nil }, st.all, sum)
		changed = changed || ch
	}
	return changed
}

// alias makes dst an alias of src: a copy or merge of references. The
// object's mutations stay ordered where they happen, and what was stored
// in its fields is in the alias's fields too.
func (a *analyzer) alias(st *state, in *ir.Instr, dst, src ir.VarID) bool {
	changed := false
	for _, f := range st.all(src) {
		d := derive(f, in.Pos, 1)
		d.at, d.stored = f.at, f.stored
		changed = st.add(dst, d) || changed
	}
	for field, m := range st.stores[src] {
		for _, f := range m {
			d := derive(f, in.Pos, 1)
			d.at = f.at
			changed = st.addStore(dst, field, d) || changed
		}
	}
	return changed
}

// catch gives a handler's caught exception what reaches it: the value of
// each throw, and what each call throws, in the blocks whose exceptional
// edges lead to the handler.
func (a *analyzer) catch(st *state, fn *ir.Func, in *ir.Instr) bool {
	changed := false
	for b := range fn.Blocks {
		if !slices.Contains(fn.Blocks[b].Exc, in.Block) {
			continue
		}
		last := st.last[b]
		if last < 0 {
			continue
		}
		switch t := &fn.Instrs[last]; t.Op {
		case ir.OpThrow:
			for _, arg := range t.Args {
				for _, f := range st.of(arg) {
					changed = st.add(in.Dst, derive(f, t.Pos, 1)) || changed
				}
			}
		case ir.OpCall, ir.OpNew:
			for _, f := range st.thrown[last] {
				changed = st.add(in.Dst, derive(f, in.Pos, 1)) || changed
			}
		}
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
func (a *analyzer) keyLabels(fn *ir.Func, defs []int, in *ir.Instr, recvOff int) map[int][]*fact {
	var out map[int][]*fact
	for i := recvOff; i+1 < len(in.Args); i++ {
		key, ok := constOf(fn, defs, in.Args[i])
		if !ok {
			continue
		}
		if m, ok := a.opts.Names.Key(key); ok && !a.keyContradicted(fn, defs, in.Args[i+1], m.DataType) {
			if out == nil {
				out = map[int][]*fact{}
			}
			f := &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("key %q", key), path: []ir.Pos{in.Pos}, conf: m.Conf}
			out[i+1] = append(out[i+1], f)
		}
	}
	return out
}

var getterVerbs = []string{"get", "opt", "form", "postform", "query", "param", "header", "lookup", "read", "cookie", "extra", "value", "object", "string"}

// wholeValueFields are properties that render the whole object
// (user.description in Swift): they hold what any of its fields holds.
var wholeValueFields = map[string]bool{"description": true, "debugDescription": true, "dictionaryRepresentation": true, "allValues": true}

// dataFreeSuffixes end the names of variables that hold a status, a count
// or a flag computed from data, not the data: derivationStatus, rowCount.
var dataFreeSuffixes = []string{"status", "count", "length", "size", "success", "succeeded", "exists", "ok"}

func dataFreeName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range dataFreeSuffixes {
		if n == s || strings.HasSuffix(n, s) && len(n) > len(s) && (n[len(n)-len(s)-1] == '_' || name[len(name)-len(s)] >= 'A' && name[len(name)-len(s)] <= 'Z') {
			return true
		}
	}
	return false
}

// publicParts are accessors that return the public part of what they are
// called on: a key entry's certificate or public key is not its private
// key.
var publicParts = map[string]bool{"getcertificate": true, "getcertificatechain": true, "getpublickey": true, "getpublic": true, "publickey": true, "certificate": true}

// decodeInto maps decoders to the argument they fill (receiver included).
var decodeInto = map[string]int{
	"encoding/json.Unmarshal":                  1,
	"encoding/json.Decoder.Decode":             1,
	"encoding/xml.Unmarshal":                   1,
	"encoding/xml.Decoder.Decode":              1,
	"encoding/gob.Decoder.Decode":              1,
	"gopkg.in/yaml.v3.Unmarshal":               1,
	"github.com/gorilla/schema.Decoder.Decode": 1,
}

// keyedRead reports whether a call reads a value under a constant key:
// a getter given a string literal first (form.get("page"),
// r.FormValue("ssn"), getParameter("q")), or chi.URLParam(r, "id").
func (a *analyzer) keyedRead(fn *ir.Func, defs []int, in *ir.Instr, recvOff int) bool {
	if in.Call == nil || !isGetterName(in.Call.Name) && !strings.HasSuffix(in.Call.Name, "Param") {
		return false
	}
	for i := recvOff; i < len(in.Args); i++ {
		if k, ok := constOf(fn, defs, in.Args[i]); ok && k != "" {
			return true
		}
	}
	return false
}

// accessPath writes the object v as the source does when it is a named
// variable or a chain of field reads from one (req, ctx.request), else "".
func accessPath(fn *ir.Func, defs []int, v ir.VarID) string {
	path := ""
	for depth := 0; depth < 4 && v >= 0 && int(v) < len(fn.Vars); depth++ {
		if name := fn.Vars[v].Name; name != "" {
			if path == "" {
				return name
			}
			return name + "." + path
		}
		if int(v) >= len(defs) || defs[v] < 0 {
			return ""
		}
		in := &fn.Instrs[defs[v]]
		switch {
		case in.Op == ir.OpAssign && len(in.Args) == 1:
		case in.Op == ir.OpLoad && len(in.Args) == 1 && in.Field != "":
			if path == "" {
				path = in.Field
			} else {
				path = in.Field + "." + path
			}
		default:
			return ""
		}
		v = in.Args[0]
	}
	return ""
}

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
	isNew := in.Op == ir.OpNew
	recvOff := 0
	if (c.HasRecv || c.Indirect) && len(in.Args) > 0 {
		recvOff = 1
	}
	keyed := a.keyLabels(fn, st.defs, in, recvOff)
	for i, fs := range a.textLabels(fn, st.defs, in.Args, in.Pos) {
		if i >= recvOff {
			if keyed == nil {
				keyed = map[int][]*fact{}
			}
			keyed[i] = append(keyed[i], fs...)
		}
	}
	factsOf := func(i int) []*fact {
		fs := st.of(in.Args[i])
		// A key or label names a value that does not already say what
		// it is: putString("password", encrypt(pw)) stays encrypted.
		for _, k := range keyed[i] {
			if !slices.ContainsFunc(fs, func(f *fact) bool { return f.dt == k.dt }) {
				fs = append(fs, k)
			}
		}
		return fs
	}
	label := calleeLabel(c)
	guards := st.guardsAt(fn)
	run, first := a.flow.invoked(fn, in, func(v ir.VarID) []closure { return st.closures[v] })
	match := a.opts.Rules.Match
	if len(run) > 0 && c.Callee == "" {
		// A local or field holding closures, called: rules for a function
		// of that name do not apply.
		match = func(string, string, *ir.Call) []rules.Hit { return nil }
	}

	// Sinks.
	remote := false
	for _, hit := range match(fn.Lang, rules.KindSink, c) {
		r := hit.Rule
		remote = remote || r.Category == "network"
		dest := a.dest(r, fn, in, recvOff)
		for i := 0; i < len(in.Args); i++ {
			if i < recvOff && !(c.HasRecv && r.Arg.Selects(-1)) || !r.Arg.Selects(i-recvOff) {
				continue
			}
			if i < recvOff && a.chainedSink(fn, st.defs, in.Args[i], r.ID) {
				// log.Info().Str("ip", ip).Msg("x"): the receiver is what
				// the previous call of the chain returned, and that call
				// reported what it carries.
				continue
			}
			for _, f := range factsOf(i) {
				if i < recvOff && f.at > 0 && a.sinkCall(fn, f.at-1, r.ID) {
					// evt.Str("ip", ip); evt.Msg(""): put on the receiver
					// by a call that already reported it.
					continue
				}
				if f.dt == "" {
					sum.addParamSink(f.param, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: a.reportFunc(fn), Call: label, Lang: fn.Lang,
						Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf * hit.Conf, Field: f.field, Guards: guards})
					continue
				}
				a.emit(f, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: a.reportFunc(fn), Call: label, Lang: fn.Lang, Conf: hit.Conf, Guards: guards}, nil)
			}
		}
	}

	// Sources. A source that delivers its data to a callback (a location
	// fix, an HTTP response) hands it to the closures it is given.
	var sourced []*fact
	keyedRead := a.keyedRead(fn, st.defs, in, recvOff)
	for _, hit := range match(fn.Lang, rules.KindSource, c) {
		if hit.Rule.DataType == requestData && keyedRead {
			// r.FormValue("page"): the key says what the value is.
			continue
		}
		f := &fact{dt: hit.Rule.DataType, param: -1, src: in.Pos, desc: "call " + label, path: []ir.Pos{in.Pos}, conf: sourceConf(hit)}
		if into := hit.Rule.Arg.Indexes; len(into) > 0 {
			// c.ShouldBindJSON(&v): the call fills its argument.
			for _, i := range into {
				if j := recvOff + i; i >= 0 && j < len(in.Args) {
					changed = st.mutate(in.Args[j], "", st.mutation(f)) || changed
				}
			}
			continue
		}
		changed = st.add(in.Dst, f) || changed
		sourced = append(sourced, f)
	}

	// Transforms (sanitizers): the result carries the input's data types
	// with the transform recorded; no default propagation.
	if hits := match(fn.Lang, rules.KindTransform, c); len(hits) > 0 {
		x := hits[0].Rule.Transform
		for i := range in.Args {
			for _, f := range factsOf(i) {
				changed = st.add(in.Dst, derive(f, in.Pos, 1, x)) || changed
			}
		}
		return changed
	}

	nameXf := a.opts.Names.FuncTransform(c.Name)

	// Closures. A call runs the closures held in the variable it calls,
	// in the receiver of an unresolved method or in the field the method
	// is named after (closureFlow.invoked), with its arguments. A closure
	// passed as an argument may be called back by the callee with
	// anything else the call is given.
	invoked := false
	for _, cl := range run {
		if cl.param {
			continue
		}
		// Arguments beyond the closure's last parameter reach that
		// parameter (varargs, an implicit it standing for several).
		last := len(in.Args) - first - 1
		if cf := a.funcs[cl.fn]; cf != nil {
			last = len(cf.Params) - cf.Captures - 1
		}
		ok, ch := a.invoke(st, fn, in, cl, in.Args[first:], func(i int) []*fact {
			var out []*fact
			for j := first + i; j < len(in.Args) && (j == first+i || i == last); j++ {
				out = append(out, factsOf(j)...)
			}
			return out
		}, sum)
		invoked, changed = invoked || ok, changed || ch
	}
	for i, arg := range in.Args {
		if len(run) > 0 && i < first {
			continue
		}
		cls := st.closures[arg]
		if len(cls) == 0 {
			continue
		}
		// A callee known to run the closure before it returns (forEach,
		// map, apply, sort.Slice) runs it here: its captures are read as
		// they are at the call. Any other callee may keep the closure and
		// run it at any later time (a listener, a stored handler), so its
		// captures are read with every mutation, wherever it happens. The
		// closure's parameters correspond to the call's other arguments
		// (the receiver of apply or forEach first).
		now := runsCallbackNow(c)
		inputs := append([]*fact(nil), sourced...)
		var others []ir.VarID
		for j := range in.Args {
			if j != i && !(c.Indirect && j == 0) {
				inputs = append(inputs, factsOf(j)...)
				others = append(others, in.Args[j])
			}
		}
		outs := others
		if !now {
			// A kept callback (a handler, a middleware) is later given
			// arguments of the caller's choosing: what it writes into
			// its parameters does not go into this call's arguments.
			outs = nil
		}
		for _, cl := range cls {
			captured := st.all
			if now {
				captured = st.of
			}
			_, ch := a.runClosure(st, fn, in, cl, outs, func(int) []*fact { return inputs }, captured, sum)
			changed = changed || ch
		}
	}
	if invoked {
		return changed
	}

	// Calls into analyzed code: apply the callee summaries. A dynamically
	// dispatched call may run its target or any override or
	// implementation of it; a construction runs the constructor on the
	// new object.
	if isNew && c.Target != "" {
		if s := a.summaryFor(c.Target); s != nil {
			// The constructor's first parameter is the new object.
			base := append([]ir.VarID{in.Dst}, in.Args...)
			var names []string
			if c.ArgNames != nil {
				names = append([]string{""}, c.ArgNames...)
			}
			args, idx := a.arrange(c.Target, base, names)
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
	if !isNew && !c.Indirect {
		for _, t := range a.cha.targets(c, fn.Lang) {
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
	}
	if applied {
		return changed
	}

	// Unknown code: conservative propagation. A getter on a value whose
	// type the schema knows (profile.getBio()) is answered from the schema
	// instead of smearing every field of the object onto the result.
	nonRecv := len(in.Args) - recvOff
	skipRecv := c.HasRecv && recvOff == 1 && nonRecv == 0 && publicParts[strings.ToLower(c.Name)]
	if c.HasRecv && recvOff == 1 && nonRecv == 0 && in.Args[0] >= 0 {
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
	// A keyed put (ctx.Set("user", u), map.put("email", e)) stores the
	// value under its key: reading another key, or another part of the
	// object, does not give it.
	putKey := ""
	if c.HasRecv && recvOff == 1 && !isNew && nonRecv == 2 && isMutator(c.Name) {
		if k, ok := constOf(fn, st.defs, in.Args[1]); ok && k != "" && !strings.ContainsAny(k, " \t\n") {
			putKey = k
		}
	}
	// A request through an HTTP client the rules do not know
	// (HTTPClient.send_request, session.post) answers with the remote's
	// response, like a network sink's; a length, count or type check
	// is a number or a flag.
	lname := strings.ToLower(c.Name)
	remote = remote || (c.HasRecv || c.RecvText != "") && requestMethods[lname]
	if dataFreeCalls[lname] {
		return changed
	}
	// A data loader (AppByTokenLoader(ctx).load(token), GraphQL's
	// DataLoader pattern) answers with the value stored under the key it
	// is given, not with the key.
	lookup := recvOff == 1 && loaderMethods[lname] && strings.Contains(strings.ToLower(c.RecvText+"|"+c.RecvType+"|"+c.Callee), "loader")
	if dst, ok := decodeInto[c.Callee]; ok && dst < len(in.Args) {
		// A decoder fills the value it is given with what it reads:
		// json.NewDecoder(r.Body).Decode(&v), json.Unmarshal(b, &v).
		for i := range in.Args {
			if i == dst {
				continue
			}
			for _, f := range factsOf(i) {
				changed = st.mutate(in.Args[dst], "", st.mutation(derive(f, in.Pos, 0.95))) || changed
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
			if i == 0 && recvOff == 1 && f.stored != "" && !readsPart(fn, st.defs, in, f.stored) {
				continue
			}
			if i == 0 && recvOff == 1 && f.dt == requestData && keyedRead {
				// request.form.get("page"): the key says what it is.
				continue
			}
			if lookup && i >= recvOff {
				continue
			}
			changed = st.add(in.Dst, derive(f, in.Pos, 0.95, nameXf)) || changed
			if putKey != "" && i == 2 {
				changed = st.mutate(in.Args[0], putKey, st.mutation(derive(f, in.Pos, 0.9))) || changed
				continue
			}
			if putKey != "" && i == 1 {
				continue
			}
			if i >= recvOff && c.HasRecv && recvOff == 1 && !isNew && isMutator(c.Name) {
				// The receiver, and the object it came from when it is a
				// builder call's result (sb.append(a).append(email)).
				r := in.Args[0]
				for depth := 0; r >= 0 && depth < 8; depth++ {
					if handleType(fn.Vars[r].Type) {
						// A connection or client is not changed by the data
						// a query or request is given: db.Where(q, email)
						// does not put the email into db.
						break
					}
					changed = st.mutate(r, "", st.mutation(derive(f, in.Pos, 0.9))) || changed
					next, ok := st.fluent[r]
					if !ok {
						break
					}
					r = next
				}
			}
		}
	}
	if r, ok := st.fluent[in.Dst]; ok && r == in.Args[0] && !remote {
		// A builder or scope function returns its receiver: the result
		// is the same object, with the mutations made to it here and
		// later (User().apply { email = x }).
		changed = a.alias(st, in, in.Dst, r) || changed
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
		if key, ok := constOf(fn, st.defs, in.Args[recvOff]); ok {
			// A value passed after the key (slog.String("address", v))
			// may say it is something else.
			if m, ok := a.opts.Names.Key(key); ok && (recvOff+1 >= len(in.Args) || !a.keyContradicted(fn, st.defs, in.Args[recvOff+1], m.DataType)) {
				changed = st.add(in.Dst, &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("%s(%q)", c.Name, key), path: []ir.Pos{in.Pos}, conf: m.Conf}) || changed
			}
		}
	}
	return changed
}

// invoke applies the summary of closure cl at a call that runs it. The
// closure's parameters are its inputs, then its captures: inputAt(i) is
// what input i receives (argVars[i] the variable passed, when known), and
// each capture receives the variable the closure bound. It reports
// whether the closure's summary was known.
func (a *analyzer) invoke(st *state, fn *ir.Func, in *ir.Instr, cl closure, argVars []ir.VarID, inputAt func(int) []*fact, sum *Summary) (bool, bool) {
	return a.runClosure(st, fn, in, cl, argVars, inputAt, st.of, sum)
}

func (a *analyzer) runClosure(st *state, fn *ir.Func, in *ir.Instr, cl closure, argVars []ir.VarID, inputAt func(int) []*fact, captured func(ir.VarID) []*fact, sum *Summary) (bool, bool) {
	cf := a.funcs[cl.fn]
	s := a.summaryFor(cl.fn)
	if cf == nil || s == nil {
		return false, false
	}
	nIn := len(cf.Params) - cf.Captures
	args := make([]ir.VarID, len(cf.Params))
	for i := range args {
		args[i] = ir.NoVar
		switch {
		case i < nIn && i < len(argVars):
			args[i] = argVars[i]
		case i >= nIn && i-nIn < len(cl.binds) && cl.in == fn.ID:
			// Captures are bound where the closure was created; run
			// anywhere else, it reads them as unknown.
			args[i] = cl.binds[i-nIn]
		}
	}
	factsAt := func(i int) []*fact {
		if i < nIn {
			return inputAt(i)
		}
		return captured(args[i])
	}
	return true, a.apply(st, fn, in, s, args, factsAt, "", in.Dst, sum)
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
			// Values with no variable (what a callback is given): the
			// field of each.
			var out []*fact
			for _, f := range factsAt(i) {
				if f.stored != "" && f.stored != field && !strings.HasPrefix(field, f.stored+".") {
					continue
				}
				d := derive(f, in.Pos, 1)
				if f.dt == "" {
					for _, part := range strings.Split(field, ".") {
						d.field = joinField(d.field, part)
					}
				}
				out = append(out, d)
			}
			return out
		}
		return a.fieldFacts(st, fn, args[i], "", field, in.Pos)
	}
	put := func(target ir.VarID, field string, f *fact) {
		if target < 0 {
			return
		}
		changed = st.mutate(target, field, st.mutation(f)) || changed
	}
	for i := range args {
		for _, t := range s.ParamReturn[i] {
			for _, f := range of(i, t.Field) {
				d := derive(f, in.Pos, t.Conf, append(append([]string{}, t.Xf...), nameXf)...)
				d.path = appendPath(d.path, t.Path...)
				if t.DstField != "" && dst >= 0 {
					changed = st.addStore(dst, t.DstField, d) || changed
					// On the object too, as held by that field only.
					g := *d
					g.stored = t.DstField
					d = &g
				}
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
					h2.Guards = mergeXf(h.Guards, st.guardsAt(fn)...)
					sum.addParamSink(f.param, h2)
					continue
				}
				h2 := h
				h2.Guards = mergeXf(h.Guards, st.guardsAt(fn)...)
				a.emit(f, h2, []ir.Pos{in.Pos})
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
		if rf.DstField != "" && dst >= 0 {
			changed = st.addStore(dst, rf.DstField, f) || changed
			g := *f
			g.stored = rf.DstField
			f = &g
		}
		changed = st.add(dst, f) || changed
	}
	// What the callee throws: a handler of the call's block catches it,
	// or it leaves this function (see analyzeFunc).
	for i := range args {
		for _, t := range s.ParamThrow[i] {
			for _, f := range of(i, t.Field) {
				d := derive(f, in.Pos, t.Conf, t.Xf...)
				d.path = appendPath(d.path, t.Path...)
				changed = st.addThrown(st.cur, d) || changed
			}
		}
	}
	for _, rf := range s.ThrowFacts {
		changed = st.addThrown(st.cur, realToFact(rf, in.Pos)) || changed
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
		Guards: h.Guards,
	}
	k := strings.Join([]string{f.dt, h.Rule, h.Func, h.Sink.String(), xfKey(xf)}, "|")
	if old, ok := a.flows[k]; ok && compareFlows(fl, old) >= 0 {
		// An unguarded path to the sink outweighs a guarded one; among
		// equally guarded ones the more confident wins, then the one
		// compareFlows puts first, whatever order they were found in.
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

// requestMethods send a request through an HTTP client and return its
// response.
var requestMethods = map[string]bool{
	"send_request": true, "sendrequest": true, "request": true, "urlopen": true, "fetch": true,
	"post": true, "patch": true, "post_json": true, "postjson": true,
}

// loaderMethods look a value up by key on a data loader.
var loaderMethods = map[string]bool{"load": true, "load_many": true, "loadmany": true}

// dataFreeCalls return a size, a count, a flag or a type, not the data
// they are given.
var dataFreeCalls = map[string]bool{
	"len": true, "count": true, "size": true, "length": true, "isempty": true, "isnotempty": true,
	"isinstance": true, "issubclass": true, "hasattr": true, "callable": true, "type": true, "typeof": true,
	"bool": true, "exists": true, "contains": true, "containskey": true, "startswith": true, "endswith": true,
	"hasprefix": true, "hassuffix": true, "isvalid": true, "is_valid": true, "equals": true, "equal": true,
}

// errorValue reports whether v is an exception or error constructed in fn
// ({"email": ValidationError("Email is required")}): its name says what
// the error is about, not what it holds.
func errorValue(fn *ir.Func, defs []int, v ir.VarID) bool {
	for depth := 0; depth < 4; depth++ {
		if v < 0 || int(v) >= len(defs) || defs[v] < 0 {
			return false
		}
		in := &fn.Instrs[defs[v]]
		switch {
		case in.Op == ir.OpAssign && len(in.Args) == 1:
			v = in.Args[0]
			continue
		case (in.Op == ir.OpNew || in.Op == ir.OpCall) && in.Call != nil:
			n := in.Call.Name
			return strings.HasSuffix(n, "Error") || strings.HasSuffix(n, "Exception")
		}
		return false
	}
	return false
}

// selfDescribing are calls and fields whose value is a network location,
// by name with any get prefix, lower-cased: in
// Str("address", l.Addr().String()) the value is the listen address, not
// the postal address the key names.
var selfDescribing = map[string]bool{
	"addr": true, "localaddr": true, "remoteaddr": true, "listenaddr": true, "serveraddr": true, "bindaddr": true,
	"localaddress": true, "remoteaddress": true, "listenaddress": true, "serveraddress": true, "bindaddress": true,
	"socketaddress": true, "inetaddress": true, "host": true, "hostname": true, "hostport": true, "hoststring": true,
	"url": true, "uri": true, "requesturi": true, "requesturl": true, "baseurl": true, "port": true, "endpoint": true,
}

// stringers render the value they are called on: l.Addr().String() is
// what l.Addr() is.
var stringers = map[string]bool{"String": true, "toString": true, "description": true, "__str__": true}

// placeholders are literals that stand in for a value, not hold one.
var placeholders = map[string]bool{"true": true, "false": true, "yes": true, "no": true, "none": true, "null": true, "nil": true, "unknown": true, "n/a": true, "na": true, "-": true, "redacted": true, "hidden": true}

// notData reports whether a literal cannot be the data its key names:
// empty, a number, a boolean or a placeholder. A hard-coded
// putString("password", "hunter2") is the secret itself.
func notData(lit string) bool {
	t := strings.ToLower(strings.TrimSpace(lit))
	if t == "" || placeholders[t] {
		return true
	}
	_, err := strconv.ParseFloat(t, 64)
	return err == nil
}

// keyContradicted reports whether the value v says it is not the data
// type dt its key names: a literal that is not data, a call or field that names a network
// location (Addr(), RemoteAddr, Host, URL, Port), or a variable on the
// way whose own name is another data type (Str("email", phone)). The key
// labels only values that do not say what they are.
func (a *analyzer) keyContradicted(fn *ir.Func, defs []int, v ir.VarID, dt string) bool {
	for depth := 0; depth < 6 && v >= 0 && int(v) < len(fn.Vars); depth++ {
		vr := &fn.Vars[v]
		if vr.Const != nil {
			return notData(*vr.Const)
		}
		if vr.Name != "" {
			if m, ok := a.opts.Names.Key(vr.Name); ok && m.DataType != dt {
				return true
			}
		}
		if int(v) >= len(defs) || defs[v] < 0 {
			return false
		}
		in := &fn.Instrs[defs[v]]
		switch {
		case in.Op == ir.OpAssign && len(in.Args) == 1:
			v = in.Args[0]
		case in.Op == ir.OpLoad && in.Field != "":
			return selfDescribing[strings.ToLower(in.Field)]
		case in.Op == ir.OpCall && in.Call != nil:
			if stringers[in.Call.Name] && in.Call.HasRecv && len(in.Args) == 1 {
				v = in.Args[0]
				continue
			}
			n := strings.ToLower(in.Call.Name)
			return selfDescribing[n] || strings.HasPrefix(n, "get") && selfDescribing[n[3:]]
		default:
			return false
		}
	}
	return false
}

// handleTypes are library types of connections, clients, loggers and
// routers: shared handles that calls pass data through, not hold.
var handleTypes = map[string]bool{
	"gorm.io/gorm.DB": true, "database/sql.DB": true, "database/sql.Tx": true, "database/sql.Conn": true,
	"database/sql.Stmt": true, "github.com/jmoiron/sqlx.DB": true, "github.com/jmoiron/sqlx.Tx": true,
	"github.com/jackc/pgx/v5/pgxpool.Pool": true, "github.com/jackc/pgx/v5.Conn": true, "github.com/jackc/pgx/v4/pgxpool.Pool": true,
	"go.mongodb.org/mongo-driver/mongo.Client": true, "go.mongodb.org/mongo-driver/mongo.Database": true,
	"go.mongodb.org/mongo-driver/mongo.Collection": true, "github.com/redis/go-redis/v9.Client": true,
	"github.com/go-redis/redis/v8.Client": true, "net/http.Client": true, "net/http.ServeMux": true,
	"github.com/gin-gonic/gin.Engine": true, "github.com/gin-gonic/gin.RouterGroup": true,
	"github.com/labstack/echo/v4.Echo": true, "github.com/labstack/echo/v4.Group": true, "github.com/gorilla/mux.Router": true,
	"github.com/go-chi/chi/v5.Mux": true, "github.com/rs/zerolog.Logger": true, "go.uber.org/zap.Logger": true,
	"go.uber.org/zap.SugaredLogger": true, "log/slog.Logger": true, "github.com/sirupsen/logrus.Logger": true,
	"google.golang.org/grpc.ClientConn": true,
}

func handleType(t string) bool {
	return t != "" && handleTypes[strings.TrimLeft(t, "*&")]
}

// copiedType is the declared type of v, or of the value it is a copy of
// (found = find_profile(p) has the type find_profile returns).
func copiedType(fn *ir.Func, defs []int, v ir.VarID) string {
	for depth := 0; depth < 4 && v >= 0 && int(v) < len(fn.Vars); depth++ {
		if t := fn.Vars[v].Type; t != "" {
			return t
		}
		if int(v) >= len(defs) || defs[v] < 0 {
			return ""
		}
		in := &fn.Instrs[defs[v]]
		if in.Op != ir.OpAssign || len(in.Args) != 1 {
			return ""
		}
		v = in.Args[0]
	}
	return ""
}

// sinkCall reports whether instruction i of fn is a call matching sink
// rule id.
func (a *analyzer) sinkCall(fn *ir.Func, i int, id string) bool {
	if i < 0 || i >= len(fn.Instrs) || fn.Instrs[i].Op != ir.OpCall || fn.Instrs[i].Call == nil {
		return false
	}
	for _, h := range a.opts.Rules.Match(fn.Lang, rules.KindSink, fn.Instrs[i].Call) {
		if h.Rule.ID == id {
			return true
		}
	}
	return false
}

// chainedSink reports whether v is the result of a call matching sink rule
// id, directly or through copies.
func (a *analyzer) chainedSink(fn *ir.Func, defs []int, v ir.VarID, id string) bool {
	for depth := 0; depth < 4 && v >= 0 && int(v) < len(defs); depth++ {
		d := defs[v]
		if d < 0 {
			return false
		}
		in := &fn.Instrs[d]
		switch {
		case in.Op == ir.OpAssign && len(in.Args) == 1:
			v = in.Args[0]
			continue
		case in.Op == ir.OpCall:
			return a.sinkCall(fn, d, id)
		}
		return false
	}
	return false
}

// wholeValueMethods render or copy a whole object: what any of its fields
// holds is in the result.
var wholeValueMethods = map[string]bool{
	"tostring": true, "string": true, "description": true, "json": true, "tojson": true, "dump": true, "dumps": true,
	"serialize": true, "encode": true, "marshal": true, "copy": true, "clone": true, "build": true, "get": true,
	"values": true, "entries": true, "items": true, "iterator": true, "asdict": true, "dict": true, "todict": true,
	"tomap": true, "model_dump": true, "stringify": true, "format": true, "unwrap": true, "orelse": true, "await": true,
}

// readsPart reports whether an unresolved method call on an object may
// return what the object's part (field or key) holds: a read with that
// constant key (ctx.Get("user")), a read with a key not known here, a
// method named after the part (getEmail() for email), or one rendering
// the whole object (toString()). ctx.ClientIP() does not return the user
// put under "user".
func readsPart(fn *ir.Func, defs []int, in *ir.Instr, part string) bool {
	name := strings.ToLower(in.Call.Name)
	if !isGetterName(name) && isMutator(name) {
		return true // a builder call returns its receiver
	}
	if len(in.Args) > 1 {
		k, ok := constOf(fn, defs, in.Args[1])
		return !ok || k == part || normName(k) == normName(part)
	}
	if wholeValueMethods[name] {
		return true
	}
	p := normName(part)
	return p != "" && strings.Contains(normName(name), p)
}

// normName lowercases a name and drops its separators: first_name and
// firstName are the same.
func normName(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
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
