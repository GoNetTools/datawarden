// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package analysis runs an inter-procedural taint analysis over IR.
//
// Each function is analyzed flow-insensitively to a fixpoint. Parameters
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
	"net/url"
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
	src   ir.Pos
	desc  string
	path  []ir.Pos
	xf    []string
	conf  float64
	seed  bool // seeded on this very variable (by its own name/type)
}

func (f *fact) key() string {
	if f.dt != "" {
		return f.dt + "|" + xfKey(f.xf)
	}
	return fmt.Sprintf("#%d|%s", f.param, xfKey(f.xf))
}

type state struct {
	facts  []map[string]*fact
	stores map[ir.VarID]map[string]map[string]*fact
	minC   float64
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
	return &fact{dt: f.dt, param: f.param, src: f.src, desc: f.desc, path: appendPath(f.path, pos), xf: mergeXf(f.xf, xf...), conf: f.conf * decay}
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
			if in.Op == ir.OpCall && in.Call != nil && in.Call.Target != "" && !seen[in.Call.Target] {
				seen[in.Call.Target] = true
				cg[f.ID] = append(cg[f.ID], in.Call.Target)
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
		if v.Name != "" && !isBoolOrFunc(v.Type) {
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

func shortType(t string) string {
	t = strings.TrimLeft(t, "*&[]")
	if i := strings.LastIndexAny(t, "/"); i >= 0 {
		t = t[i+1:]
	}
	return t
}

func (a *analyzer) analyzeFunc(fn *ir.Func) *Summary {
	st := &state{facts: make([]map[string]*fact, len(fn.Vars)), stores: map[ir.VarID]map[string]map[string]*fact{}, minC: a.opts.MinConf}
	a.seed(st, fn)
	sum := &Summary{}
	for iter := 0; iter < 40; iter++ {
		changed := false
		for i := range fn.Instrs {
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
		for _, arg := range in.Args {
			for _, f := range st.of(arg) {
				if f.dt == "" {
					sum.addParamReturn(f.param, Transfer{Xf: f.xf, Conf: f.conf, Path: appendPath(f.path, in.Pos)})
				} else {
					sum.addReturnFact(RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf})
				}
			}
		}
	}
	for i, pid := range fn.Params {
		for _, f := range st.of(pid) {
			switch {
			case f.dt == "" && f.param != i:
				sum.addParamParam(i, f.param, Transfer{Xf: f.xf, Conf: f.conf, Path: f.path})
			case f.dt != "" && !f.seed:
				sum.addParamOut(i, RealFact{DataType: f.dt, Desc: f.desc, Src: f.src, Path: f.path, Xf: f.xf, Conf: f.conf})
			}
		}
	}
	return sum
}

func (a *analyzer) step(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) bool {
	changed := false
	switch in.Op {
	case ir.OpAssign:
		for _, arg := range in.Args {
			for _, f := range st.of(arg) {
				changed = st.add(in.Dst, derive(f, in.Pos, 1)) || changed
			}
		}
	case ir.OpLoad:
		if len(in.Args) == 0 {
			return false
		}
		obj := in.Args[0]
		owner := in.Owner
		if owner == "" && obj >= 0 {
			owner = fn.Vars[obj].Type
		}
		ctxName := owner
		if ctxName == "" && obj >= 0 {
			ctxName = fn.Vars[obj].Name
		}
		h, fs := a.opts.Schema.Field(owner, in.Field)
		switch fs {
		case detect.FieldPII:
			f := &fact{dt: h.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("field %s (%s)", fieldLabel(owner, in.Field), h.Via), path: []ir.Pos{in.Pos}, conf: h.Conf}
			if h.Transform != "" {
				f.xf = []string{h.Transform}
			}
			changed = st.add(in.Dst, f) || changed
		case detect.FieldUnknown:
			if m, ok := a.opts.Names.Field(ctxName, in.Field); ok {
				f := &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("field %s", fieldLabel(owner, in.Field)), path: []ir.Pos{in.Pos}, conf: m.Conf}
				if m.Transform != "" {
					f.xf = []string{m.Transform}
				}
				changed = st.add(in.Dst, f) || changed
			}
		}
		if fm := st.stores[obj]; fm != nil {
			for _, f := range fm[in.Field] {
				changed = st.add(in.Dst, derive(f, in.Pos, 1)) || changed
			}
		}
		if fs != detect.FieldNotPII && !a.opts.Schema.KnownType(owner) {
			for _, f := range st.of(obj) {
				changed = st.add(in.Dst, derive(f, in.Pos, 0.8)) || changed
			}
		}
	case ir.OpStore:
		if len(in.Args) < 2 {
			return false
		}
		obj, val := in.Args[0], in.Args[1]
		for _, f := range st.of(val) {
			d := derive(f, in.Pos, 1)
			changed = st.addStore(obj, in.Field, d) || changed
			changed = st.add(obj, d) || changed
		}
		// A store without a declared owner type is a map or object literal
		// ({"email": v}): the key names the value, whatever other types say
		// about fields of the same name. For typed owners the schema decides.
		untyped := in.Owner == ""
		if _, fs := a.opts.Schema.Field(in.Owner, in.Field); untyped || (fs == detect.FieldUnknown && !a.opts.Schema.KnownType(in.Owner)) {
			if m, ok := a.opts.Names.Key(in.Field); ok {
				changed = st.add(obj, &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("key %q", in.Field), path: []ir.Pos{in.Pos}, conf: m.Conf}) || changed
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
						Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf * hit.Conf})
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

	// Calls into analyzed code: apply the callee summary.
	if c.Target != "" {
		if s := a.summaryFor(c.Target); s != nil {
			for i := range in.Args {
				fs := factsOf(i)
				if len(fs) == 0 {
					continue
				}
				for _, t := range s.ParamReturn[i] {
					for _, f := range fs {
						d := derive(f, in.Pos, t.Conf, append(append([]string{}, t.Xf...), nameXf)...)
						d.path = appendPath(d.path, t.Path...)
						changed = st.add(in.Dst, d) || changed
					}
				}
				for _, h := range s.ParamSink[i] {
					for _, f := range fs {
						if f.dt == "" {
							h2 := h
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
			for dst, m := range s.ParamParam {
				if dst >= len(in.Args) {
					continue
				}
				for src, ts := range m {
					if src >= len(in.Args) {
						continue
					}
					for _, t := range ts {
						for _, f := range factsOf(src) {
							changed = st.add(in.Args[dst], derive(f, in.Pos, t.Conf, t.Xf...)) || changed
						}
					}
				}
			}
			for dst, rfs := range s.ParamOut {
				if dst >= len(in.Args) {
					continue
				}
				for _, rf := range rfs {
					changed = st.add(in.Args[dst], realToFact(rf, in.Pos)) || changed
				}
			}
			for _, rf := range s.ReturnFacts {
				f := realToFact(rf, in.Pos)
				f.xf = mergeXf(f.xf, nameXf)
				changed = st.add(in.Dst, f) || changed
			}
			return changed
		}
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
				changed = st.add(in.Args[0], derive(f, in.Pos, 0.9)) || changed
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
