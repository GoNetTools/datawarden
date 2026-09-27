// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package explain says why datawarden reported a flow: why its source is
// that data type, what happened at each step of its path, why the sink
// rule matched, how the policy decided and what would silence it. It
// reads the lowered IR of the files on the path again, so a finding can be
// explained without the analysis keeping any extra state.
package explain

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/policy"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// Rules finds the rules matching a call, a field read or a parameter
// (implemented by *rules.Set).
type Rules interface {
	Match(lang, kind string, c *ir.Call) []rules.Hit
	MatchField(lang, owner, field, recv string) []rules.Hit
	MatchParam(lang string, annotations []string) []rules.Hit
	ByID(id string) *rules.Rule
}

// Names recognises personal-data names (implemented by
// *detect.Classifier).
type Names interface {
	Ident(name string) (detect.Match, bool)
	Field(owner, field string) (detect.Match, bool)
	Key(s string) (detect.Match, bool)
	Getter(name string) (detect.Match, bool)
	FuncTransform(name string) string
}

// Statuses of an explained flow, as the scan report prints them.
const (
	StatusNew      = "NEW"
	StatusBaseline = "BASELINE"
	StatusAllowed  = "ALLOWED"
	StatusInfo     = "INFO"
	StatusDropped  = "DROPPED"
)

// Input is one flow to explain and what is needed to explain it.
type Input struct {
	Flow     *finding.Flow
	Decision policy.Decision
	// Funcs are the lowered functions of the files on the flow's path.
	Funcs []*ir.Func
	Rules Rules
	// Lines returns the lines of a source file, or nil.
	Lines func(file string) []string
}

// Explanation is a flow explained end to end.
type Explanation struct {
	Status      string          `json:"status"`
	DataType    string          `json:"data_type"`
	Class       string          `json:"class,omitempty"`
	Severity    string          `json:"severity,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Confidence  float64         `json:"confidence"`
	Source      Source          `json:"source"`
	Steps       []Step          `json:"steps"`
	Sink        Sink            `json:"sink"`
	Policy      policy.Decision `json:"policy"`
	// Silence lists what would silence the finding, narrowest first. It is
	// empty unless the flow is a new violation.
	Silence []Option `json:"silence,omitempty"`
}

// Source says why the source is personal data of the flow's type.
type Source struct {
	Pos  ir.Pos `json:"pos"`
	Code string `json:"code,omitempty"`
	// Desc is the source as the scan report describes it.
	Desc string `json:"desc"`
	// Why lists the matches that make it that data type.
	Why []string `json:"why,omitempty"`
}

// Step is one position on the path and what happened there.
type Step struct {
	Pos  ir.Pos `json:"pos"`
	Func string `json:"func,omitempty"`
	Code string `json:"code,omitempty"`
	What string `json:"what"`
	// IR is the instruction at the position, as `datawarden ir` prints it.
	IR string `json:"ir,omitempty"`
}

// Sink says why the sink rule matched.
type Sink struct {
	Pos         ir.Pos `json:"pos"`
	Code        string `json:"code,omitempty"`
	Call        string `json:"call"`
	Func        string `json:"func"`
	Rule        string `json:"rule"`
	Description string `json:"description,omitempty"`
	Why         string `json:"why,omitempty"`
	Dest        string `json:"dest"`
}

// Option is one way to silence a finding.
type Option struct {
	When string `json:"when"`
	Do   string `json:"do"`
}

// Explainer explains flows.
type Explainer struct {
	Names Names
}

// Explain explains one flow.
func (x Explainer) Explain(in Input) *Explanation {
	f := in.Flow
	idx := newIndex(in.Funcs)
	code := func(p ir.Pos) string {
		if in.Lines == nil || p.Line <= 0 {
			return ""
		}
		lines := in.Lines(p.File)
		if p.Line > len(lines) {
			return ""
		}
		return strings.TrimSpace(lines[p.Line-1])
	}
	e := &Explanation{
		Status: status(f, in.Decision), DataType: f.DataType, Class: f.Class, Severity: f.Severity,
		Fingerprint: f.Fingerprint, Confidence: f.Confidence, Policy: in.Decision,
	}
	e.Source = Source{Pos: f.Source, Code: code(f.Source), Desc: f.SourceDesc, Why: x.sourceWhy(in, idx)}
	e.Steps = x.steps(in, idx, code)
	e.Sink = x.sink(in, idx, code)
	if e.Status == StatusNew {
		e.Silence = silence(f)
	}
	return e
}

func status(f *finding.Flow, d policy.Decision) string {
	switch d.Status {
	case policy.StatusViolation:
		if f.Baselined {
			return StatusBaseline
		}
		return StatusNew
	case policy.StatusAllowed:
		return StatusAllowed
	case policy.StatusDropped:
		return StatusDropped
	}
	return StatusInfo
}

// index finds the instructions and variables at a position.
type index struct {
	instrs map[ir.Pos][]ref
	vars   map[ir.Pos][]ref
	lines  map[string][]ref // "file:line" -> instructions
	funcs  map[string]*ir.Func
}

type ref struct {
	fn *ir.Func
	i  int // instruction or variable index
}

func newIndex(funcs []*ir.Func) *index {
	idx := &index{instrs: map[ir.Pos][]ref{}, vars: map[ir.Pos][]ref{}, lines: map[string][]ref{}, funcs: map[string]*ir.Func{}}
	for _, fn := range funcs {
		idx.funcs[fn.ID] = fn
		for i := range fn.Instrs {
			p := fn.Instrs[i].Pos
			idx.instrs[p] = append(idx.instrs[p], ref{fn, i})
			k := fmt.Sprintf("%s:%d", p.File, p.Line)
			idx.lines[k] = append(idx.lines[k], ref{fn, i})
		}
		for i := range fn.Vars {
			if !fn.Vars[i].IsConst() && fn.Vars[i].Name != "" {
				idx.vars[fn.Vars[i].Pos] = append(idx.vars[fn.Vars[i].Pos], ref{fn, i})
			}
		}
	}
	return idx
}

// at returns the instructions at p, or on its line when none is exactly
// at it.
func (idx *index) at(p ir.Pos) []ref {
	if rs := idx.instrs[p]; len(rs) > 0 {
		return rs
	}
	return idx.lines[fmt.Sprintf("%s:%d", p.File, p.Line)]
}

// best picks the instruction that says most about a step: a call, then a
// store, a return, a read, a computation, a copy.
func best(rs []ref) (ref, bool) {
	rank := map[ir.Op]int{ir.OpCall: 9, ir.OpNew: 8, ir.OpStore: 7, ir.OpReturn: 6, ir.OpThrow: 6, ir.OpLoad: 5, ir.OpCompute: 4,
		ir.OpClosure: 3, ir.OpCatch: 3, ir.OpYield: 3, ir.OpAssign: 2, ir.OpPhi: 1}
	var out ref
	top := 0
	for _, r := range rs {
		if n := rank[r.fn.Instrs[r.i].Op]; n > top {
			out, top = r, n
		}
	}
	return out, top > 0
}

func (x Explainer) sourceWhy(in Input, idx *index) []string {
	f := in.Flow
	var why []string
	add := func(format string, args ...any) { why = append(why, fmt.Sprintf(format, args...)) }
	for _, r := range idx.vars[f.Source] {
		v := r.fn.Vars[r.i]
		if len(v.Annotations) > 0 && in.Rules != nil {
			for _, h := range in.Rules.MatchParam(r.fn.Lang, v.Annotations) {
				if h.Rule.DataType == f.DataType {
					add("parameter `%s` is annotated %s: source rule `%s`%s", v.Name, h.How, h.Rule.ID, ruleConf(h.Rule))
				}
			}
		}
		if x.Names != nil {
			if m, ok := x.Names.Ident(v.Name); ok && m.DataType == f.DataType {
				add("the name `%s` matches %s", v.Name, pattern(m))
			}
		}
	}
	for _, r := range idx.at(f.Source) {
		in2 := &r.fn.Instrs[r.i]
		switch in2.Op {
		case ir.OpCall, ir.OpNew:
			c := in2.Call
			if c == nil {
				continue
			}
			if in.Rules != nil {
				for _, h := range in.Rules.Match(r.fn.Lang, rules.KindSource, c) {
					if h.Rule.DataType == f.DataType {
						add("the call `%s` matches source rule `%s` (%s)%s", label(c), h.Rule.ID, how(h), ruleConf(h.Rule))
					}
				}
			}
			if x.Names == nil {
				continue
			}
			for _, a := range in2.Args {
				if k, ok := constArg(r.fn, a); ok {
					if m, ok := x.Names.Key(k); ok && m.DataType == f.DataType {
						add("the key %q next to the value matches %s", k, pattern(m))
					}
				}
			}
			if m, ok := x.Names.Getter(c.Name); ok && m.DataType == f.DataType {
				add("the getter `%s()` matches %s", c.Name, pattern(m))
			}
		case ir.OpLoad:
			obj := ""
			if len(in2.Args) > 0 && in2.Args[0] >= 0 && int(in2.Args[0]) < len(r.fn.Vars) {
				obj = r.fn.Vars[in2.Args[0]].Name
			}
			if in.Rules != nil {
				for _, h := range in.Rules.MatchField(r.fn.Lang, in2.Owner, in2.Field, obj) {
					if h.Rule.DataType == f.DataType {
						add("reading `%s` (%s) matches source rule `%s`%s", in2.Field, h.How, h.Rule.ID, ruleConf(h.Rule))
					}
				}
			}
			if x.Names != nil {
				if m, ok := x.Names.Field(in2.Owner, in2.Field); ok && m.DataType == f.DataType {
					add("the field name `%s` matches %s", in2.Field, pattern(m))
				}
			}
		}
	}
	// The description names the identifier or key that matched.
	if x.Names != nil {
		for _, pre := range []string{"identifier ", "key "} {
			if q, ok := strings.CutPrefix(f.SourceDesc, pre); ok {
				name, err := strconv.Unquote(q)
				if err != nil {
					continue
				}
				if pre == "key " {
					if m, ok := x.Names.Key(name); ok && m.DataType == f.DataType {
						add("the key %q next to the value matches %s", name, pattern(m))
					}
				} else if m, ok := x.Names.Ident(name); ok && m.DataType == f.DataType {
					add("the name `%s` matches %s", name, pattern(m))
				}
			}
		}
	}
	// A schema hint (a struct tag, a column, an annotation) is named in
	// parentheses in the report's description: field Customer.NationalID
	// (json:"national_id").
	if i := strings.LastIndexByte(f.SourceDesc, '('); i >= 0 && strings.HasSuffix(f.SourceDesc, ")") {
		hint := f.SourceDesc[i+1 : len(f.SourceDesc)-1]
		switch {
		case strings.HasPrefix(hint, "field name"), strings.HasPrefix(hint, "field of"), strings.HasPrefix(hint, "@"):
		default:
			why = append([]string{fmt.Sprintf("the schema hint %s says it is %s", hint, f.DataType)}, why...)
		}
	}
	if len(why) == 0 {
		add("%s", f.SourceDesc)
	}
	return dedupe(why)
}

func pattern(m detect.Match) string {
	s := fmt.Sprintf("the %s pattern", m.DataType)
	if m.Pattern != "" {
		s = fmt.Sprintf("the pattern %q of %s", m.Pattern, m.DataType)
	}
	s += fmt.Sprintf(" (confidence %.2f)", m.Conf)
	if m.Transform != "" {
		s += fmt.Sprintf(", and says the value is %s", m.Transform)
	}
	return s
}

func ruleConf(r *rules.Rule) string {
	if r.Confidence > 0 && r.Confidence < 1 {
		return fmt.Sprintf(", which scales its confidence by %.2f", r.Confidence)
	}
	return ""
}

func how(h rules.Hit) string {
	if h.How == "resolved" {
		return "resolved callee"
	}
	return h.How
}

func label(c *ir.Call) string {
	if c.Callee != "" {
		return c.Callee
	}
	if c.RecvText != "" {
		return c.RecvText + "." + c.Name
	}
	return c.Name
}

func constArg(fn *ir.Func, v ir.VarID) (string, bool) {
	if v < 0 || int(v) >= len(fn.Vars) || fn.Vars[v].Const == nil {
		return "", false
	}
	return *fn.Vars[v].Const, true
}

func varName(fn *ir.Func, v ir.VarID) string {
	if v < 0 || int(v) >= len(fn.Vars) || fn.Vars[v].Name == "" {
		return ""
	}
	return fn.Vars[v].Name
}

func (x Explainer) steps(in Input, idx *index, code func(ir.Pos) string) []Step {
	f := in.Flow
	var out []Step
	for i, p := range f.Path {
		if i > 0 && p == f.Path[i-1] {
			continue
		}
		s := Step{Pos: p, Code: code(p)}
		r, ok := best(idx.at(p))
		switch {
		case ok:
			s.Func = r.fn.ID
			s.IR = ir.FormatInstr(r.fn, &r.fn.Instrs[r.i])
			s.What = x.describe(in, idx, r)
			if n := len(out); n > 0 {
				if w := ranHere(r, out[n-1].Func); w != "" {
					s.What = w
				}
			}
		default:
			if vs := idx.vars[p]; len(vs) > 0 {
				v := vs[0].fn.Vars[vs[0].i]
				s.Func = vs[0].fn.ID
				s.What = fmt.Sprintf("`%s` holds it", v.Name)
				if v.Param >= 0 {
					s.What = fmt.Sprintf("parameter `%s` of %s receives it", v.Name, short(vs[0].fn.ID))
				}
			} else {
				s.What = "(no instruction here in the IR: the file may have changed since the scan)"
			}
		}
		switch {
		case i == 0:
			s.What = "source: " + f.SourceDesc
		case p == f.Sink:
			s.What = "sink: " + s.What
		}
		out = append(out, s)
	}
	if n := len(out); n == 0 || out[n-1].Pos != f.Sink {
		// The path ends where the value is last touched; the sink call is
		// the last step.
		s := Step{Pos: f.Sink, Code: code(f.Sink), What: "sink: sent by `" + f.SinkCall + "`"}
		if r, ok := best(idx.at(f.Sink)); ok {
			s.Func = r.fn.ID
			s.IR = ir.FormatInstr(r.fn, &r.fn.Instrs[r.i])
		}
		out = append(out, s)
	}
	return out
}

// ranHere describes a call step reached from prev, a function the call
// does not name: one the call runs, so the value comes out of it. That is
// an implementation of an interface method, or a closure (a callback or
// handler) the analysis assumes the call may run. Without this, the step
// reads as if the call's arguments carried the value.
func ranHere(r ref, prev string) string {
	ins := &r.fn.Instrs[r.i]
	c := ins.Call
	if ins.Op != ir.OpCall || c == nil || prev == "" || prev == r.fn.ID || prev == c.Target || prev == c.Callee {
		return ""
	}
	if name := prev[strings.LastIndexByte(prev, '.')+1:]; name == c.Name {
		return fmt.Sprintf("calls %s, which implements %s: what it returns or writes comes out here", short(prev), short(label(c)))
	}
	return fmt.Sprintf("runs %s, a function value the analysis assumes %s may call (a callback or handler it holds or is given): what it returns or writes comes out here", short(prev), short(label(c)))
}

func (x Explainer) describe(in Input, idx *index, r ref) string {
	fn := r.fn
	ins := &fn.Instrs[r.i]
	dst := varName(fn, ins.Dst)
	arg := func(i int) string {
		if i < len(ins.Args) {
			if n := varName(fn, ins.Args[i]); n != "" {
				return "`" + n + "`"
			}
		}
		return "a value"
	}
	switch ins.Op {
	case ir.OpAssign:
		if dst != "" {
			return fmt.Sprintf("assigned to `%s`", dst)
		}
		return "copied"
	case ir.OpLoad:
		return fmt.Sprintf("read `%s` of %s", ins.Field, arg(0))
	case ir.OpStore:
		return fmt.Sprintf("stored in `%s` of %s: reading that field later gives it back", ins.Field, arg(0))
	case ir.OpReturn:
		return fmt.Sprintf("returned from %s to its callers", short(fn.ID))
	case ir.OpPhi:
		return "merged where branches join"
	case ir.OpCompute:
		op := ins.Operator
		if op == "" {
			return "part of a computed value"
		}
		return fmt.Sprintf("part of a value computed with `%s` (a string built from it still holds it)", op)
	case ir.OpClosure:
		return fmt.Sprintf("captured by the closure %s", short(ins.Func))
	case ir.OpThrow:
		return "thrown: the handler that catches it receives it"
	case ir.OpCatch:
		return "caught as the exception being handled"
	case ir.OpYield:
		return "yielded to the generator's caller"
	case ir.OpNew:
		if ins.Call == nil {
			return "put into a new object"
		}
		t := label(ins.Call)
		if strings.HasPrefix(t, "[") {
			// Go packs the arguments of a variadic call into a slice.
			return "passed as an argument"
		}
		return fmt.Sprintf("put into a new %s", short(t))
	case ir.OpCall:
		c := ins.Call
		if c == nil {
			return "a call"
		}
		if in.Rules != nil {
			if hs := in.Rules.Match(fn.Lang, rules.KindTransform, c); len(hs) > 0 {
				return fmt.Sprintf("transformed by `%s` (%s, rule `%s`)", label(c), hs[0].Rule.Transform, hs[0].Rule.ID)
			}
			for _, h := range in.Rules.Match(fn.Lang, rules.KindSink, c) {
				if h.Rule.ID == in.Flow.SinkRule {
					return fmt.Sprintf("sent by `%s`", label(c))
				}
			}
		}
		if x.Names != nil {
			if t := x.Names.FuncTransform(c.Name); t != "" {
				return fmt.Sprintf("transformed by `%s` (%s: its name says so)", label(c), t)
			}
		}
		if t := c.Target; t != "" {
			return fmt.Sprintf("passed to %s, which is analysed: its summary carries the value on", short(t))
		}
		if _, ok := idx.funcs[c.Callee]; ok && c.Callee != "" {
			return fmt.Sprintf("passed to %s, which is analysed: its summary carries the value on", short(c.Callee))
		}
		return fmt.Sprintf("through `%s`, code datawarden does not see into: its result is assumed to carry its arguments", label(c))
	}
	return ins.Op.String()
}

func short(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		id = id[i+1:]
	}
	return "`" + id + "`"
}

func (x Explainer) sink(in Input, idx *index, code func(ir.Pos) string) Sink {
	f := in.Flow
	s := Sink{Pos: f.Sink, Code: code(f.Sink), Call: f.SinkCall, Func: f.Function, Rule: f.SinkRule, Dest: dest(f.Dest)}
	var r *rules.Rule
	if in.Rules != nil {
		r = in.Rules.ByID(f.SinkRule)
	}
	if r != nil {
		s.Description = r.Description
	}
	for _, ref := range idx.at(f.Sink) {
		ins := &ref.fn.Instrs[ref.i]
		if ins.Op != ir.OpCall || ins.Call == nil || in.Rules == nil {
			continue
		}
		for _, h := range in.Rules.Match(ref.fn.Lang, rules.KindSink, ins.Call) {
			if h.Rule.ID != f.SinkRule {
				continue
			}
			switch {
			case h.How == "resolved":
				s.Why = fmt.Sprintf("the callee `%s` matches the rule's call patterns (%s)", ins.Call.Callee, patterns(h.Rule.Call))
			case strings.HasPrefix(h.How, "receiver name") && h.Rule.Receiver != "":
				s.Why = fmt.Sprintf("the callee is not resolved; `%s` is called on %s, which matches the rule's receiver pattern `%s` (confidence ×%.2f)",
					ins.Call.Name, strings.TrimPrefix(h.How, "receiver name "), h.Rule.Receiver, h.Conf)
			default:
				s.Why = fmt.Sprintf("the callee is not resolved; `%s` matches by its %s (confidence ×%.2f)", ins.Call.Name, h.How, h.Conf)
			}
		}
	}
	return s
}

func patterns(ps []string) string {
	if len(ps) > 4 {
		return strings.Join(ps[:4], ", ") + fmt.Sprintf(" and %d more", len(ps)-4)
	}
	return strings.Join(ps, ", ")
}

func dest(d finding.Destination) string {
	s := d.Kind
	if d.Vendor != "" {
		s = d.Vendor + " (" + d.Kind + ")"
	}
	if d.Host != "" {
		s += ", host " + d.Host
	}
	if d.FirstParty {
		s += ", first party"
	}
	return s
}

// silence lists what would silence a violation, narrowest first, as in
// docs/FINDINGS.md.
func silence(f *finding.Flow) []Option {
	var out []Option
	if field, ok := strings.CutPrefix(f.SourceDesc, "field "); ok {
		field, _, _ = strings.Cut(field, " ")
		switch f.Lang {
		case "go":
			out = append(out, Option{When: "the field is not " + f.DataType, Do: fmt.Sprintf("tag it where it is declared: %s `pii:\"-\"`", field)})
		case "java", "kotlin":
			out = append(out, Option{When: "the field is not " + f.DataType, Do: fmt.Sprintf("annotate it where it is declared: @PII(\"-\") on %s", field)})
		}
	}
	reason := `reason: "why this is acceptable"`
	out = append(out, Option{When: "this one flow is acceptable",
		Do: fmt.Sprintf("policy:\n  allow:\n    - {sink: %s, data_types: [%s], path: %q, %s}", f.SinkRule, f.DataType, f.Sink.File, reason)})
	if f.Dest.Host != "" && (f.Dest.Kind == "network" || f.Dest.Kind == "third_party") {
		out = append(out, Option{When: f.Dest.Host + " is your own service", Do: fmt.Sprintf("first_party_domains: [%s]", f.Dest.Host)})
	}
	out = append(out, Option{When: fmt.Sprintf("%s may always go to %s", f.DataType, f.SinkRule),
		Do: fmt.Sprintf("policy:\n  allow:\n    - {sink: %s, data_types: [%s], %s}", f.SinkRule, f.DataType, reason)})
	out = append(out, Option{When: "the directory is out of scope",
		Do: fmt.Sprintf("policy:\n  allow:\n    - {path: %q, %s}", path.Dir(f.Sink.File)+"/**", reason)})
	out = append(out, Option{When: "the sink rule is wrong for this codebase",
		Do: fmt.Sprintf("in a file under .datawarden/rules/:\n- {id: %s, disabled: true}", f.SinkRule)})
	out = append(out, Option{When: f.DataType + " is handled elsewhere", Do: fmt.Sprintf("policy:\n  ignore_data_types: [%s]", f.DataType)})
	out = append(out, Option{When: "it exists today and will be fixed over time", Do: "datawarden baseline"})
	return out
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
