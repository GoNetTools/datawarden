// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules loads sink, source and transform rules. Built-in rules are
// YAML files embedded in the binary; a repository can add, replace or
// disable rules by id with its own YAML files.
package rules

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GoNetTools/datawarden/internal/lang"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Rule kinds.
const (
	KindSink      = "sink"
	KindSource    = "source"
	KindTransform = "transform"
	// KindAPI rules model library calls: what they do with their
	// arguments (Effect) and what they return (Returns).
	KindAPI = "api"
)

// API effects: what a call does with the data it is given.
const (
	// EffectBuilder: the arguments go into the receiver, which the call
	// returns (StringBuilder.append, Request.Builder.post).
	EffectBuilder = "builder"
	// EffectSends: the arguments leave the program and the result is the
	// remote's answer, not derived from them (HttpClient.send).
	EffectSends = "sends"
	// EffectDerives: the result carries every argument (String.format).
	EffectDerives = "derives"
	// EffectNone: the result carries no data (String.length, List.size).
	EffectNone = "none"
)

var validEffects = map[string]bool{EffectBuilder: true, EffectSends: true, EffectDerives: true, EffectNone: true}

// Destination kinds.
const (
	DestThirdParty = "third_party"
	DestFirstParty = "first_party"
	DestLog        = "log"
	DestStorage    = "storage"
	DestNetwork    = "network"
	DestIPC        = "ipc"
)

var validDestKinds = map[string]bool{DestThirdParty: true, DestFirstParty: true, DestLog: true, DestStorage: true, DestNetwork: true, DestIPC: true}

// Dest describes where a sink sends data.
type Dest struct {
	Host   string `yaml:"host,omitempty" json:"host,omitempty"`
	Kind   string `yaml:"kind" json:"kind"`
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
	Vendor string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
}

// StringList accepts either a scalar or a sequence in YAML.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = StringList{n.Value}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = v
		return nil
	}
	return fmt.Errorf("line %d: expected string or list", n.Line)
}

// ArgSpec selects call arguments: a single index, a list, or "*" for all.
// Indexes exclude the receiver; -1 selects the receiver itself (a value
// that writes itself: dict.write(toFile:)).
type ArgSpec struct {
	All     bool  `json:"all,omitempty"`
	Indexes []int `json:"indexes,omitempty"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *ArgSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "*" || n.Value == "all" {
			a.All = true
			return nil
		}
		i, err := strconv.Atoi(n.Value)
		if err != nil {
			return fmt.Errorf("line %d: arg must be an index, a list of indexes, or \"*\"", n.Line)
		}
		a.Indexes = []int{i}
		return nil
	case yaml.SequenceNode:
		return n.Decode(&a.Indexes)
	}
	return fmt.Errorf("line %d: bad arg", n.Line)
}

// Selects reports whether argument i (receiver excluded) is selected.
func (a ArgSpec) Selects(i int) bool {
	if a.All {
		return true
	}
	for _, x := range a.Indexes {
		if x == i {
			return true
		}
	}
	return false
}

// Rule is one sink, source or transform rule.
type Rule struct {
	ID   string     `yaml:"id" json:"id"`
	Kind string     `yaml:"kind,omitempty" json:"kind"`
	Lang StringList `yaml:"lang" json:"lang"`
	// Call lists qualified callee names; '*' matches any run of characters.
	Call StringList `yaml:"call" json:"call"`
	// Receiver is a regular expression matched against the receiver
	// expression when the receiver type could not be resolved
	// (e.g. "(?i)^(log|logger)$").
	Receiver string `yaml:"receiver,omitempty" json:"receiver,omitempty"`
	// MatchBare lets the rule match an unresolved call with no receiver by
	// method name alone (Kotlin scope functions: prefs.edit { putString(..) }).
	MatchBare bool `yaml:"match_bare,omitempty" json:"match_bare,omitempty"`
	// Arg selects which arguments reach the sink (receiver excluded).
	Arg  ArgSpec `yaml:"arg" json:"arg"`
	Dest Dest    `yaml:"dest,omitempty" json:"dest"`
	// HostArg names an argument holding a URL; when it is a constant the
	// host is used as the destination host.
	HostArg *int `yaml:"host_arg,omitempty" json:"host_arg,omitempty"`
	// ArgIs restricts a sink to calls whose argument (by index, -1 for
	// the receiver) is a variable whose name matches the regular
	// expression: fmt.Fprintf is a log only when it writes to os.Stderr.
	// ArgNot is the opposite: the rule does not apply when the argument
	// matches. Qualified names are matched as "importpath.Name"
	// (os.Stderr) or "obj.field" chains.
	ArgIs  map[int]string `yaml:"arg_is,omitempty" json:"arg_is,omitempty"`
	ArgNot map[int]string `yaml:"arg_not,omitempty" json:"arg_not,omitempty"`
	// DataType is produced by source rules.
	DataType string `yaml:"data_type,omitempty" json:"data_type,omitempty"`
	// Field lists field reads that are sources, as "Type.field" ('*'
	// matches any run of characters in the type): r.Body of a
	// net/http.Request, req.body in Express. When the object's type is not
	// known, Receiver is matched against the object as written (req,
	// ctx.request).
	Field StringList `yaml:"field,omitempty" json:"field,omitempty"`
	// ParamAnnotation lists parameter annotations or decorators that make
	// the parameter a source (@RequestBody, @Body()). One given a key
	// (@Body("email")) is described by that key instead.
	ParamAnnotation StringList `yaml:"param_annotation,omitempty" json:"param_annotation,omitempty"`
	// Confidence scales the confidence of what a source rule produces
	// (default 1): request data is personal data often, not always.
	Confidence float64 `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	// Transform is applied by transform rules ("sha256", "masked").
	Transform string `yaml:"transform,omitempty" json:"transform,omitempty"`
	// Effect is what an api rule's call does with its arguments (see
	// EffectBuilder...); Returns is the qualified type it returns, or
	// "$T" for the receiver's element type (Optional<User>.get()).
	Effect      string `yaml:"effect,omitempty" json:"effect,omitempty"`
	Returns     string `yaml:"returns,omitempty" json:"returns,omitempty"`
	Category    string `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string `yaml:"severity,omitempty" json:"severity,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`

	Origin string `yaml:"-" json:"origin"`

	callRes  []*regexp.Regexp
	argIs    map[int]*regexp.Regexp
	argNot   map[int]*regexp.Regexp
	fields   []fieldPattern
	recvRe   *regexp.Regexp
	names    []string         // last segment of each call pattern
	nameRes  []*regexp.Regexp // names with a wildcard, compiled; nil for others
	typeSegs []string         // second-to-last segment of each call pattern
}

// Set is a validated, indexed collection of rules, with the name
// heuristics loaded alongside them.
type Set struct {
	Rules  []*Rule
	byID   map[string]*Rule
	byName map[string][]*Rule
	wild   []*Rule
	heur   *Heuristics
	hash   string
}

// Builtin returns the rules embedded in the binary.
func Builtin() ([]*Rule, error) {
	rs, _, err := readTree(builtinFS, "builtin", "builtin:")
	return rs, err
}

// BuiltinHeuristics returns the name heuristics embedded in the binary.
func BuiltinHeuristics() (*Heuristics, error) {
	_, h, err := readTree(builtinFS, "builtin", "builtin:")
	return h, err
}

// Load returns the built-in rules and heuristics merged with repository
// overrides read from fsys (later sources win). Each path may name a
// YAML file or a directory of them; missing paths are skipped. fsys may
// be nil when there are no overrides.
func Load(fsys fs.FS, paths ...string) (*Set, error) {
	all, heur, err := readTree(builtinFS, "builtin", "builtin:")
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if fsys == nil {
			break
		}
		rs, h, err := readTree(fsys, path.Clean(p), "")
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
		heur.merge(h)
	}
	set, err := NewSet(all)
	if err != nil {
		return nil, err
	}
	set.heur = heur
	set.rehash()
	return set, nil
}

// Heuristics returns the set's name heuristics (never nil).
func (s *Set) Heuristics() *Heuristics {
	if s.heur == nil {
		return &Heuristics{}
	}
	return s.heur
}

// readTree parses one YAML file or every *.yaml/*.yml under a directory,
// returning the rules and the merged heuristics they define.
func readTree(fsys fs.FS, root, originPrefix string) ([]*Rule, *Heuristics, error) {
	heur := &Heuristics{}
	st, err := fs.Stat(fsys, root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, heur, nil
		}
		return nil, nil, err
	}
	var files []string
	if st.IsDir() {
		err = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else {
		files = []string{root}
	}
	sort.Strings(files)
	var out []*Rule
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, nil, err
		}
		origin := f
		if originPrefix != "" {
			origin = originPrefix + path.Base(f)
		}
		rs, h, err := parse(b, origin)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, rs...)
		heur.merge(h)
	}
	return out, heur, nil
}

// parse decodes a rule file: a list of rules, or {rules: [...],
// heuristics: {...}}. Unknown keys are errors, so a misspelt field cannot
// silently change what a rule matches.
func parse(b []byte, origin string) ([]*Rule, *Heuristics, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", origin, err)
	}
	if len(doc.Content) == 0 {
		return nil, nil, nil // empty file
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var rs []*Rule
	var heur *Heuristics
	if doc.Content[0].Kind == yaml.MappingNode {
		var wrapped struct {
			Rules      []*Rule   `yaml:"rules"`
			Heuristics yaml.Node `yaml:"heuristics"`
		}
		if err := dec.Decode(&wrapped); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", origin, err)
		}
		rs = wrapped.Rules
		h, err := parseHeuristics(&wrapped.Heuristics, origin)
		if err != nil {
			return nil, nil, err
		}
		heur = h
	} else if err := dec.Decode(&rs); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", origin, err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if r == nil {
			continue
		}
		r.Origin = origin
		if r.ID != "" && seen[r.ID] {
			return nil, nil, fmt.Errorf("%s: rule %s is defined twice", origin, r.ID)
		}
		seen[r.ID] = true
	}
	return rs, heur, nil
}

// NewSet merges rules by id (later wins), drops disabled ones, validates
// and compiles them.
func NewSet(rules []*Rule) (*Set, error) {
	order := []string{}
	byID := map[string]*Rule{}
	for _, r := range rules {
		if r == nil {
			continue
		}
		if r.ID == "" {
			return nil, fmt.Errorf("%s: rule without id", r.Origin)
		}
		if _, ok := byID[r.ID]; !ok {
			order = append(order, r.ID)
		}
		byID[r.ID] = r
	}
	s := &Set{byID: map[string]*Rule{}, byName: map[string][]*Rule{}}
	for _, id := range order {
		r := byID[id]
		if r.Disabled {
			continue
		}
		if err := r.compile(); err != nil {
			return nil, fmt.Errorf("%s: rule %s: %w", r.Origin, r.ID, err)
		}
		s.Rules = append(s.Rules, r)
		s.byID[id] = r
		isWild := false
		for _, n := range r.names {
			if strings.Contains(n, "*") {
				isWild = true
			} else {
				s.byName[n] = append(s.byName[n], r)
			}
		}
		if isWild {
			s.wild = append(s.wild, r)
		}
	}
	s.rehash()
	return s, nil
}

// rehash computes the set's hash from its rules and heuristics: a
// change to either invalidates cached summaries.
func (s *Set) rehash() {
	b, _ := json.Marshal(struct {
		Rules      []*Rule
		Heuristics *Heuristics
	}{s.Rules, s.heur})
	h := sha256.Sum256(b)
	s.hash = hex.EncodeToString(h[:8])
}

func (r *Rule) compile() error {
	if r.Kind == "" {
		r.Kind = KindSink
	}
	switch r.Kind {
	case KindSink:
		if !r.Arg.All && len(r.Arg.Indexes) == 0 {
			r.Arg.All = true
		}
		if !validDestKinds[r.Dest.Kind] {
			return fmt.Errorf("dest.kind %q must be one of third_party, first_party, log, storage, network, ipc", r.Dest.Kind)
		}
	case KindSource:
		if r.DataType == "" {
			return fmt.Errorf("source rule needs data_type")
		}
		if r.Confidence < 0 || r.Confidence > 1 {
			return fmt.Errorf("confidence %v must be between 0 and 1", r.Confidence)
		}
		if r.Confidence == 0 {
			r.Confidence = 1
		}
	case KindTransform:
		if r.Transform == "" {
			return fmt.Errorf("transform rule needs transform")
		}
	case KindAPI:
		if r.Effect == "" && r.Returns == "" {
			return fmt.Errorf("api rule needs effect (builder, sends, derives, none) or returns")
		}
		if r.Effect != "" && !validEffects[r.Effect] {
			return fmt.Errorf("effect %q must be one of builder, sends, derives, none", r.Effect)
		}
		if r.Dest.Kind != "" || r.Arg.All || len(r.Arg.Indexes) > 0 || r.DataType != "" {
			return fmt.Errorf("api rule takes only call, effect and returns")
		}
	default:
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	if (len(r.Field) > 0 || len(r.ParamAnnotation) > 0) && r.Kind != KindSource {
		return fmt.Errorf("field and param_annotation are for source rules")
	}
	if len(r.Call) == 0 && len(r.Field) == 0 && len(r.ParamAnnotation) == 0 {
		return fmt.Errorf("call is required (or, for a source, field or param_annotation)")
	}
	if len(r.Lang) == 0 {
		return fmt.Errorf("lang is required")
	}
	for i, l := range r.Lang {
		r.Lang[i] = lang.Normalize(l)
		if !lang.IsCode(r.Lang[i]) {
			return fmt.Errorf("lang %q is not supported (use one of %s)", l, strings.Join(lang.CodeNames(), ", "))
		}
	}
	for _, i := range r.Arg.Indexes {
		if i < -1 {
			return fmt.Errorf("arg %d: indexes start at 0 (-1 is the receiver)", i)
		}
	}
	if r.HostArg != nil && *r.HostArg < 0 {
		return fmt.Errorf("host_arg %d: indexes start at 0", *r.HostArg)
	}
	if (r.Effect != "" || r.Returns != "") && r.Kind != KindAPI {
		return fmt.Errorf("effect and returns are for api rules")
	}
	if (len(r.ArgIs) > 0 || len(r.ArgNot) > 0) && r.Kind != KindSink {
		return fmt.Errorf("arg_is and arg_not are for sink rules")
	}
	var err error
	if r.argIs, err = compileArgPatterns("arg_is", r.ArgIs); err != nil {
		return err
	}
	if r.argNot, err = compileArgPatterns("arg_not", r.ArgNot); err != nil {
		return err
	}
	r.callRes, r.names, r.nameRes, r.typeSegs = nil, nil, nil, nil
	for _, c := range r.Call {
		re, err := globToRegexp(c)
		if err != nil {
			return err
		}
		r.callRes = append(r.callRes, re)
		segs := splitCallee(c)
		name := segs[len(segs)-1]
		r.names = append(r.names, name)
		var nameRe *regexp.Regexp
		if name != "*" && strings.Contains(name, "*") {
			nameRe, _ = globToRegexp(name) // nil when invalid: matches nothing
		}
		r.nameRes = append(r.nameRes, nameRe)
		ts := ""
		if len(segs) >= 2 {
			ts = segs[len(segs)-2]
		}
		r.typeSegs = append(r.typeSegs, ts)
	}
	r.fields = nil
	for _, f := range r.Field {
		i := strings.LastIndexByte(f, '.')
		if i <= 0 || i == len(f)-1 {
			return fmt.Errorf("field %q must be Type.field", f)
		}
		re, err := globToRegexp(f[:i])
		if err != nil {
			return err
		}
		r.fields = append(r.fields, fieldPattern{owner: re, name: f[i+1:]})
	}
	for _, a := range r.ParamAnnotation {
		if strings.ContainsAny(a, "@() ") {
			return fmt.Errorf("param_annotation %q: give the bare name (RequestBody, Body)", a)
		}
	}
	if r.Receiver != "" {
		re, err := regexp.Compile(r.Receiver)
		if err != nil {
			return fmt.Errorf("receiver: %w", err)
		}
		r.recvRe = re
	}
	return nil
}

type fieldPattern struct {
	owner *regexp.Regexp
	name  string
}

func compileArgPatterns(key string, m map[int]string) (map[int]*regexp.Regexp, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[int]*regexp.Regexp, len(m))
	for i, p := range m {
		if i < -1 {
			return nil, fmt.Errorf("%s %d: indexes start at 0 (-1 is the receiver)", key, i)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s %d: %w", key, i, err)
		}
		out[i] = re
	}
	return out, nil
}

// ArgAllowed reports whether a call with the given argument names (by
// index, -1 for the receiver; "" when unnamed) passes the rule's arg_is
// and arg_not conditions.
func (r *Rule) ArgAllowed(name func(i int) string) bool {
	for i, re := range r.argIs {
		if !re.MatchString(name(i)) {
			return false
		}
	}
	for i, re := range r.argNot {
		if re.MatchString(name(i)) {
			return false
		}
	}
	return true
}

func globToRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for _, part := range strings.Split(g, "*") {
		b.WriteString(regexp.QuoteMeta(part))
		b.WriteString(".*")
	}
	s := strings.TrimSuffix(b.String(), ".*") + "$"
	return regexp.Compile(s)
}

// splitCallee splits "pkg/path.Type.Method" on dots that are not part of
// the import path: the last '/' ends the path portion.
func splitCallee(c string) []string {
	slash := strings.LastIndexByte(c, '/')
	head, tail := "", c
	if slash >= 0 {
		// The package path may itself contain dots (github.com/...); keep
		// everything up to the first dot after the last slash together.
		dot := strings.IndexByte(c[slash:], '.')
		if dot < 0 {
			return []string{c}
		}
		head, tail = c[:slash+dot], c[slash+dot+1:]
	}
	parts := strings.Split(tail, ".")
	if head != "" {
		parts = append([]string{head}, parts...)
	}
	return parts
}

// Hash identifies the effective rule set (used to invalidate caches).
func (s *Set) Hash() string { return s.hash }

// ByID returns a rule.
func (s *Set) ByID(id string) *Rule { return s.byID[id] }

// All returns the rules in load order.
func (s *Set) All() []*Rule { return s.Rules }
