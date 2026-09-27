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
)

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
	Transform   string `yaml:"transform,omitempty" json:"transform,omitempty"`
	Category    string `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string `yaml:"severity,omitempty" json:"severity,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`

	Origin string `yaml:"-" json:"origin"`

	callRes  []*regexp.Regexp
	fields   []fieldPattern
	recvRe   *regexp.Regexp
	names    []string // last segment of each call pattern
	typeSegs []string // second-to-last segment of each call pattern
}

// Set is a validated, indexed collection of rules.
type Set struct {
	Rules  []*Rule
	byID   map[string]*Rule
	byName map[string][]*Rule
	wild   []*Rule
	hash   string
}

// Builtin returns the rules embedded in the binary.
func Builtin() ([]*Rule, error) {
	return readTree(builtinFS, "builtin", "builtin:")
}

// Load returns the built-in rules merged with repository overrides read
// from fsys (later sources win). Each path may name a YAML file or a
// directory of them; missing paths are skipped. fsys may be nil when there
// are no overrides.
func Load(fsys fs.FS, paths ...string) (*Set, error) {
	all, err := Builtin()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if fsys == nil {
			break
		}
		rs, err := readTree(fsys, path.Clean(p), "")
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return NewSet(all)
}

// readTree parses one YAML file or every *.yaml/*.yml under a directory.
func readTree(fsys fs.FS, root, originPrefix string) ([]*Rule, error) {
	st, err := fs.Stat(fsys, root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
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
			return nil, err
		}
	} else {
		files = []string{root}
	}
	sort.Strings(files)
	var out []*Rule
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		origin := f
		if originPrefix != "" {
			origin = originPrefix + path.Base(f)
		}
		rs, err := parse(b, origin)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

// parse decodes a rule file: a list of rules, or {rules: [...]}. Unknown
// keys are errors, so a misspelt field cannot silently change what a rule
// matches.
func parse(b []byte, origin string) ([]*Rule, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	if len(doc.Content) == 0 {
		return nil, nil // empty file
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var rs []*Rule
	if doc.Content[0].Kind == yaml.MappingNode {
		var wrapped struct {
			Rules []*Rule `yaml:"rules"`
		}
		if err := dec.Decode(&wrapped); err != nil {
			return nil, fmt.Errorf("%s: %w", origin, err)
		}
		rs = wrapped.Rules
	} else if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if r == nil {
			continue
		}
		r.Origin = origin
		if r.ID != "" && seen[r.ID] {
			return nil, fmt.Errorf("%s: rule %s is defined twice", origin, r.ID)
		}
		seen[r.ID] = true
	}
	return rs, nil
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
	b, _ := json.Marshal(s.Rules)
	h := sha256.Sum256(b)
	s.hash = hex.EncodeToString(h[:8])
	return s, nil
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
	r.callRes, r.names, r.typeSegs = nil, nil, nil
	for _, c := range r.Call {
		re, err := globToRegexp(c)
		if err != nil {
			return err
		}
		r.callRes = append(r.callRes, re)
		segs := splitCallee(c)
		r.names = append(r.names, segs[len(segs)-1])
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
