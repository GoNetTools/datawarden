// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package ruletest checks rules and frontends against annotated example
// code. A comment line names a rule, and the annotation applies to the next
// line that is not itself an annotation:
//
//	// ruleid: log.go.stdlib
//	log.Printf("signup %s", email)
//
//	// ok: log.go.stdlib
//	log.Printf("order %d", orderID)
//
// The annotations, as in Semgrep's rule tests:
//
//	ruleid: <id>      the line must produce a finding for rule <id>
//	ok: <id>          the line must not produce a violation for rule <id>
//	todoruleid: <id>  known miss: the line should produce a finding but does not yet
//	todook: <id>      known false positive: the line produces a violation it should not
//
// Several ids can share one annotation, separated by commas. A finding for
// a sink rule is a flow into that sink on the line; for a source rule, a
// flow of the rule's data type starting on the line; for a transform rule,
// a flow through the line that carries the rule's transform.
//
// Every violation reported in the example files must be annotated at its
// sink line, so examples also catch rules that start matching too much.
package ruletest

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

// Mark is the kind of an annotation.
type Mark string

// Annotation marks.
const (
	RuleID     Mark = "ruleid"
	OK         Mark = "ok"
	TodoRuleID Mark = "todoruleid"
	TodoOK     Mark = "todook"
)

// Annotation says what a rule must (or must not) report on one line.
type Annotation struct {
	Mark   Mark
	RuleID string
	// File is slash-separated and relative to the example root; Line is
	// the annotated line, not the comment's.
	File string
	Line int
}

func (a Annotation) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", a.File, a.Line, a.Mark, a.RuleID)
}

// annotationRe matches a whole-line comment holding an annotation, in the
// comment syntaxes of the supported languages (//, #, /* */).
var annotationRe = regexp.MustCompile(`^\s*(?://+|#+|/\*+|\*+)\s*(todoruleid|todook|ruleid|ok)\s*:\s*([A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*)\s*(?:\*+/)?\s*$`)

// Parse reads the annotations of every file under root in fsys.
func Parse(fsys fs.FS, root string) ([]Annotation, error) {
	var out []Annotation
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		rel := p
		if root != "." {
			rel = strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
		}
		anns, err := ParseFile(rel, b)
		if err != nil {
			return err
		}
		out = append(out, anns...)
		return nil
	})
	return out, err
}

// ParseFile reads the annotations of one file.
func ParseFile(rel string, src []byte) ([]Annotation, error) {
	var out, pending []Annotation
	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		m := annotationRe.FindStringSubmatch(sc.Text())
		if m == nil {
			for _, a := range pending {
				a.Line = line
				out = append(out, a)
			}
			pending = nil
			continue
		}
		for _, id := range strings.Split(m[2], ",") {
			if id = strings.TrimSpace(id); id != "" {
				pending = append(pending, Annotation{Mark: Mark(m[1]), RuleID: id, File: rel})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("%s: annotation %s: %s at the end of the file has no line to apply to", rel, pending[0].Mark, pending[0].RuleID)
	}
	return out, nil
}

// Rules looks rules up by id (*rules.Set).
type Rules interface {
	ByID(id string) *rules.Rule
}

// Result is the outcome of checking annotations against findings.
type Result struct {
	// Failures are test failures.
	Failures []string
	// Known lists todoruleid misses and todook false positives that still
	// hold, for the test log.
	Known []string
	// Covered holds the rule ids with a ruleid or todoruleid annotation.
	Covered map[string]bool
}

// Check compares annotations with the flows a scan of the example root
// reported.
func Check(rs Rules, anns []Annotation, flows []*finding.Flow) Result {
	res := Result{Covered: map[string]bool{}}
	fail := func(format string, args ...any) { res.Failures = append(res.Failures, fmt.Sprintf(format, args...)) }

	// annotated[file:line][rule id] is true when a violation there is expected.
	annotated := map[string]map[string]bool{}
	for _, a := range anns {
		r := rs.ByID(a.RuleID)
		if r == nil {
			fail("%s: unknown rule id", a)
			continue
		}
		if a.Mark == RuleID || a.Mark == TodoRuleID {
			res.Covered[a.RuleID] = true
		}
		found := findings(r, a.File, a.Line, flows, false)
		violations := findings(r, a.File, a.Line, flows, true)
		switch a.Mark {
		case RuleID:
			if len(found) == 0 {
				fail("%s: no finding (%s)", a, what(r))
			}
		case OK:
			if len(violations) > 0 {
				fail("%s: unexpected violation: %s", a, describe(violations[0]))
			}
		case TodoRuleID:
			if len(found) > 0 {
				fail("%s: now reported; change todoruleid to ruleid", a)
			} else {
				res.Known = append(res.Known, fmt.Sprintf("%s (known miss)", a))
			}
		case TodoOK:
			if len(violations) == 0 {
				fail("%s: no longer reported; change todook to ok", a)
			} else {
				res.Known = append(res.Known, fmt.Sprintf("%s (known false positive)", a))
			}
		}
		if r.Kind == rules.KindSink { // checked above; not "unannotated" below
			k := fmt.Sprintf("%s:%d", a.File, a.Line)
			if annotated[k] == nil {
				annotated[k] = map[string]bool{}
			}
			annotated[k][a.RuleID] = true
		}
	}

	// Every violation must be expected at its sink line.
	seen := map[string]bool{}
	for _, f := range flows {
		if !f.Violation {
			continue
		}
		k := fmt.Sprintf("%s:%d", f.Sink.File, f.Sink.Line)
		if annotated[k][f.SinkRule] || seen[k+f.SinkRule] {
			continue
		}
		seen[k+f.SinkRule] = true
		fail("%s: unannotated violation %s; add `ruleid: %s` above the line if it is a leak, or `todook: %s` if it is a false positive",
			k, describe(f), f.SinkRule, f.SinkRule)
	}
	sort.Strings(res.Failures)
	sort.Strings(res.Known)
	return res
}

// findings returns the flows that count as a finding of rule r on the
// line; with violationsOnly, only those the policy calls violations.
func findings(r *rules.Rule, file string, line int, flows []*finding.Flow, violationsOnly bool) []*finding.Flow {
	var out []*finding.Flow
	for _, f := range flows {
		if violationsOnly && !f.Violation {
			continue
		}
		hit := false
		switch r.Kind {
		case rules.KindSource:
			hit = f.DataType == r.DataType && f.Source.File == file && f.Source.Line == line
		case rules.KindTransform:
			hit = contains(f.Transforms, r.Transform) && onPath(f, file, line)
		default:
			hit = f.SinkRule == r.ID && f.Sink.File == file && f.Sink.Line == line
		}
		if hit {
			out = append(out, f)
		}
	}
	return out
}

func onPath(f *finding.Flow, file string, line int) bool {
	for _, p := range f.Path {
		if p.File == file && p.Line == line {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func what(r *rules.Rule) string {
	switch r.Kind {
	case rules.KindSource:
		return fmt.Sprintf("expected a %s flow starting here", r.DataType)
	case rules.KindTransform:
		return fmt.Sprintf("expected a flow through here carrying %q", r.Transform)
	}
	return "expected a flow into this sink"
}

func describe(f *finding.Flow) string {
	return fmt.Sprintf("%s → %s in %s (confidence %.2f)", f.DataType, f.SinkRule, f.Function, f.Confidence)
}

// Missing returns the ids of rules with no ruleid or todoruleid example,
// skipping rules whose languages are all outside langs (frontends missing
// from this build).
func Missing(set *rules.Set, covered map[string]bool, langs map[string]bool) []string {
	var out []string
	for _, r := range set.Rules {
		runnable := false
		for _, l := range r.Lang {
			runnable = runnable || langs[l]
		}
		if runnable && !covered[r.ID] {
			out = append(out, r.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Tester parses and checks annotated examples: the CLI's RuleTester.
type Tester struct{}

// Parse reads the annotations under root (see Parse).
func (Tester) Parse(fsys fs.FS, root string) ([]Annotation, error) { return Parse(fsys, root) }

// Check compares annotations with findings (see Check).
func (Tester) Check(rs Rules, anns []Annotation, flows []*finding.Flow) Result {
	return Check(rs, anns, flows)
}
