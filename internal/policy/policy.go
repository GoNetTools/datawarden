// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy decides which findings are violations and how severe
// they are.
package policy

import (
	"path"
	"regexp"
	"strings"

	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
)

// Severity levels.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Catalog describes data types (implemented by *detect.Classifier).
type Catalog interface {
	Lookup(id string) detect.DataType
	Class(id string) detect.Class
}

// Evaluator applies a repository's policy.
type Evaluator struct {
	Config  *config.Config
	Catalog Catalog
}

// Apply filters flows and literals by the config, then sets Class,
// Violation, Severity and Allowed on what remains. A class's entry in
// policy.classes overrides fail_on and safe_transforms for its data.
func (e Evaluator) Apply(flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal) {
	c := e.Config
	p := c.Policy
	ignore := toSet(p.IgnoreDataTypes)
	ignoreClass := toSet(p.IgnoreClasses)
	failOn := map[string]map[string]bool{"": toSet(p.FailOn)}
	safe := map[string]map[string]bool{"": toSet(p.SafeTransforms)}
	for class, cp := range p.Classes {
		if cp.FailOn != nil {
			failOn[class] = toSet(cp.FailOn)
		}
		if cp.SafeTransforms != nil {
			safe[class] = toSet(cp.SafeTransforms)
		}
	}
	forClass := func(m map[string]map[string]bool, class string) map[string]bool {
		if s, ok := m[class]; ok {
			return s
		}
		return m[""]
	}

	var outF []*finding.Flow
	for _, f := range flows {
		dt := e.Catalog.Lookup(f.DataType)
		if ignore[f.DataType] || ignoreClass[dt.Class] || f.Confidence < c.MinConfidence {
			continue
		}
		f.Class = dt.Class
		f.Severity = e.flowSeverity(f, dt)
		f.Violation = false
		f.Allowed = ""
		switch {
		case !forClass(failOn, dt.Class)[f.Dest.Kind] || f.Dest.FirstParty:
		case f.Confidence < p.MinConfidence:
		case anySafe(f.Transforms, forClass(safe, dt.Class)):
			f.Allowed = "transform: " + strings.Join(f.Transforms, ",")
		default:
			if a := matchAllow(p.Allow, f); a != nil {
				f.Allowed = "allow"
				if a.Reason != "" {
					f.Allowed = "allow: " + a.Reason
				}
			} else {
				f.Violation = true
			}
		}
		outF = append(outF, f)
	}
	var keptL []*finding.Literal
	for _, l := range lits {
		dt := e.Catalog.Lookup(l.DataType)
		if ignore[l.DataType] || ignoreClass[dt.Class] {
			continue
		}
		l.Class = dt.Class
		l.Severity = Medium
		if e.raised(dt) {
			l.Severity = High
		}
		l.Violation = p.FailOnLiterals == nil || *p.FailOnLiterals
		keptL = append(keptL, l)
	}
	return outF, keptL
}

// raised reports whether findings of dt are high severity wherever they
// go: special-category data, identity documents (severity: high in the
// taxonomy) and classes marked high (health, cardholder data, credentials).
func (e Evaluator) raised(dt detect.DataType) bool {
	return dt.Sensitive || dt.Severity == High || e.Catalog.Class(dt.Class).Severity == High
}

func (e Evaluator) flowSeverity(f *finding.Flow, dt detect.DataType) string {
	sev := Medium
	switch f.Dest.Kind {
	case "third_party":
		sev = High
	case "first_party":
		sev = Low
	}
	if e.raised(dt) && sev == Medium {
		sev = High
	}
	return sev
}

func anySafe(xf []string, safe map[string]bool) bool {
	for _, x := range xf {
		if safe[x] {
			return true
		}
	}
	return false
}

func matchAllow(allows []config.Allow, f *finding.Flow) *config.Allow {
	for i := range allows {
		a := &allows[i]
		if a.Sink == "" && len(a.DataTypes) == 0 && a.DestHost == "" && len(a.DestKinds) == 0 && a.Path == "" {
			continue
		}
		if a.Sink != "" && !glob(a.Sink, f.SinkRule) {
			continue
		}
		if len(a.DataTypes) > 0 && !toSet(a.DataTypes)[f.DataType] {
			continue
		}
		if a.DestHost != "" && !glob(a.DestHost, f.Dest.Host) {
			continue
		}
		if len(a.DestKinds) > 0 && !toSet(a.DestKinds)[f.Dest.Kind] {
			continue
		}
		if a.Path != "" && !pathGlob(a.Path, f.Sink.File) {
			continue
		}
		return a
	}
	return nil
}

func glob(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	if err == nil && ok {
		return true
	}
	if strings.Contains(pattern, "*") {
		re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
		m, _ := regexp.MatchString(re, s)
		return m
	}
	return pattern == s
}

func pathGlob(pattern, p string) bool {
	re := regexp.QuoteMeta(pattern)
	re = strings.ReplaceAll(re, `\*\*/`, "(?:.*/)?")
	re = strings.ReplaceAll(re, `\*\*`, ".*")
	re = strings.ReplaceAll(re, `\*`, "[^/]*")
	re = strings.ReplaceAll(re, `\?`, "[^/]")
	m, _ := regexp.MatchString("^"+re+"$", p)
	return m
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Policies applies the policy of whichever configuration it is given: the
// CLI's Policy.
type Policies struct {
	Catalog Catalog
}

// Apply evaluates findings under cfg (see Evaluator.Apply).
func (p Policies) Apply(cfg *config.Config, flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal) {
	return Evaluator{
		Config:  cfg,
		Catalog: p.Catalog,
	}.Apply(flows, lits)
}
