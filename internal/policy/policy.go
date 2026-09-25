// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy decides which findings are violations and how severe
// they are.
package policy

import (
	"path"
	"regexp"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/config"
	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/finding"
)

// Severity levels.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Identity documents are high severity even when committed as literals.
var identityTypes = map[string]bool{"vn_cccd": true, "national_id": true, "us_ssn": true, "passport": true, "drivers_license": true, "tax_id": true, "insurance_id": true}

// Catalog describes data types (implemented by *detect.Classifier).
type Catalog interface {
	Lookup(id string) detect.DataType
}

// Evaluator applies a repository's policy.
type Evaluator struct {
	Config  *config.Config
	Catalog Catalog
}

// Apply filters flows and literals by the config, then sets Violation,
// Severity and Allowed on what remains.
func (e Evaluator) Apply(flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal) {
	c := e.Config
	p := c.Policy
	ignore := toSet(p.IgnoreDataTypes)
	failOn := toSet(p.FailOn)
	safe := toSet(p.SafeTransforms)

	var outF []*finding.Flow
	for _, f := range flows {
		if ignore[f.DataType] || f.Confidence < c.MinConfidence {
			continue
		}
		f.Severity = e.flowSeverity(f)
		f.Violation = false
		f.Allowed = ""
		switch {
		case !failOn[f.Dest.Kind] || f.Dest.FirstParty:
		case f.Confidence < p.MinConfidence:
		case anySafe(f.Transforms, safe):
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
		if ignore[l.DataType] {
			continue
		}
		l.Severity = Medium
		if identityTypes[l.DataType] || e.Catalog.Lookup(l.DataType).Sensitive {
			l.Severity = High
		}
		l.Violation = p.FailOnLiterals == nil || *p.FailOnLiterals
		keptL = append(keptL, l)
	}
	return outF, keptL
}

func (e Evaluator) flowSeverity(f *finding.Flow) string {
	sev := Medium
	switch f.Dest.Kind {
	case "third_party":
		sev = High
	case "first_party":
		sev = Low
	}
	dt := e.Catalog.Lookup(f.DataType)
	if (dt.Sensitive || identityTypes[f.DataType]) && sev == Medium {
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
	return Evaluator{Config: cfg, Catalog: p.Catalog}.Apply(flows, lits)
}
