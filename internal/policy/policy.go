// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy decides which findings are violations and how severe
// they are.
package policy

import (
	"fmt"
	"math"
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

// Decision statuses.
const (
	StatusViolation = "violation"
	StatusAllowed   = "allowed"
	StatusInfo      = "info"
	StatusDropped   = "dropped"
)

// Decision is how the policy treats a flow and why, with the settings
// that would change it.
type Decision struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	// Allowed is the flow's Allowed text when the status is allowed.
	Allowed string   `json:"-"`
	Changes []string `json:"changes,omitempty"`
}

// sets are a configuration's policy lists, resolved per class.
type sets struct {
	ignore, ignoreClass   map[string]bool
	failOn, safe, guarded map[string]map[string]bool
}

func (e Evaluator) sets() sets {
	p := e.Config.Policy
	st := sets{
		ignore: toSet(p.IgnoreDataTypes), ignoreClass: toSet(p.IgnoreClasses),
		failOn: map[string]map[string]bool{"": toSet(p.FailOn)}, safe: map[string]map[string]bool{"": toSet(p.SafeTransforms)},
		guarded: map[string]map[string]bool{"": toSet(p.ConsentGuarded)},
	}
	for class, cp := range p.Classes {
		if cp.FailOn != nil {
			st.failOn[class] = toSet(cp.FailOn)
		}
		if cp.SafeTransforms != nil {
			st.safe[class] = toSet(cp.SafeTransforms)
		}
		if cp.ConsentGuarded != nil {
			st.guarded[class] = toSet(cp.ConsentGuarded)
		}
	}
	return st
}

func forClass(m map[string]map[string]bool, class string) map[string]bool {
	if s, ok := m[class]; ok {
		return s
	}
	return m[""]
}

// decide evaluates one flow without changing it.
func (e Evaluator) decide(st sets, f *finding.Flow) Decision {
	c := e.Config
	p := c.Policy
	dt := e.Catalog.Lookup(f.DataType)
	class := dt.Class
	failOn := forClass(st.failOn, class)
	switch {
	case st.ignore[f.DataType]:
		return Decision{Status: StatusDropped, Reason: fmt.Sprintf("policy.ignore_data_types lists %s", f.DataType)}
	case st.ignoreClass[class]:
		return Decision{Status: StatusDropped, Reason: fmt.Sprintf("policy.ignore_classes lists %s", class)}
	case f.Confidence < c.MinConfidence:
		return Decision{Status: StatusDropped, Reason: fmt.Sprintf("confidence %.2f is below min_confidence %.2f", f.Confidence, c.MinConfidence),
			Changes: []string{fmt.Sprintf("`min_confidence: %.2f` or lower would show it", floor2(f.Confidence))}}
	case f.Dest.FirstParty:
		return Decision{Status: StatusInfo, Reason: fmt.Sprintf("%s is a first-party host (first_party_domains)", f.Dest.Host),
			Changes: []string{fmt.Sprintf("removing %s from `first_party_domains` would make it a violation", f.Dest.Host)}}
	case !failOn[f.Dest.Kind]:
		return Decision{Status: StatusInfo, Reason: fmt.Sprintf("the destination kind %s is not in %s", f.Dest.Kind, failOnKey(p, class)),
			Changes: []string{fmt.Sprintf("adding %s to `%s` would make it a violation", f.Dest.Kind, failOnKey(p, class))}}
	case f.Confidence < p.MinConfidence:
		return Decision{Status: StatusInfo, Reason: fmt.Sprintf("confidence %.2f is below policy.min_confidence %.2f", f.Confidence, p.MinConfidence),
			Changes: []string{fmt.Sprintf("`policy.min_confidence: %.2f` or lower would make it a violation", floor2(f.Confidence))}}
	case anySafe(f.Transforms, forClass(st.safe, class)):
		key := classKey(p, class, "safe_transforms", func(cp config.ClassPolicy) bool { return cp.SafeTransforms != nil })
		return Decision{Status: StatusAllowed, Allowed: "transform: " + strings.Join(f.Transforms, ","),
			Reason:  fmt.Sprintf("it was transformed (%s) on the way, and `%s` accepts that", strings.Join(f.Transforms, ", "), key),
			Changes: []string{fmt.Sprintf("removing %s from `%s` would make it a violation", strings.Join(f.Transforms, " and "), key)}}
	case len(f.Guards) > 0 && forClass(st.guarded, class)[f.Dest.Kind]:
		key := classKey(p, class, "consent_guarded", func(cp config.ClassPolicy) bool { return cp.ConsentGuarded != nil })
		return Decision{Status: StatusAllowed, Allowed: "consent: " + strings.Join(f.Guards, "; "),
			Reason:  fmt.Sprintf("the sink runs behind a consent check (%s), and `%s` lists %s", strings.Join(f.Guards, "; "), key, f.Dest.Kind),
			Changes: []string{fmt.Sprintf("removing %s from `%s` would make it a violation", f.Dest.Kind, key)}}
	}
	if a := matchAllow(p.Allow, f); a != nil {
		d := Decision{Status: StatusAllowed, Allowed: "allow", Reason: "a `policy.allow` entry matches it: " + allowText(a),
			Changes: []string{"removing that `policy.allow` entry would make it a violation"}}
		if a.Reason != "" {
			d.Allowed = "allow: " + a.Reason
		}
		return d
	}
	d := Decision{Status: StatusViolation, Reason: fmt.Sprintf("%s is in %s, confidence %.2f is at least policy.min_confidence %.2f, and nothing accepts it",
		f.Dest.Kind, failOnKey(p, class), f.Confidence, p.MinConfidence)}
	if f.Dest.Host != "" && (f.Dest.Kind == "network" || f.Dest.Kind == "third_party") {
		d.Changes = append(d.Changes, fmt.Sprintf("`first_party_domains: [%s]` would make it first party, which is not a violation", f.Dest.Host))
	}
	if len(f.Guards) > 0 {
		d.Changes = append(d.Changes, fmt.Sprintf("`policy.consent_guarded: [%s]` would accept it: the sink runs behind %s", f.Dest.Kind, strings.Join(f.Guards, "; ")))
	}
	if len(f.Transforms) > 0 {
		d.Changes = append(d.Changes, fmt.Sprintf("adding %s to `policy.safe_transforms` would accept it", strings.Join(f.Transforms, " or ")))
	}
	if f.Confidence-p.MinConfidence < 0.1 {
		d.Changes = append(d.Changes, fmt.Sprintf("`policy.min_confidence` above %.2f would make it informational", f.Confidence))
	}
	scope := f.Dest.Kind + " flow"
	if strings.HasPrefix(failOnKey(p, class), "policy.classes.") {
		scope = class + " flow into " + f.Dest.Kind
	}
	d.Changes = append(d.Changes, fmt.Sprintf("removing %s from `%s` would make every %s informational", f.Dest.Kind, failOnKey(p, class), scope))
	return d
}

// classKey names a per-class setting when the class overrides it.
func classKey(p config.Policy, class, name string, set func(config.ClassPolicy) bool) string {
	if cp, ok := p.Classes[class]; ok && set(cp) {
		return "policy.classes." + class + "." + name
	}
	return "policy." + name
}

// allowText writes an allow entry as it appears in the config.
func allowText(a *config.Allow) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+": "+v)
		}
	}
	add("sink", a.Sink)
	if len(a.DataTypes) > 0 {
		add("data_types", "["+strings.Join(a.DataTypes, ", ")+"]")
	}
	add("dest_host", a.DestHost)
	if len(a.DestKinds) > 0 {
		add("dest_kinds", "["+strings.Join(a.DestKinds, ", ")+"]")
	}
	add("path", a.Path)
	add("reason", fmt.Sprintf("%q", a.Reason))
	if a.Reason == "" {
		parts = parts[:len(parts)-1]
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// failOnKey names the setting that decides the flow's destination kinds.
func failOnKey(p config.Policy, class string) string {
	if cp, ok := p.Classes[class]; ok && cp.FailOn != nil {
		return "policy.classes." + class + ".fail_on"
	}
	return "policy.fail_on"
}

func floor2(x float64) float64 { return math.Floor(x*100) / 100 }

// Decide explains how the policy treats a flow.
func (e Evaluator) Decide(f *finding.Flow) Decision {
	return e.decide(e.sets(), f)
}

// Apply filters flows and literals by the config, then sets Class,
// Violation, Severity and Allowed on what remains. A class's entry in
// policy.classes overrides fail_on and safe_transforms for its data.
func (e Evaluator) Apply(flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal) {
	st := e.sets()
	var outF []*finding.Flow
	for _, f := range flows {
		d := e.decide(st, f)
		if d.Status == StatusDropped {
			continue
		}
		dt := e.Catalog.Lookup(f.DataType)
		f.Class = dt.Class
		f.Severity = e.flowSeverity(f, dt)
		f.Violation = d.Status == StatusViolation
		f.Allowed = d.Allowed
		outF = append(outF, f)
	}
	ignore, ignoreClass := st.ignore, st.ignoreClass
	p := e.Config.Policy
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

// Decide explains how the policy of cfg treats a flow (see
// Evaluator.Decide).
func (p Policies) Decide(cfg *config.Config, f *finding.Flow) Decision {
	return Evaluator{Config: cfg, Catalog: p.Catalog}.Decide(f)
}

// Apply evaluates findings under cfg (see Evaluator.Apply).
func (p Policies) Apply(cfg *config.Config, flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal) {
	return Evaluator{
		Config:  cfg,
		Catalog: p.Catalog,
	}.Apply(flows, lits)
}
