// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/ir"
)

// Hit is a rule that matched a call site.
type Hit struct {
	Rule *Rule
	// Conf is 1.0 for a fully resolved callee and lower for heuristic
	// matches on unresolved receivers.
	Conf float64
	How  string
}

// Match returns the rules of the given kind that match the call.
func (s *Set) Match(lang, kind string, c *ir.Call) []Hit {
	if c == nil {
		return nil
	}
	var hits []Hit
	named := s.byName[c.Name]
	cands := make([]*Rule, 0, len(named)+len(s.wild))
	cands = append(append(cands, named...), s.wild...)
	seen := map[*Rule]bool{}
	for _, r := range cands {
		if seen[r] || r.Kind != kind || !r.hasLang(lang) {
			continue
		}
		seen[r] = true
		if h, ok := r.match(c); ok {
			hits = append(hits, h)
		}
	}
	return hits
}

func (r *Rule) hasLang(l string) bool {
	for _, x := range r.Lang {
		if x == l || x == "*" {
			return true
		}
	}
	return false
}

func (r *Rule) match(c *ir.Call) (Hit, bool) {
	best := Hit{}
	for i, re := range r.callRes {
		if c.Callee != "" {
			if re.MatchString(c.Callee) {
				return Hit{Rule: r, Conf: 1.0, How: "resolved"}, true
			}
			continue
		}
		if !nameMatches(r.names[i], c.Name) {
			continue
		}
		ts := r.typeSegs[i]
		wildName := strings.Contains(r.names[i], "*")
		if !isTypeName(ts) || wildName {
			ts = "" // only class-like segments (Sentry, Log, FirebaseCrashlytics) identify a receiver
		}
		switch {
		case wildName && r.recvRe == nil:
		case c.RecvType != "" && ts != "" && lastSeg(c.RecvType) == ts:
			best = maxHit(best, Hit{Rule: r, Conf: 0.8, How: "receiver type " + c.RecvType})
		case c.RecvText != "" && ts != "" && lastSeg(c.RecvText) == ts:
			best = maxHit(best, Hit{Rule: r, Conf: 0.8, How: "receiver " + c.RecvText})
		case r.recvRe != nil && c.RecvText != "" && r.recvRe.MatchString(c.RecvText):
			best = maxHit(best, Hit{Rule: r, Conf: 0.75, How: "receiver name " + c.RecvText})
		case r.MatchBare && !wildName && (c.RecvText == "" || c.RecvText == "this"):
			best = maxHit(best, Hit{Rule: r, Conf: 0.6, How: "bare call " + c.Name})
		}
	}
	return best, best.Rule != nil
}

func nameMatches(pattern, name string) bool {
	if pattern == name || pattern == "*" {
		return true
	}
	if strings.Contains(pattern, "*") {
		re, err := globToRegexp(pattern)
		return err == nil && re.MatchString(name)
	}
	return false
}

func maxHit(a, b Hit) Hit {
	if b.Conf > a.Conf {
		return b
	}
	return a
}

func lastSeg(s string) string {
	s = strings.TrimLeft(s, "*&")
	if i := strings.IndexAny(s, "<["); i > 0 {
		s = s[:i]
	}
	if i := strings.LastIndexAny(s, "./"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func isTypeName(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z' && !strings.Contains(s, "*")
}
