// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// consentWords name a check that the user agreed to processing: a sink
// that runs only when such a check passed is reported as guarded.
var consentWords = []string{"consent", "optedin", "optin", "trackingallowed", "trackingenabled", "trackingauthorized", "allowtracking",
	"cantrack", "analyticsenabled", "analyticsallowed", "gdpr"}

// foldName lower-cases a name and drops its separators: has_consent and
// hasConsent both read hasconsent.
func foldName(name string) string { return strings.ToLower(separators.Replace(name)) }

var separators = strings.NewReplacer("_", "", "-", "")

func consentName(name string) bool {
	n := foldName(name)
	for _, w := range consentWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// consentCheck reports whether v is the result of a consent check
// (hasConsent(), user.optedIn, analyticsEnabled) and whether it is true
// when consent was given (false for !hasConsent()).
// A call of a helper that returns a consent check (helpers) is one too.
func consentCheck(fn *ir.Func, defs []int, v ir.VarID, depth int, helpers map[string]string) (desc string, positive, ok bool) {
	if v < 0 || int(v) >= len(fn.Vars) || depth > 4 {
		return "", false, false
	}
	if name := fn.Vars[v].Name; name != "" && consentName(name) {
		return name, true, true
	}
	if defs[v] < 0 {
		return "", false, false
	}
	in := &fn.Instrs[defs[v]]
	switch in.Op {
	case ir.OpCall:
		if in.Call != nil && consentName(in.Call.Name) {
			return in.Call.Name + "()", true, true
		}
		if in.Call != nil && helpers[in.Call.Target] != "" {
			return fmt.Sprintf("%s() (%s)", in.Call.Name, helpers[in.Call.Target]), true, true
		}
	case ir.OpLoad:
		if consentName(in.Field) {
			return in.Field, true, true
		}
	case ir.OpCompute:
		if in.Operator == "!" && len(in.Args) == 1 {
			d, p, ok := consentCheck(fn, defs, in.Args[0], depth+1, helpers)
			return d, !p, ok
		}
		if in.Operator == "&&" || in.Operator == "and" {
			for _, a := range in.Args {
				if d, p, ok := consentCheck(fn, defs, a, depth+1, helpers); ok && p {
					return d, true, true
				}
			}
		}
	case ir.OpAssign:
		if len(in.Args) == 1 {
			return consentCheck(fn, defs, in.Args[0], depth+1, helpers)
		}
	}
	return "", false, false
}

// guards returns, per block, the consent checks that must have passed for
// control to reach it: a branch on a consent check whose "consent given"
// successor is entered only from the branch and dominates the block.
func guards(fn *ir.Func, helpers map[string]string) [][]string {
	if len(fn.Blocks) == 0 {
		return nil
	}
	defs := definitions(fn)
	var out [][]string
	var idom []int32
	var preds [][]int32
	for _, blk := range fn.Blocks {
		if blk.Term != ir.TermIf || len(blk.Succs) != 2 {
			continue
		}
		desc, positive, ok := consentCheck(fn, defs, blk.Cond, 0, helpers)
		if !ok {
			continue
		}
		if idom == nil {
			idom, preds = fn.Dominators(), fn.Preds()
			out = make([][]string, len(fn.Blocks))
		}
		s := blk.Succs[0]
		if !positive {
			s = blk.Succs[1]
		}
		if int(s) >= len(preds) || len(preds[s]) != 1 {
			continue
		}
		label := "consent check " + desc
		if p := condPos(fn, defs, blk.Cond); p.IsValid() {
			label = fmt.Sprintf("%s at %s", label, p)
		}
		for g := range fn.Blocks {
			if ir.Dominates(idom, s, int32(g)) {
				out[g] = append(out[g], label)
			}
		}
	}
	return out
}

func condPos(fn *ir.Func, defs []int, v ir.VarID) ir.Pos {
	if v >= 0 && int(v) < len(defs) && defs[v] >= 0 {
		return fn.Instrs[defs[v]].Pos
	}
	if v >= 0 && int(v) < len(fn.Vars) {
		return fn.Vars[v].Pos
	}
	return ir.Pos{}
}

// definitions maps each variable to the index of its (first) defining
// instruction, or -1.
func definitions(fn *ir.Func) []int {
	defs := make([]int, len(fn.Vars))
	for i := range defs {
		defs[i] = -1
	}
	for i := range fn.Instrs {
		if d := fn.Instrs[i].Dst; d >= 0 && int(d) < len(defs) && !fn.Vars[d].Cell && defs[d] < 0 {
			defs[d] = i
		}
	}
	return defs
}

// consentHelpers finds the functions that return a consent check, such as
// fun canTrack() = consents.hasConsent() && settings.analyticsOn: a
// branch on a call of one is a consent check. It maps each to the check
// it returns.
func consentHelpers(funcs []*ir.Func) map[string]string {
	out := map[string]string{}
	for round := 0; round < 4; round++ {
		grew := false
		for _, fn := range funcs {
			if out[fn.ID] != "" {
				continue
			}
			defs := definitions(fn)
			desc, returns := "", 0
			for i := range fn.Instrs {
				in := &fn.Instrs[i]
				if in.Op != ir.OpReturn {
					continue
				}
				returns++
				d, positive, ok := "", false, false
				if len(in.Args) == 1 {
					d, positive, ok = consentCheck(fn, defs, in.Args[0], 0, out)
				}
				if !ok || !positive {
					returns = -1
					break
				}
				desc = d
			}
			if returns > 0 {
				out[fn.ID] = desc
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	return out
}

// inheritedGuards finds, per function, the consent checks guarding every
// place it is called from (sites lists them: the calling function and
// block), so that a sink in a function only ever called after consent was
// given is reported with that check. A function with no known caller
// inherits nothing: it may be called from anywhere.
func inheritedGuards(sites map[string][]callSite, blocks map[string][][]string) map[string][]string {
	out := map[string][]string{}
	for round := 0; round < 8; round++ {
		grew := false
		for _, callee := range slices.Sorted(maps.Keys(sites)) {
			var common []string
			for i, s := range sites[callee] {
				var here []string
				if bg := blocks[s.fn]; s.block >= 0 && int(s.block) < len(bg) {
					here = append(here, bg[s.block]...)
				}
				here = mergeXf(here, out[s.fn]...)
				if i == 0 {
					common = here
				} else {
					common = intersect(common, here)
				}
				if len(common) == 0 {
					break
				}
			}
			common = mergeXf(nil, common...)
			if !slices.Equal(common, out[callee]) {
				out[callee] = common
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	return out
}

type callSite struct {
	fn    string
	block int32
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
