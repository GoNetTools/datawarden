// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// consentWords name a check that the user agreed to processing: a sink
// that runs only when such a check passed is reported as guarded.
var consentWords = []string{"consent", "optedin", "optin", "trackingallowed", "trackingenabled", "trackingauthorized", "allowtracking",
	"cantrack", "analyticsenabled", "analyticsallowed", "gdpr"}

func consentName(name string) bool {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
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
func consentCheck(fn *ir.Func, defs []int, v ir.VarID, depth int) (desc string, positive, ok bool) {
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
	case ir.OpLoad:
		if consentName(in.Field) {
			return in.Field, true, true
		}
	case ir.OpCompute:
		if in.Operator == "!" && len(in.Args) == 1 {
			d, p, ok := consentCheck(fn, defs, in.Args[0], depth+1)
			return d, !p, ok
		}
		if in.Operator == "&&" || in.Operator == "and" {
			for _, a := range in.Args {
				if d, p, ok := consentCheck(fn, defs, a, depth+1); ok && p {
					return d, true, true
				}
			}
		}
	case ir.OpAssign:
		if len(in.Args) == 1 {
			return consentCheck(fn, defs, in.Args[0], depth+1)
		}
	}
	return "", false, false
}

// guards returns, per block, the consent checks that must have passed for
// control to reach it: a branch on a consent check whose "consent given"
// successor is entered only from the branch and dominates the block.
func guards(fn *ir.Func) [][]string {
	if len(fn.Blocks) == 0 {
		return nil
	}
	defs := make([]int, len(fn.Vars))
	for i := range defs {
		defs[i] = -1
	}
	for i := range fn.Instrs {
		if d := fn.Instrs[i].Dst; d >= 0 && int(d) < len(defs) && !fn.Vars[d].Cell && defs[d] < 0 {
			defs[d] = i
		}
	}
	var out [][]string
	var idom []int32
	var preds [][]int32
	for _, blk := range fn.Blocks {
		if blk.Term != ir.TermIf || len(blk.Succs) != 2 {
			continue
		}
		desc, positive, ok := consentCheck(fn, defs, blk.Cond, 0)
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
