// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// Text that labels the value after it: "credit card: " + cc,
// "phone=$phone", log.Printf("user email: %s", e). The words before a
// trailing ':' or '=' name what follows, the way a map key names its
// value.

// placeholder matches a format verb or template placeholder.
var placeholder = regexp.MustCompile(`%[-+# 0-9.*]*[a-zA-Z]|\{\d*\}`)

// labelStopWords are left out of a label: "password is: ", "the email = ".
var labelStopWords = map[string]bool{"is": true, "was": true, "are": true, "were": true, "the": true, "a": true, "an": true, "of": true, "new": true, "old": true}

// constOf returns the literal v holds: a constant, or a copy of one (an
// argument label in Swift binds the value to a variable of that name).
func constOf(fn *ir.Func, defs []int, v ir.VarID) (string, bool) {
	for depth := 0; depth < 4 && v >= 0 && int(v) < len(fn.Vars); depth++ {
		if fn.Vars[v].IsConst() {
			return *fn.Vars[v].Const, true
		}
		if int(v) >= len(defs) || defs[v] < 0 {
			break
		}
		in := &fn.Instrs[defs[v]]
		if in.Op != ir.OpAssign || len(in.Args) != 1 {
			break
		}
		v = in.Args[0]
	}
	return "", false
}

// textLabel classifies the label at the end of text, if it ends with one.
func (a *analyzer) textLabel(text string) (string, float64, bool) {
	t := strings.TrimRight(text, " \t")
	if !strings.HasSuffix(t, ":") && !strings.HasSuffix(t, "=") {
		return "", 0, false
	}
	t = strings.TrimRight(t, ":= \t")
	words := strings.FieldsFunc(t, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
	})
	for len(words) > 0 && labelStopWords[strings.ToLower(words[len(words)-1])] {
		words = words[:len(words)-1]
	}
	for n := min(3, len(words)); n >= 1; n-- {
		phrase := strings.Join(words[len(words)-n:], "_")
		if m, ok := a.opts.Names.Key(phrase); ok {
			return m.DataType, m.Conf * 0.85, true
		}
	}
	return "", 0, false
}

// textLabels labels the values that follow labelled text among args (a
// concatenation or template), and the arguments that fill the
// placeholders of a format string: arg index -> facts.
func (a *analyzer) textLabels(fn *ir.Func, defs []int, args []ir.VarID, pos ir.Pos) map[int][]*fact {
	var out map[int][]*fact
	label := func(i int, text string) {
		dt, conf, ok := a.textLabel(text)
		if !ok || i >= len(args) || args[i] < 0 {
			return
		}
		if _, isConst := constOf(fn, defs, args[i]); isConst {
			return
		}
		if out == nil {
			out = map[int][]*fact{}
		}
		out[i] = append(out[i], &fact{dt: dt, param: -1, src: pos, desc: fmt.Sprintf("labelled %q", strings.TrimSpace(text)), path: []ir.Pos{pos}, conf: conf})
	}
	for i, v := range args {
		text, ok := constOf(fn, defs, v)
		if !ok {
			continue
		}
		// A format string: the text before each placeholder labels the
		// argument that fills it.
		if locs := placeholder.FindAllStringIndex(text, -1); len(locs) > 0 {
			prev := 0
			for k, l := range locs {
				label(i+1+k, text[prev:l[0]])
				prev = l[1]
			}
			continue
		}
		label(i+1, text)
	}
	return out
}
