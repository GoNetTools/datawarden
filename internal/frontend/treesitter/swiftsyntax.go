// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package treesitter

import (
	"bytes"
	"regexp"
)

// swiftNormalize blanks Swift syntax newer than the tree-sitter grammar
// knows, none of which moves data: typed throws (throws(E)), ownership
// modifiers (consuming, borrowing, sending), suppressed conformances
// (~Copyable), @unchecked, await, empty associated-value patterns
// (case .done():) and freestanding macro blocks (#Preview { ... }).
// Without it a file using them parses with errors and the code after the
// error is partly lost. Blanking replaces bytes with spaces and keeps
// newlines, so every position in the file stays where it was. Strings and
// comments are left alone.
func swiftNormalize(src []byte) []byte {
	code := swiftCodeMask(src)
	out := append([]byte(nil), src...)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	for _, re := range swiftBlanked {
		for _, m := range re.pattern.FindAllSubmatchIndex(src, -1) {
			from, to := m[2*re.group], m[2*re.group+1]
			if from < 0 || !code[from] {
				continue
			}
			if re.ok != nil && !re.ok(src, m[0], m[1]) {
				continue
			}
			blank(from, to)
		}
	}
	for _, m := range swiftMacroStart.FindAllIndex(src, -1) {
		start := m[0] + bytes.IndexByte(src[m[0]:m[1]], '#')
		if !code[start] {
			continue
		}
		blank(start, swiftMacroEnd(src, code, m[1]))
	}
	return out
}

type swiftBlank struct {
	pattern *regexp.Regexp
	group   int                                 // the submatch blanked
	ok      func(src []byte, from, to int) bool // extra check on the whole match
}

var swiftBlanked = []swiftBlank{
	// func f() throws(StoreError) -> T: the error type.
	{pattern: regexp.MustCompile(`\bthrows(\(\s*[A-Za-z_][\w.]*\s*\))`), group: 1},
	// struct Mutex<Value: ~Copyable>: ~Copyable: the tilde.
	{pattern: regexp.MustCompile(`(~)(?:Copyable|Escapable)\b`), group: 1},
	// @unchecked Sendable.
	{pattern: regexp.MustCompile(`(@unchecked)\b`), group: 1},
	// await: an expression prefix that changes no value.
	{pattern: regexp.MustCompile(`\b(await)\b`), group: 1},
	// _ v: consuming sending Value, -> sending R, borrowing func f().
	{pattern: regexp.MustCompile(`\b(consuming|borrowing|sending)[ \t]+`), group: 1, ok: swiftModifierContext},
	// case .success(): an empty associated-value list.
	{pattern: regexp.MustCompile(`\bcase[ \t]+\.[A-Za-z_]\w*(\(\))[ \t]*[:,]`), group: 1},
}

// swiftModifierContext reports whether the ownership word at from is a
// modifier: after a colon, arrow, parenthesis, comma or another modifier,
// or before a declaration keyword. A variable of that name (if sending
// { ... }) is left alone.
func swiftModifierContext(src []byte, from, to int) bool {
	if to >= len(src) || !(isWordByte(src[to]) || src[to] == '(' || src[to] == '[') {
		return false // a type, a function type or a declaration follows
	}
	prev := bytes.TrimRight(src[:from], " \t")
	if len(prev) > 0 {
		switch prev[len(prev)-1] {
		case ':', '(', ',', '>':
			return true
		}
		for _, w := range []string{"inout", "consuming", "borrowing", "sending"} {
			if bytes.HasSuffix(prev, []byte(w)) {
				return true
			}
		}
	}
	rest := bytes.TrimLeft(src[from:], "abcdefghijklmnopqrstuvwxyz")
	rest = bytes.TrimLeft(rest, " \t")
	for _, w := range []string{"func ", "init", "var ", "let ", "subscript", "mutating ", "static "} {
		if bytes.HasPrefix(rest, []byte(w)) {
			return true
		}
	}
	return false
}

// swiftMacroStart finds a freestanding macro at the start of a line:
// #Preview("Small") { ... }. Compiler directives (#if, #else, #endif,
// #available, ...) are lower case and not matched.
var swiftMacroStart = regexp.MustCompile(`(?m)^[ \t]*#[A-Z]\w*`)

// swiftMacroEnd returns the end of a macro expansion starting at i (after
// its name): an argument list, then a trailing closure, both optional.
func swiftMacroEnd(src []byte, code []bool, i int) int {
	skipSpace := func(i int) int {
		for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
			i++
		}
		return i
	}
	i = skipSpace(i)
	if i < len(src) && src[i] == '(' {
		i = swiftMatch(src, code, i, '(', ')')
	}
	j := skipSpace(i)
	if j >= len(src) || src[j] != '{' {
		return i
	}
	i = swiftMatch(src, code, j, '{', '}')
	// Further trailing closures: } timeline: { ... }
	for {
		m := swiftExtraClosure.FindIndex(src[i:])
		if m == nil || m[0] != 0 {
			return i
		}
		i = swiftMatch(src, code, i+m[1]-1, '{', '}')
	}
}

// swiftExtraClosure is a labelled trailing closure after the first one.
var swiftExtraClosure = regexp.MustCompile(`^\s*[A-Za-z_]\w*[ \t]*:[ \t]*\{`)

// swiftMatch returns the position after the bracket closing the one at i,
// counting only brackets in code.
func swiftMatch(src []byte, code []bool, i int, open, close byte) int {
	depth := 0
	for ; i < len(src); i++ {
		if !code[i] {
			continue
		}
		switch src[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(src)
}

// swiftCodeMask marks the bytes of src that are code: not inside a string
// literal or a comment. Interpolations inside strings count as strings,
// which only means they are not normalized.
func swiftCodeMask(src []byte) []bool {
	code := make([]bool, len(src))
	for i := 0; i < len(src); {
		switch {
		case bytes.HasPrefix(src[i:], []byte("//")):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case bytes.HasPrefix(src[i:], []byte("/*")):
			depth := 0
			for i < len(src) {
				if bytes.HasPrefix(src[i:], []byte("/*")) {
					depth++
					i += 2
					continue
				}
				if bytes.HasPrefix(src[i:], []byte("*/")) {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
		case bytes.HasPrefix(src[i:], []byte(`"""`)):
			end := bytes.Index(src[i+3:], []byte(`"""`))
			if end < 0 {
				return code
			}
			i += 3 + end + 3
		case src[i] == '"':
			i++
			for i < len(src) && src[i] != '"' && src[i] != '\n' {
				if bytes.HasPrefix(src[i:], []byte(`\(`)) {
					// An interpolation: its own strings do not end this one.
					depth := 0
					for i++; i < len(src) && src[i] != '\n'; i++ {
						if src[i] == '(' {
							depth++
						} else if src[i] == ')' {
							depth--
							if depth == 0 {
								break
							}
						}
					}
				} else if src[i] == '\\' {
					i++
				}
				i++
			}
			i++
		default:
			code[i] = true
			i++
		}
	}
	return code
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
