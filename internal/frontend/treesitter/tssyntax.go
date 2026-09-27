// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package treesitter

import "bytes"

// tsNormalize blanks the type arguments of tagged templates
// (sql<{ id: string }>`SELECT ...`, as in Kysely), which
// tree-sitter-typescript 0.23 cannot parse: it reads them as comparisons
// and loses the call. Type arguments move no data. Blanking replaces bytes
// with spaces and keeps newlines, so every position in the file stays
// where it was. Strings, templates and comments are left alone.
func tsNormalize(src []byte) []byte {
	s := &tsScanner{src: src, code: make([]bool, len(src))}
	s.scan(0, false)
	var out []byte
	for _, t := range s.templates {
		from, to, ok := s.typeArgsBefore(t)
		if !ok {
			continue
		}
		if out == nil {
			out = append([]byte(nil), src...)
		}
		for i := from; i < to; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	if out == nil {
		return src
	}
	return out
}

// typeArgsBefore returns the type argument list <...> ending right before
// the template starting at t, when an identifier directly precedes it
// (tag<T>`...`, not x => `...` or <T>`...`).
func (s *tsScanner) typeArgsBefore(t int) (from, to int, ok bool) {
	j := t - 1
	for j >= 0 && (s.src[j] == ' ' || s.src[j] == '\t') {
		j--
	}
	if j < 1 || s.src[j] != '>' || !s.code[j] || s.src[j-1] == '=' {
		return 0, 0, false
	}
	depth := 0
	for k := j; k >= 0 && j-k < 4096; k-- {
		if !s.code[k] {
			continue
		}
		switch s.src[k] {
		case '>':
			if k > 0 && s.src[k-1] == '=' {
				k-- // => in a function type
				continue
			}
			depth++
		case '<':
			depth--
			if depth == 0 {
				if k == 0 || !(isWordByte(s.src[k-1]) || s.src[k-1] == '$') {
					return 0, 0, false
				}
				return k, j + 1, true
			}
		}
	}
	return 0, 0, false
}

// tsScanner marks the bytes of a TypeScript or JavaScript file that are
// code, not strings, templates or comments, and records where templates
// start. Code inside ${...} counts as code. Regular expression literals are
// not recognized and count as code.
type tsScanner struct {
	src       []byte
	code      []bool
	templates []int
}

// scan marks code from i. When nested (inside ${...}), it stops at the
// unmatched } and returns its index.
func (s *tsScanner) scan(i int, nested bool) int {
	depth := 0
	for i < len(s.src) {
		c := s.src[i]
		switch {
		case c == '/' && i+1 < len(s.src) && s.src[i+1] == '/':
			for i < len(s.src) && s.src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s.src) && s.src[i+1] == '*':
			end := bytes.Index(s.src[i+2:], []byte("*/"))
			if end < 0 {
				return len(s.src)
			}
			i += 2 + end + 2
		case c == '\'' || c == '"':
			i = s.quoted(i, c)
		case c == '`':
			s.templates = append(s.templates, i)
			i = s.template(i)
		default:
			if c == '{' {
				depth++
			} else if c == '}' {
				if depth == 0 && nested {
					return i
				}
				depth--
			}
			s.code[i] = true
			i++
		}
	}
	return i
}

func (s *tsScanner) quoted(i int, q byte) int {
	for i++; i < len(s.src) && s.src[i] != q && s.src[i] != '\n'; i++ {
		if s.src[i] == '\\' {
			i++
		}
	}
	return i + 1
}

// template skips the template starting at i, scanning its substitutions
// as code, and returns the index after its closing backtick.
func (s *tsScanner) template(i int) int {
	for i++; i < len(s.src); {
		switch {
		case s.src[i] == '\\':
			i += 2
		case s.src[i] == '`':
			return i + 1
		case s.src[i] == '$' && i+1 < len(s.src) && s.src[i+1] == '{':
			i = s.scan(i+2, true) + 1
		default:
			i++
		}
	}
	return i
}
