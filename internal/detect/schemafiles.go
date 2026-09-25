// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/ir"
)

var (
	reProtoPkg    = regexp.MustCompile(`^\s*package\s+([\w.]+)\s*;`)
	reProtoBlock  = regexp.MustCompile(`^\s*(message|enum|oneof|service|extend)\s+(\w+)\s*\{`)
	reProtoField  = regexp.MustCompile(`^\s*(?:repeated\s+|optional\s+|required\s+)?(map\s*<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*\d+`)
	reProtoPIIOpt = regexp.MustCompile(`\(\s*(?:[\w.]*\.)?pii\s*\)\s*=\s*"([^"]*)"`)
	reLinePII     = regexp.MustCompile(`(?i)\bpii\s*:\s*([\w\-]+)`)
)

// ParseProto extracts messages and fields from a .proto file. Fields can be
// annotated with a `[(pii) = "email"]` option or a `// pii: email` comment.
func ParseProto(path string, src []byte) []*ir.TypeDecl {
	var out []*ir.TypeDecl
	pkg := ""
	type frame struct {
		kind string
		decl *ir.TypeDecl
		name string
	}
	var stack []frame
	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		code := line
		comment := ""
		if j := strings.Index(line, "//"); j >= 0 {
			code, comment = line[:j], line[j:]
		}
		if m := reProtoPkg.FindStringSubmatch(code); m != nil {
			pkg = m[1]
			continue
		}
		if m := reProtoBlock.FindStringSubmatch(code); m != nil {
			fr := frame{kind: m[1], name: m[2]}
			if m[1] == "message" {
				parts := []string{}
				if pkg != "" {
					parts = append(parts, pkg)
				}
				for _, f := range stack {
					if f.kind == "message" {
						parts = append(parts, f.name)
					}
				}
				parts = append(parts, m[2])
				fr.decl = &ir.TypeDecl{Name: strings.Join(parts, "."), Kind: "proto", Lang: "proto", Pos: ir.Pos{File: path, Line: i + 1}}
				out = append(out, fr.decl)
			}
			stack = append(stack, fr)
			if strings.Count(code, "}") >= strings.Count(code, "{") {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			owner := top.decl
			if top.kind == "oneof" {
				for k := len(stack) - 1; k >= 0; k-- {
					if stack[k].decl != nil {
						owner = stack[k].decl
						break
					}
				}
			}
			if owner != nil && top.kind != "enum" {
				if m := reProtoField.FindStringSubmatch(code); m != nil && !isProtoKeyword(m[1]) {
					f := ir.Field{Name: m[2], Type: m[1], Pos: ir.Pos{File: path, Line: i + 1}, Tags: map[string]string{}}
					if o := reProtoPIIOpt.FindStringSubmatch(code); o != nil {
						f.Tags["pii"] = o[1]
					} else if c := reLinePII.FindStringSubmatch(comment); c != nil {
						f.Tags["pii"] = c[1]
					}
					owner.Fields = append(owner.Fields, f)
				}
			}
		}
		for n := strings.Count(code, "}"); n > 0 && len(stack) > 0; n-- {
			stack = stack[:len(stack)-1]
		}
	}
	return out
}

func isProtoKeyword(s string) bool {
	switch s {
	case "option", "reserved", "extensions", "rpc", "returns", "import", "syntax", "package":
		return true
	}
	return false
}

var (
	reCreateTable = regexp.MustCompile(`(?is)\bcreate\s+(?:temporary\s+|temp\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w."\x60\[\]]+)\s*\(`)
	reAlterAdd    = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."\x60\[\]]+)\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?([\w"\x60\[\]]+)\s+([\w()]+)`)
	reSQLComment  = regexp.MustCompile(`(?i)comment\s+(?:on\s+column\s+[\w."]+\s+is\s+)?'([^']*)'`)
)

var sqlConstraintWords = set("primary", "constraint", "unique", "foreign", "key", "index", "check", "exclude", "fulltext", "spatial", "period", "like")

// ParseSQL extracts tables and columns from CREATE TABLE / ALTER TABLE ADD
// COLUMN statements in migrations. A `COMMENT 'pii:email'` on a column is
// treated as an explicit hint.
func ParseSQL(path string, src []byte) []*ir.TypeDecl {
	text, linePII := blankSQLComments(string(src))
	lineAt := lineIndex(text)
	var out []*ir.TypeDecl
	byName := map[string]*ir.TypeDecl{}
	get := func(name string, off int) *ir.TypeDecl {
		n := unquoteSQL(name)
		if t, ok := byName[n]; ok {
			return t
		}
		t := &ir.TypeDecl{Name: "table:" + n, Kind: "table", Lang: "sql", Pos: ir.Pos{File: path, Line: lineAt(off)}}
		byName[n] = t
		out = append(out, t)
		return t
	}
	for _, m := range reCreateTable.FindAllStringSubmatchIndex(text, -1) {
		t := get(text[m[2]:m[3]], m[0])
		body, bodyStart := balanced(text, m[1]-1)
		for _, col := range splitTopLevel(body, bodyStart) {
			def := strings.TrimSpace(col.text)
			if def == "" {
				continue
			}
			words := strings.Fields(def)
			if len(words) < 2 || sqlConstraintWords[strings.ToLower(words[0])] {
				continue
			}
			f := ir.Field{Name: unquoteSQL(words[0]), Type: strings.ToLower(words[1]), Pos: ir.Pos{File: path, Line: lineAt(col.off + leadingSpace(col.text))}, Tags: map[string]string{"column": unquoteSQL(words[0])}}
			if c := reSQLComment.FindStringSubmatch(def); c != nil {
				if p := reLinePII.FindStringSubmatch(c[1]); p != nil {
					f.Tags["pii"] = p[1]
				}
			} else if dt, ok := linePII[f.Pos.Line]; ok {
				f.Tags["pii"] = dt
			}
			t.Fields = append(t.Fields, f)
		}
	}
	for _, m := range reAlterAdd.FindAllStringSubmatchIndex(text, -1) {
		t := get(text[m[2]:m[3]], m[0])
		name := unquoteSQL(text[m[4]:m[5]])
		t.Fields = append(t.Fields, ir.Field{Name: name, Type: strings.ToLower(text[m[6]:m[7]]), Pos: ir.Pos{File: path, Line: lineAt(m[4])}, Tags: map[string]string{"column": name}})
	}
	return out
}

func leadingSpace(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t\r\n"))
}

func unquoteSQL(s string) string {
	s = strings.Trim(s, "\"`[]")
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = strings.Trim(s[i+1:], "\"`[]")
	}
	return strings.ToLower(s)
}

// balanced returns the text between the '(' at open and its matching ')'.
func balanced(s string, open int) (string, int) {
	depth := 0
	inStr := byte(0)
	for i := open; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], open + 1
			}
		}
	}
	return s[open+1:], open + 1
}

type piece struct {
	text string
	off  int
}

func splitTopLevel(s string, base int) []piece {
	var out []piece
	depth, start := 0, 0
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, piece{s[start:i], base + start})
				start = i + 1
			}
		}
	}
	out = append(out, piece{s[start:], base + start})
	return out
}

func lineIndex(text string) func(off int) int {
	var starts []int
	starts = append(starts, 0)
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return func(off int) int {
		lo, hi := 0, len(starts)-1
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if starts[mid] <= off {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo + 1
	}
}

// blankSQLComments replaces "-- ..." comments with spaces (keeping offsets)
// and returns any "pii: <type>" hints found in them, keyed by line.
func blankSQLComments(text string) (string, map[int]string) {
	b := []byte(text)
	hints := map[int]string{}
	line := 1
	inStr := byte(0)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' {
			line++
			continue
		}
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		if c == '\'' {
			inStr = c
			continue
		}
		if c == '-' && i+1 < len(b) && b[i+1] == '-' {
			j := i
			for j < len(b) && b[j] != '\n' {
				j++
			}
			if m := reLinePII.FindStringSubmatch(string(b[i:j])); m != nil {
				hints[line] = m[1]
			}
			for k := i; k < j; k++ {
				b[k] = ' '
			}
			i = j - 1
		}
	}
	return string(b), hints
}
