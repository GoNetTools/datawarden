// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package lang is the one description of the languages datawarden reads:
// their names, aliases, file extensions and test-file conventions. The file
// walker, rule and config validation, and the scanner all look languages
// up here, so adding a language starts with one entry in the table below.
package lang

import (
	"path"
	"sort"
	"strings"
)

// Canonical language names, as used in rules, configuration and reports.
const (
	Go         = "go"
	Kotlin     = "kotlin"
	Java       = "java"
	TypeScript = "typescript"
	Python     = "python"
	Swift      = "swift"
	Proto      = "proto"
	SQL        = "sql"
)

// Kind says what datawarden does with a language's files.
type Kind int

const (
	// Code files are lowered to the IR by a frontend and analysed.
	Code Kind = iota
	// Schema files are only parsed for schema hints (protobuf, SQL).
	Schema
)

// Language describes one language.
type Language struct {
	// Name is the canonical name.
	Name string
	Kind Kind
	// Aliases are other names accepted in rules and configuration.
	Aliases []string
	// Extensions are lower-case file extensions, with the dot.
	Extensions []string
	// NotSource lists file-name suffixes that carry one of the extensions
	// but are not source code (TypeScript declaration files).
	NotSource []string
	// TestSuffixes mark test files by the end of their base name. Test
	// directories (src/test/, __tests__/) and the .test./.spec. infixes
	// apply to every language and are handled by the file walker.
	TestSuffixes []string
	// TestPrefixes mark test files by the start of their base name
	// (test_user.py), and TestNames by the whole name (conftest.py).
	TestPrefixes []string
	TestNames    []string
	// Ignore reports whether the language's own toolchain skips the file
	// (the go tool ignores testdata/, _dir/ and .dir/). May be nil.
	Ignore func(rel string) bool
}

// table lists every language. Keep it sorted by name.
var table = []Language{
	{
		Name: Go,
		Kind: Code,
		Aliases: []string{"golang"},
		Extensions: []string{".go"},
		TestSuffixes: []string{"_test.go"},
		Ignore: goIgnored
	},
	{
		Name: Java,
		Kind: Code,
		Extensions: []string{".java"},
		TestSuffixes: []string{"Test.java", "Tests.java"}
	},
	{
		Name: Kotlin,
		Kind: Code,
		Aliases: []string{"kt", "kts"},
		Extensions: []string{".kt", ".kts"},
		TestSuffixes: []string{"Test.kt", "Tests.kt"}
	},
	{
		Name: Proto,
		Kind: Schema,
		Aliases: []string{"protobuf"},
		Extensions: []string{".proto"}
	},
	{
		Name: Python,
		Kind: Code,
		Aliases: []string{"py"},
		Extensions: []string{".py"},
		TestPrefixes: []string{"test_"},
		TestSuffixes: []string{"_test.py"},
		TestNames: []string{"conftest.py"}
	},
	{
		Name: SQL,
		Kind: Schema,
		Extensions: []string{".sql"}
	},
	{
		Name: Swift,
		Kind: Code,
		Extensions: []string{".swift"},
		TestSuffixes: []string{"Tests.swift", "Test.swift"}
	},
	{
		Name: TypeScript,
		Kind: Code,
		Aliases: []string{"ts", "tsx", "javascript", "js", "jsx"},
		Extensions: []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"},
		NotSource:  []string{".d.ts", ".d.mts", ".d.cts"}
	},
}

// All returns every language, sorted by name.
func All() []Language {
	return append([]Language(nil), table...)
}

// CodeNames returns the names of the languages that have frontends,
// sorted.
func CodeNames() []string {
	var out []string
	for _, l := range table {
		if l.Kind == Code {
			out = append(out, l.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Lookup finds a language by name or alias, ignoring case.
func Lookup(name string) (Language, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, l := range table {
		if l.Name == n {
			return l, true
		}
		for _, a := range l.Aliases {
			if a == n {
				return l, true
			}
		}
	}
	return Language{}, false
}

// Normalize returns the canonical name for a name or alias, or the
// lower-cased input when the language is unknown.
func Normalize(name string) string {
	if l, ok := Lookup(name); ok {
		return l.Name
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// IsCode reports whether name (or an alias) is a language with a frontend.
func IsCode(name string) bool {
	l, ok := Lookup(name)
	return ok && l.Kind == Code
}

// OfPath returns the language of a slash-separated path by its extension,
// or "" for files datawarden does not parse.
func OfPath(rel string) string {
	l, ok := ForPath(rel)
	if !ok {
		return ""
	}
	return l.Name
}

// ForPath returns the language of a slash-separated path by its extension.
func ForPath(rel string) (Language, bool) {
	ext := strings.ToLower(path.Ext(rel))
	if ext == "" {
		return Language{}, false
	}
	lower := strings.ToLower(rel)
	for _, l := range table {
		for _, e := range l.Extensions {
			if e != ext {
				continue
			}
			for _, s := range l.NotSource {
				if strings.HasSuffix(lower, s) {
					return Language{}, false
				}
			}
			return l, true
		}
	}
	return Language{}, false
}

// IsTestFile reports whether a base name follows the language's test-file
// naming convention.
func (l Language) IsTestFile(base string) bool {
	for _, s := range l.TestSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	for _, p := range l.TestPrefixes {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	for _, n := range l.TestNames {
		if base == n {
			return true
		}
	}
	return false
}

// Ignored reports whether the language's toolchain skips the file.
func (l Language) Ignored(rel string) bool {
	return l.Ignore != nil && l.Ignore(rel)
}

// goIgnored mirrors the go tool: directories whose name starts with "."
// or "_", or is "testdata", are not part of any package.
func goIgnored(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range parts[:len(parts)-1] {
		if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "_") || p == "testdata" {
			return true
		}
	}
	return false
}
