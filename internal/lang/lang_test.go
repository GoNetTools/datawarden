// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package lang

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestTableIsConsistent guards the table itself: a new entry must not
// reuse another language's name, alias or extension.
func TestTableIsConsistent(t *testing.T) {
	names := map[string]string{}
	exts := map[string]string{}
	var order []string
	for _, l := range All() {
		order = append(order, l.Name)
		if l.Name == "" || l.Name != strings.ToLower(l.Name) {
			t.Errorf("name %q must be non-empty and lower-case", l.Name)
		}
		if len(l.Extensions) == 0 {
			t.Errorf("%s: no extensions", l.Name)
		}
		for _, n := range append([]string{l.Name}, l.Aliases...) {
			if other, ok := names[n]; ok {
				t.Errorf("%q is used by both %s and %s", n, other, l.Name)
			}
			names[n] = l.Name
		}
		for _, e := range l.Extensions {
			if !strings.HasPrefix(e, ".") || e != strings.ToLower(e) {
				t.Errorf("%s: extension %q must be lower-case and start with a dot", l.Name, e)
			}
			if other, ok := exts[e]; ok {
				t.Errorf("extension %s is claimed by both %s and %s", e, other, l.Name)
			}
			exts[e] = l.Name
		}
	}
	if !sort.StringsAreSorted(order) {
		t.Errorf("keep the table sorted by name: %v", order)
	}
}

func TestOfPath(t *testing.T) {
	for p, want := range map[string]string{
		"a.go": Go, "A.kt": Kotlin, "build.gradle.kts": Kotlin, "B.java": Java, "c.tsx": TypeScript, "d.js": TypeScript,
		"e.d.ts": "", "E.D.TS": "", "f.mjs": TypeScript, "x.proto": Proto, "m.sql": SQL, "r.md": "", "Makefile": "", "dir.go/README": "",
	} {
		if got := OfPath(p); got != want {
			t.Errorf("OfPath(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestLookupAndNormalize(t *testing.T) {
	for in, want := range map[string]string{"golang": Go, "KT": Kotlin, "js": TypeScript, " TypeScript ": TypeScript, "protobuf": Proto, "cobol": "cobol"} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := Lookup("cobol"); ok {
		t.Error("unknown language found")
	}
	if !IsCode("kotlin") || !IsCode("js") || IsCode("sql") || IsCode("cobol") {
		t.Error("IsCode")
	}
	if got := CodeNames(); !reflect.DeepEqual(got, []string{Go, Java, Kotlin, TypeScript}) {
		t.Errorf("CodeNames() = %v", got)
	}
}

func TestTestFilesAndIgnoredPaths(t *testing.T) {
	cases := []struct {
		path string
		test bool
	}{
		{"pkg/x_test.go", true}, {"pkg/x.go", false},
		{"app/FooTest.kt", true}, {"app/FooTests.java", true}, {"app/Foo.java", false},
		{"web/app.ts", false},
	}
	for _, c := range cases {
		l, _ := ForPath(c.path)
		if got := l.IsTestFile(c.path[strings.LastIndex(c.path, "/")+1:]); got != c.test {
			t.Errorf("IsTestFile(%s) = %v", c.path, got)
		}
	}
	golang, _ := Lookup(Go)
	for p, want := range map[string]bool{"a/b.go": false, "testdata/x.go": true, "a/_gen/x.go": true, "a/.cache/x.go": true, "_x.go": false} {
		if got := golang.Ignored(p); got != want {
			t.Errorf("Go Ignored(%s) = %v", p, got)
		}
	}
	kotlin, _ := Lookup(Kotlin)
	if kotlin.Ignored("testdata/A.kt") {
		t.Error("only Go ignores testdata")
	}
}
