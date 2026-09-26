// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package treesitter

import (
	"strings"
	"testing"
)

func TestSwiftNormalize(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"func f() throws(StoreError) -> T {", "func f() throws" + strings.Repeat(" ", len("(StoreError)")) + " -> T {"},
		{"struct M<V: ~Copyable>: ~Copyable, @unchecked Sendable {", "struct M<V:  Copyable>:  Copyable,            Sendable {"},
		{"init(_ v: consuming sending Value) {", "init(_ v:                   Value) {"},
		{"_ body: (inout sending Value) throws(E) -> sending R", "_ body: (inout         Value) throws    ->         R"},
		{"borrowing func withLock() {}", "          func withLock() {}"},
		{"let x = try await api.fetch()", "let x = try       api.fetch()"},
		{"case .success(): done()", "case .success  : done()"},
		// Not syntax: a variable, strings and comments stay as they are.
		{"if sending { send() }", "if sending { send() }"},
		{"let s = \"await throws(E) ~Copyable\"", "let s = \"await throws(E) ~Copyable\""},
		{"// await the result", "// await the result"},
		{"log(\"\\(dict[\"await\"]) await\")", "log(\"\\(dict[\"await\"]) await\")"},
	} {
		if got := string(swiftNormalize([]byte(tc.in))); got != tc.want {
			t.Errorf("swiftNormalize(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestSwiftNormalizeMacroBlock(t *testing.T) {
	src := "struct V {}\n\n#Preview(\"Small\", as: .systemSmall) {\n  V()\n} timeline: {\n  x\n}\n#if DEBUG\nlet y = 1\n#endif\n"
	got := string(swiftNormalize([]byte(src)))
	if len(got) != len(src) || strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Fatalf("positions moved:\n%s", got)
	}
	if strings.Contains(got, "#Preview") || strings.Contains(got, "V()") {
		t.Errorf("macro block not blanked:\n%s", got)
	}
	if strings.Contains(got, "timeline") || strings.Contains(got, "x\n") {
		t.Errorf("labelled trailing closure not blanked:\n%s", got)
	}
	if !strings.Contains(got, "#if DEBUG") || !strings.Contains(got, "let y = 1") {
		t.Errorf("compiler directive or code after the macro blanked:\n%s", got)
	}
}
