// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package treesitter

import (
	"strings"
	"testing"
)

func TestTSNormalize(t *testing.T) {
	blank := func(s string) string { return strings.Repeat(" ", len(s)) }
	for _, tc := range []struct{ in, want string }{
		{"sql<{ db: string }>`SELECT 1`", "sql" + blank("<{ db: string }>") + "`SELECT 1`"},
		{"sql<number>`count(${x})`.execute(db)", "sql" + blank("<number>") + "`count(${x})`.execute(db)"},
		{"sql<{\n  id: string;\n}>`x`", "sql" + blank("<{") + "\n" + blank("  id: string;") + "\n" + blank("}>") + "`x`"},
		{"q<Map<string, () => void>>`x`", "q" + blank("<Map<string, () => void>>") + "`x`"},
		{"f(sql<T>`a ${inner<U>`b`} c`)", "f(sql" + blank("<T>") + "`a ${inner" + blank("<U>") + "`b`} c`)"},
		// Not type arguments of a tag: left as they are.
		{"const f = (x) => `hi ${x}`", "const f = (x) => `hi ${x}`"},
		{"return <string>`abc`", "return <string>`abc`"},
		{"a < b > `c`", "a < b > `c`"},
		{"const s = `<b>` + `<i>`", "const s = `<b>` + `<i>`"},
		{"// sql<T>`x`\nlet a = '<b>`'", "// sql<T>`x`\nlet a = '<b>`'"},
		{"html`<p>${a}</p>`", "html`<p>${a}</p>`"},
	} {
		if got := string(tsNormalize([]byte(tc.in))); got != tc.want {
			t.Errorf("tsNormalize(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}
