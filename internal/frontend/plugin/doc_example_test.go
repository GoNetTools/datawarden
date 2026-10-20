// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"os"
	"strings"
	"testing"
)

// TestDocExampleDecodes keeps the response example in docs/IR.md
// ("External frontends") a valid module.
func TestDocExampleDecodes(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/IR.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	anchor := strings.Index(s, `"funcs": [{"id": "lib/app.greet"`)
	if anchor < 0 {
		t.Fatal("response example not found in docs/IR.md")
	}
	start := strings.LastIndex(s[:anchor], "```json\n") + len("```json\n")
	end := anchor + strings.Index(s[anchor:], "\n```")
	m, err := Decode("ruby", []byte(s[start:end]))
	if err != nil {
		t.Fatalf("%v\n%s", err, s[start:end])
	}
	if len(m.Funcs) != 1 || m.Funcs[0].ID != "lib/app.greet" || len(m.Funcs[0].Instrs) != 2 {
		t.Errorf("module = %+v", m)
	}
}
