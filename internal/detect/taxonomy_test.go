// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// TestBuiltinTaxonomy guards internal/detect/builtin/datatypes.yaml.
func TestBuiltinTaxonomy(t *testing.T) {
	tx, err := ParseTaxonomy(builtinTaxonomy)
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]bool{}
	for _, c := range tx.Classes {
		classes[c.ID] = true
	}
	for _, want := range []string{"pii", "phi", "pci", "credential"} {
		if !classes[want] {
			t.Errorf("class %s missing", want)
		}
	}
	c := NewClassifier(tx.Types)
	for id, class := range map[string]string{"email": "pii", "health": "phi", "credit_card": "pci", "national_id": "pii"} {
		if got := c.Lookup(id).Class; got != class {
			t.Errorf("%s: class %q, want %q", id, got, class)
		}
	}
	if c.Class("phi").Severity != "high" || c.Class("pii").Severity != "" || c.Class("nope").Label != "nope" {
		t.Error("class lookup")
	}
	if len(c.Classes()) != len(tx.Classes) {
		t.Error("Classes")
	}
}

func TestTaxonomyValidation(t *testing.T) {
	head := "classes:\n  - {id: pii, label: Personal data}\ndata_types:\n"
	for name, body := range map[string]string{
		"unknown key":      "  - {id: a, label: A, class: pii, category: c, patterns: [a], colour: red}\n",
		"unknown class":    "  - {id: a, label: A, class: phi, category: c, patterns: [a]}\n",
		"duplicate type":   "  - {id: a, label: A, class: pii, category: c, patterns: [a]}\n  - {id: a, label: A, class: pii, category: c, patterns: [b]}\n",
		"no patterns":      "  - {id: a, label: A, class: pii, category: c}\n",
		"upper-case word":  "  - {id: a, label: A, class: pii, category: c, patterns: [Email]}\n",
		"bad regex":        "  - {id: a, label: A, class: pii, category: c, values: [{name: x, regex: '(', confidence: 0.9}]}\n",
		"bad confidence":   "  - {id: a, label: A, class: pii, category: c, values: [{name: x, regex: 'x', confidence: 2}]}\n",
		"bad severity":     "  - {id: a, label: A, class: pii, category: c, patterns: [a], severity: urgent}\n",
		"missing category": "  - {id: a, label: A, class: pii, patterns: [a]}\n",
	} {
		if _, err := ParseTaxonomy([]byte(head + body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseTaxonomy([]byte("classes:\n  - {id: pii, label: P}\n  - {id: pii, label: P}\ndata_types: []\n")); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate class: %v", err)
	}
	tx, err := ParseTaxonomy([]byte(head + "  - {id: loyalty_card, label: Loyalty card, class: pii, category: financial, patterns: [loyalty card]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := NewClassifier(tx.Types, tx.Classes...).Ident("customerLoyaltyCard"); !ok || m.DataType != "loyalty_card" {
		t.Errorf("custom taxonomy: %+v %v", m, ok)
	}
}
