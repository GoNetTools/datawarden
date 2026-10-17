// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"slices"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Heuristics are the word lists the analysis falls back on for code no
// rule describes: which method names mutate their receiver, which return
// no data, which run a callback at once, which words mean consent. They
// are data (builtin/heuristics.yaml), extended by the `heuristics:` key of
// a repository's rule files: lists append, map entries override.
type Heuristics struct {
	// Lists are word lists by table ("mutator_prefixes"); Maps are word
	// to value tables ("transform_checks", "decode_into").
	Lists map[string][]string          `json:"lists,omitempty"`
	Maps  map[string]map[string]string `json:"maps,omitempty"`
	sets  map[string]map[string]bool
}

// The tables a heuristics document may define.
var (
	heuristicLists = []string{"getter_verbs", "whole_value_fields", "whole_value_methods", "data_free_suffixes", "data_free_calls",
		"public_parts", "request_methods", "loader_methods", "self_describing", "stringers", "placeholders", "handle_types",
		"mutator_prefixes", "immediate_callbacks", "pii_detectors", "container_ops", "container_builders", "consent_words", "label_stop_words"}
	heuristicMaps = []string{"decode_into", "transform_checks"}
)

// HeuristicTables lists every table, lists first.
func HeuristicTables() []string {
	return append(append([]string(nil), heuristicLists...), heuristicMaps...)
}

// Words returns a list table, nil for an unknown or map table.
func (h *Heuristics) Words(table string) []string {
	if h == nil {
		return nil
	}
	return h.Lists[table]
}

// Has reports whether word is in the list table.
func (h *Heuristics) Has(table, word string) bool {
	if h == nil {
		return false
	}
	return h.sets[table][word]
}

// Lookup returns the value of key in the map table.
func (h *Heuristics) Lookup(table, key string) (string, bool) {
	if h == nil {
		return "", false
	}
	v, ok := h.Maps[table][key]
	return v, ok
}

// merge adds o's tables to h: list words append (once), map entries
// override.
func (h *Heuristics) merge(o *Heuristics) {
	if o == nil {
		return
	}
	if h.Lists == nil {
		h.Lists, h.Maps, h.sets = map[string][]string{}, map[string]map[string]string{}, map[string]map[string]bool{}
	}
	for _, t := range heuristicLists {
		for _, w := range o.Lists[t] {
			if !h.sets[t][w] {
				if h.sets[t] == nil {
					h.sets[t] = map[string]bool{}
				}
				h.sets[t][w] = true
				h.Lists[t] = append(h.Lists[t], w)
			}
		}
	}
	for _, t := range heuristicMaps {
		for k, v := range o.Maps[t] {
			if h.Maps[t] == nil {
				h.Maps[t] = map[string]string{}
			}
			h.Maps[t][k] = v
		}
	}
}

// parseHeuristics decodes the `heuristics:` mapping of a rule file.
// Unknown tables are errors, so a misspelt table cannot silently do
// nothing.
func parseHeuristics(n *yaml.Node, origin string) (*Heuristics, error) {
	h := &Heuristics{Lists: map[string][]string{}, Maps: map[string]map[string]string{}, sets: map[string]map[string]bool{}}
	if n == nil || n.Kind == 0 {
		return h, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: line %d: heuristics must be a mapping of tables", origin, n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		switch {
		case slices.Contains(heuristicLists, key.Value):
			if val.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s: line %d: heuristics.%s must be a list of words", origin, val.Line, key.Value)
			}
			h.sets[key.Value] = map[string]bool{}
			for _, w := range val.Content {
				if w.Kind != yaml.ScalarNode || w.Value == "" {
					return nil, fmt.Errorf("%s: line %d: heuristics.%s: words only", origin, w.Line, key.Value)
				}
				h.Lists[key.Value] = append(h.Lists[key.Value], w.Value)
				h.sets[key.Value][w.Value] = true
			}
		case slices.Contains(heuristicMaps, key.Value):
			if val.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s: line %d: heuristics.%s must be a mapping", origin, val.Line, key.Value)
			}
			h.Maps[key.Value] = map[string]string{}
			for j := 0; j+1 < len(val.Content); j += 2 {
				k, v := val.Content[j], val.Content[j+1]
				if v.Kind != yaml.ScalarNode {
					return nil, fmt.Errorf("%s: line %d: heuristics.%s.%s: a word or number", origin, v.Line, key.Value, k.Value)
				}
				if key.Value == "decode_into" {
					if i, err := strconv.Atoi(v.Value); err != nil || i < 0 {
						return nil, fmt.Errorf("%s: line %d: heuristics.decode_into.%s: an argument index", origin, v.Line, k.Value)
					}
				}
				h.Maps[key.Value][k.Value] = v.Value
			}
		default:
			known := HeuristicTables()
			sort.Strings(known)
			return nil, fmt.Errorf("%s: line %d: unknown heuristics table %q (tables: %v)", origin, key.Line, key.Value, known)
		}
	}
	return h, nil
}
