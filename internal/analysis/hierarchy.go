// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"slices"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// maxTargets bounds the functions one dynamically dispatched call may run.
const maxTargets = 16

// hierarchy is the class table of the program: it resolves a dynamically
// dispatched call to the overrides and implementations it may run (class
// hierarchy analysis).
type hierarchy struct {
	classes map[string]*ir.Class
	byShort map[string][]*ir.Class
	subs    map[string][]*ir.Class // direct subtypes by class name
}

func newHierarchy(classes []*ir.Class) *hierarchy {
	h := &hierarchy{classes: map[string]*ir.Class{}, byShort: map[string][]*ir.Class{}, subs: map[string][]*ir.Class{}}
	for _, c := range classes {
		if c == nil || c.Name == "" {
			continue
		}
		if _, dup := h.classes[c.Name]; dup {
			continue
		}
		h.classes[c.Name] = c
		s := shortClass(c.Name)
		h.byShort[s] = append(h.byShort[s], c)
	}
	names := make([]string, 0, len(h.classes))
	for n := range h.classes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := h.classes[n]
		for _, s := range c.Supers {
			// A supertype missing from the table (declared in a file not
			// scanned this run) is indexed by its name as written.
			key := strings.TrimLeft(s, "*&")
			if sc := h.class(s); sc != nil {
				if sc == c {
					continue
				}
				key = sc.Name
			}
			h.subs[key] = append(h.subs[key], c)
		}
	}
	return h
}

func shortClass(name string) string {
	if i := strings.LastIndexAny(name, "./:"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// class finds a class by qualified name, or by short name when that is
// unambiguous. Pointer and optional markers are ignored.
func (h *hierarchy) class(name string) *ir.Class {
	name = strings.TrimSuffix(strings.TrimLeft(name, "*&"), "?")
	if c, ok := h.classes[name]; ok {
		return c
	}
	if cs := h.byShort[shortClass(name)]; len(cs) == 1 {
		return cs[0]
	}
	return nil
}

// targets lists the functions a call may run: its static target, and for
// a call on a receiver of a known type the overrides and implementations
// of the method in the receiver type's subtypes.
//
// Only classes of the caller's language (lang) are considered: a Go
// err.Error() is not a call of a JavaScript class's Error method.
func (h *hierarchy) targets(c *ir.Call, lang string) []string {
	var out []string
	if c.Target != "" {
		out = append(out, c.Target)
	}
	if c.Indirect || c.RecvType == "" || c.Name == "" {
		return out
	}
	rootName := strings.TrimSuffix(strings.TrimLeft(c.RecvType, "*&"), "?")
	seen := map[*ir.Class]bool{}
	if root := h.class(c.RecvType); root != nil {
		rootName = root.Name
		seen[root] = true
	}
	work := append([]*ir.Class(nil), h.subs[rootName]...)
	for len(work) > 0 && len(out) < maxTargets {
		k := work[0]
		work = work[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		if k.Lang != "" && lang != "" && k.Lang != lang {
			continue
		}
		if id, ok := k.Methods[c.Name]; ok && !slices.Contains(out, id) {
			out = append(out, id)
		}
		work = append(work, h.subs[k.Name]...)
	}
	return out
}

// ancestors lists the short names of a class and of its supertypes,
// nearest first.
func (h *hierarchy) ancestors(name string) []string {
	out := []string{name}
	c := h.class(name)
	for i := 0; c != nil && i < len(out) && len(out) < maxTargets; i++ {
		if i > 0 {
			if c = h.class(out[i]); c == nil {
				continue
			}
		}
		for _, s := range c.Supers {
			if k := ownerKey(s); k != "" && !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	return out
}
