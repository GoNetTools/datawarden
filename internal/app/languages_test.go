// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/lang"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

// TestEveryLanguageIsWired keeps internal/lang, the frontends and the
// rules in step: a language added to the table needs a frontend here (or
// an "unavailable" entry in builds without cgo), a frontend must answer to
// the name it is registered under, and every rule must name known
// languages.
func TestEveryLanguageIsWired(t *testing.T) {
	reg := NewComponents(time.Now).Frontends
	available, unavailable := reg.Languages(), reg.Unavailable()
	for _, l := range lang.CodeNames() {
		if !slices.Contains(available, l) && unavailable[l] == "" {
			t.Errorf("%s is a code language in internal/lang but app.NewComponents registers no frontend for it", l)
		}
	}
	for _, l := range append(slices.Clone(available), keys(unavailable)...) {
		if !lang.IsCode(l) {
			t.Errorf("frontend %q is not a code language in internal/lang", l)
		}
	}
	for _, l := range available {
		fe, err := reg.Frontend(l, frontend.Options{FS: fstest.MapFS{}})
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		if fe.Lang() != l {
			t.Errorf("frontend registered as %q reports Lang() = %q", l, fe.Lang())
		}
	}

	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules {
		for _, l := range r.Lang {
			if !lang.IsCode(l) {
				t.Errorf("rule %s: lang %q is not a code language", r.ID, l)
			}
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
