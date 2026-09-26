// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// irCorpora are the source trees whose lowered IR must verify: the
// conformance programs, the rule examples and the test repositories.
var irCorpora = []string{
	"../frontend/testdata/conformance",
	"../rules/testdata/examples",
	"../../testdata",
}

// TestLoweredIRVerifies lowers every program the tests use with every
// frontend and checks the result against the IR specification (ir.Verify):
// SSA form, phis, terminators and exceptional edges.
func TestLoweredIRVerifies(t *testing.T) {
	reg := NewComponents(time.Now).Frontends
	available := reg.Languages()
	for _, corpus := range irCorpora {
		root, err := filepath.Abs(corpus)
		if err != nil {
			t.Fatal(err)
		}
		fsys := os.DirFS(root)
		groups := map[string][]string{}
		err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if l, ok := lang.Lookup(lang.OfPath(p)); ok && l.Kind == lang.Code {
				groups[l.Name] = append(groups[l.Name], p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(groups))
		for l := range groups {
			names = append(names, l)
		}
		sort.Strings(names)
		for _, l := range names {
			t.Run(strings.TrimLeft(corpus, "./")+"/"+l, func(t *testing.T) {
				if !slices.Contains(available, l) {
					t.Skipf("no %s frontend in this build", l)
				}
				if l == lang.Go {
					if _, err := exec.LookPath("go"); err != nil {
						t.Skip("go toolchain not available")
					}
				}
				fe, err := reg.Frontend(l, frontend.Options{Root: root, FS: fsys})
				if err != nil {
					t.Fatal(err)
				}
				m, err := fe.Lower(context.Background(), groups[l])
				if err != nil {
					t.Fatal(err)
				}
				if len(m.Funcs) == 0 {
					t.Fatalf("no functions lowered from %d files", len(groups[l]))
				}
				if err := m.Verify(); err != nil {
					t.Errorf("%d functions; IR does not verify:\n%v", len(m.Funcs), err)
				}
			})
		}
	}
}
