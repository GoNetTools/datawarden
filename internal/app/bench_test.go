// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"io"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/cli"
)

// BenchmarkScan runs a full, uncached scan of each fixture end to end, the
// way `piiflow scan --no-cache` does. The Go fixture includes `go list`.
func BenchmarkScan(b *testing.B) {
	langs := NewComponents(time.Now).Frontends.Languages()
	for _, fx := range []struct{ name, lang string }{{"goapp", "go"}, {"android", "kotlin"}, {"web", "typescript"}} {
		b.Run(fx.name, func(b *testing.B) {
			if !slices.Contains(langs, fx.lang) {
				b.Skipf("no %s frontend in this build", fx.lang)
			}
			if _, err := exec.LookPath("go"); fx.lang == "go" && err != nil {
				b.Skip("go toolchain not available")
			}
			args := []string{"scan", "--root", "../../testdata/" + fx.name, "--no-cache", "--no-baseline", "--no-fail", "--format", "json"}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if code := New(io.Discard, io.Discard).Run(context.Background(), args); code != cli.ExitClean {
					b.Fatalf("exit %d", code)
				}
			}
		})
	}
}
