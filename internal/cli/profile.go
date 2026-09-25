// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"runtime"
	"runtime/pprof"

	"github.com/GoNetTools/pii-scanner/internal/scan"
)

// profile holds the pprof flags of the commands that run the analysis
// (scan, baseline, map).
type profile struct {
	cpu, mem string
}

func (p *profile) register(fs *flag.FlagSet) {
	fs.StringVar(&p.cpu, "cpuprofile", "", "write a CPU profile of the analysis to `file` (go tool pprof)")
	fs.StringVar(&p.mem, "memprofile", "", "write a heap profile, taken after the analysis, to `file` (go tool pprof -sample_index=alloc_space)")
}

// runScanner runs the scan, profiling it when asked. Profiles are buffered
// and written through the Workspace once the scan has succeeded.
func (a *App) runScanner(ctx context.Context, p *profile, req scan.Request) (*scan.Result, error) {
	var cpu bytes.Buffer
	if p.cpu != "" {
		if err := pprof.StartCPUProfile(&cpu); err != nil {
			return nil, fmt.Errorf("cpu profile: %w", err)
		}
	}
	res, err := a.Scanner.Run(ctx, req)
	if p.cpu != "" {
		pprof.StopCPUProfile()
	}
	if err != nil {
		return nil, err
	}
	if p.cpu != "" {
		if err := a.writeProfile(p.cpu, cpu.Bytes()); err != nil {
			return nil, err
		}
	}
	if p.mem != "" {
		var heap bytes.Buffer
		runtime.GC() // up-to-date statistics
		if err := pprof.WriteHeapProfile(&heap); err != nil {
			return nil, fmt.Errorf("heap profile: %w", err)
		}
		if err := a.writeProfile(p.mem, heap.Bytes()); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (a *App) writeProfile(path string, data []byte) error {
	abs, err := a.Workspace.Abs(path)
	if err != nil {
		return err
	}
	if err := a.Workspace.WriteFile(abs, data); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	return nil
}
