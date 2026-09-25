// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Command datawarden-bench measures datawarden's accuracy and speed on a labelled
// corpus (testdata/eval.yaml): precision, recall and F1 per case, data type
// and sink, a confidence-threshold sweep, and scan time and allocations.
//
//	go run ./cmd/datawarden-bench [-manifest testdata/eval.yaml] [-runs 3] [-check]
//	                           [-json eval.json] [-markdown eval.md]
//
// Scans go through the same code as `datawarden scan --no-cache --no-baseline`.
// Exit codes: 0 ok, 1 a case scored below its min_precision/min_recall
// (with -check), 2 error.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/app"
	"github.com/GoNetTools/pii-scanner/internal/cli"
	"github.com/GoNetTools/pii-scanner/internal/eval"
	"github.com/GoNetTools/pii-scanner/internal/finding"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("datawarden-bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifest := fs.String("manifest", filepath.Join("testdata", "eval.yaml"), "labelled corpus")
	runs := fs.Int("runs", 1, "scans per case for timing (the median is reported)")
	check := fs.Bool("check", false, "exit 1 when a case scores below its min_precision or min_recall")
	jsonOut := fs.String("json", "", "also write the result as JSON to `file`")
	mdOut := fs.String("markdown", "", "also write a Markdown summary to `file`")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "datawarden-bench: %v\n", err)
		return 2
	}

	b, err := os.ReadFile(*manifest)
	if err != nil {
		return fail(err)
	}
	m, err := eval.Parse(b)
	if err != nil {
		return fail(err)
	}
	base, err := filepath.Abs(filepath.Dir(*manifest))
	if err != nil {
		return fail(err)
	}
	langs := map[string]bool{}
	for _, l := range app.NewComponents(time.Now).Frontends.Languages() {
		langs[l] = true
	}
	res, err := eval.Run(ctx, eval.Options{
		Manifest:  m,
		BaseDir:   base,
		Scan:      scan,
		Available: func(l string) bool { return langs[l] },
		Runs:      *runs,
	})
	if err != nil {
		return fail(err)
	}

	if err := eval.WriteText(stdout, res); err != nil {
		return fail(err)
	}
	for _, out := range []struct {
		path  string
		write func(io.Writer, *eval.Result) error
	}{{*jsonOut, eval.WriteJSON}, {*mdOut, eval.WriteMarkdown}} {
		if out.path == "" {
			continue
		}
		var buf bytes.Buffer
		if err := out.write(&buf, res); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(out.path, buf.Bytes(), 0o644); err != nil {
			return fail(err)
		}
	}
	if *check {
		if fails := res.Check(m); len(fails) > 0 {
			fmt.Fprintf(stderr, "\ndatawarden-bench: accuracy below the manifest's minimums:\n  %s\n", strings.Join(fails, "\n  "))
			return 1
		}
	}
	return 0
}

// scan runs `datawarden scan` in-process and measures it.
func scan(ctx context.Context, dir string, minConf float64) (*eval.Scan, error) {
	args := []string{"scan", "--root", dir, "--no-cache", "--no-baseline", "--no-fail", "--format", "json"}
	if minConf > 0 {
		args = append(args, "--min-confidence", strconv.FormatFloat(minConf, 'f', -1, 64))
	}
	var out, errb bytes.Buffer
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	code := app.New(&out, &errb).Run(ctx, args)
	wall := time.Since(start)
	runtime.ReadMemStats(&after)
	if code == cli.ExitError {
		return nil, fmt.Errorf("scan %s: %s", dir, strings.TrimSpace(errb.String()))
	}
	var rep struct {
		Flows        []*finding.Flow    `json:"flows"`
		Literals     []*finding.Literal `json:"literals"`
		FilesScanned int                `json:"files_scanned"`
		Functions    int                `json:"functions"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		return nil, fmt.Errorf("scan %s: bad JSON report: %w", dir, err)
	}
	return &eval.Scan{
		Flows: rep.Flows, Literals: rep.Literals, Wall: wall,
		AllocBytes: after.TotalAlloc - before.TotalAlloc,
		Files:      rep.FilesScanned, Functions: rep.Functions,
	}, nil
}
