// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Command datawarden-bench measures datawarden's accuracy and speed on a labelled
// corpus (testdata/eval.yaml): precision, recall and F1 per case, data type
// and sink, a confidence-threshold sweep, and scan time and allocations.
//
//	go run ./cmd/datawarden-bench [-manifest testdata/eval.yaml] [-runs 3] [-check]
//	                           [-json eval.json] [-markdown eval.md] [-external]
//
// External cases (open-source apps pinned by repo and commit) are fetched
// with git into -cache and scanned only with -external.
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/GoNetTools/datawarden/internal/app"
	"github.com/GoNetTools/datawarden/internal/cli"
	"github.com/GoNetTools/datawarden/internal/eval"
	"github.com/GoNetTools/datawarden/internal/finding"
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
	external := fs.Bool("external", false, "also run external cases: fetch their repositories with git")
	cacheDir := fs.String("cache", defaultCache(), "where external repositories are checked out")
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
	opts := eval.Options{
		Manifest:  m,
		BaseDir:   base,
		Scan:      scan,
		Available: func(l string) bool { return langs[l] },
		Runs:      *runs,
	}
	if *external {
		opts.Fetch = func(ctx context.Context, repo, commit string) (string, error) {
			return fetch(ctx, *cacheDir, repo, commit, stderr)
		}
	}
	res, err := eval.Run(ctx, opts)
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

func defaultCache() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "datawarden-eval")
	}
	return filepath.Join(os.TempDir(), "datawarden-eval")
}

// fetch checks out repo at commit under cache (once) and returns the
// checkout.
func fetch(ctx context.Context, cache, repo, commit string, log io.Writer) (string, error) {
	name := strings.NewReplacer("https://", "", "http://", "", "/", "_", ":", "_").Replace(strings.TrimSuffix(repo, ".git"))
	dir := filepath.Join(cache, name+"-"+commit[:12])
	git := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	if head, err := git("rev-parse", "HEAD"); err == nil && head == commit {
		return dir, nil
	}
	fmt.Fprintf(log, "fetching %s at %s\n", repo, commit[:12])
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", repo}, {"fetch", "-q", "--depth", "1", "origin", commit}, {"checkout", "-q", "--detach", "FETCH_HEAD"}} {
		if _, err := git(args...); err != nil {
			return "", err
		}
	}
	return dir, nil
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
