// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/GoNetTools/datawarden/internal/explain"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/scan"
)

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{6,64}$`)

// runExplain prints why datawarden reported a flow: `datawarden explain
// 3f9a1c` (a fingerprint or a prefix of one) or `datawarden explain
// app/Login.kt:42` (a flow whose sink or source is on that line).
func (a *App) runExplain(ctx context.Context, args []string) (int, error) {
	fl := a.flagSet("explain")
	var c common
	c.register(fl)
	format := fl.String("format", "text", "output format: text or json")
	baselinePath := fl.String("baseline", "", "baseline file (default from config: .datawarden/baseline.json)")
	reportPath := fl.String("report", "", "read the flows from this JSON report (scan --json) instead of scanning")
	fl.Usage = func() {
		fmt.Fprint(a.Stderr, `Usage: datawarden explain <fingerprint | file:line> [flags]

Explains a flow end to end: why its source is that data type, what happens
at each step of its path, why the sink rule matched, how the policy decided
and what would silence it. A fingerprint (or a prefix of one) is printed by
scan, SARIF, JSON and PR comments; file:line selects the flows whose sink or
source is on that line. With --report, the flows come from a saved JSON
report and nothing is scanned.

`)
		fl.PrintDefaults()
	}
	pos, err := parseInterspersed(fl, args)
	if err != nil {
		return ExitError, err
	}
	if len(pos) != 1 {
		fl.Usage()
		return ExitError, fmt.Errorf("explain takes one fingerprint or file:line")
	}
	if *format != "text" && *format != "json" {
		return ExitError, fmt.Errorf("unknown format %q (text, json)", *format)
	}
	if a.Explainer == nil {
		return ExitError, fmt.Errorf("this build cannot explain findings")
	}
	s, err := a.open(&c, nil)
	if err != nil {
		return ExitError, err
	}
	sel, err := a.selector(s, pos[0])
	if err != nil {
		return ExitError, err
	}
	var all []*finding.Flow
	if *reportPath != "" {
		if all, err = a.reportFlows(*reportPath); err != nil {
			return ExitError, err
		}
	} else {
		res, err := a.Scanner.Run(ctx, a.request(s, &c))
		if err != nil {
			return ExitError, err
		}
		all = res.Flows
		a.Policy.Apply(s.cfg, all, nil)
		bpath := *baselinePath
		if bpath == "" {
			bpath = s.inRoot(s.cfg.Baseline)
		} else if bpath, err = a.Workspace.Abs(bpath); err != nil {
			return ExitError, err
		}
		if _, _, err := a.markBaseline(bpath, all, nil); err != nil {
			return ExitError, err
		}
	}
	var picked []*finding.Flow
	for _, f := range all {
		if sel(f) {
			picked = append(picked, f)
		}
	}
	if len(picked) == 0 {
		return ExitError, fmt.Errorf("no flow matches %s (datawarden scan --all lists them; a fingerprint is in the JSON and SARIF reports)", pos[0])
	}
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].Confidence > picked[j].Confidence })

	// The IR of the files on the paths, for what happens at each step.
	var files []string
	seen := map[string]bool{}
	for _, f := range picked {
		for _, p := range append([]ir.Pos{f.Source, f.Sink}, f.Path...) {
			if p.File != "" && !seen[p.File] {
				seen[p.File] = true
				files = append(files, p.File)
			}
		}
	}
	var funcs []*ir.Func
	if lowerer, ok := a.Scanner.(Lowerer); ok {
		m, err := lowerer.Lower(ctx, scan.Request{Repo: s.repo, Config: s.cfg, Paths: files, Logf: s.logf})
		if err != nil {
			return ExitError, err
		}
		funcs = m.Funcs
	}
	lines := map[string][]string{}
	readLines := func(file string) []string {
		if l, ok := lines[file]; ok {
			return l
		}
		b, err := fs.ReadFile(s.repo.FS, file)
		if err != nil {
			lines[file] = nil
			return nil
		}
		lines[file] = strings.Split(string(b), "\n")
		return lines[file]
	}
	var out []*explain.Explanation
	for _, f := range picked {
		out = append(out, a.Explainer.Explain(explain.Input{
			Flow: f, Decision: a.Policy.Decide(s.cfg, f), Funcs: funcs, Rules: s.rules, Lines: readLines,
		}))
	}
	if len(out) > 1 && *format == "text" {
		fmt.Fprintf(a.Stdout, "%d flows match %s\n\n", len(out), pos[0])
	}
	if err := a.Explainer.Write(a.Stdout, *format, out); err != nil {
		return ExitError, err
	}
	return ExitClean, nil
}

// reportFlows reads the flows of a JSON scan report.
func (a *App) reportFlows(path string) ([]*finding.Flow, error) {
	p, err := a.Workspace.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := a.Workspace.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var r struct {
		Tool  string          `json:"tool"`
		Flows []*finding.Flow `json:"flows"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Tool != "datawarden" {
		return nil, fmt.Errorf("%s is not a datawarden JSON report (datawarden scan --json FILE writes one)", path)
	}
	return r.Flows, nil
}

// selector parses a fingerprint (or prefix) or file:line argument.
func (a *App) selector(s *session, arg string) (func(*finding.Flow) bool, error) {
	if fingerprintRe.MatchString(arg) {
		return func(f *finding.Flow) bool { return strings.HasPrefix(f.Fingerprint, arg) }, nil
	}
	i := strings.LastIndexByte(arg, ':')
	if i <= 0 {
		return nil, fmt.Errorf("%q is neither a fingerprint nor file:line", arg)
	}
	line, err := strconv.Atoi(arg[i+1:])
	if err != nil || line <= 0 {
		return nil, fmt.Errorf("%q is neither a fingerprint nor file:line", arg)
	}
	file := arg[:i]
	// A path relative to the working directory, or to the repository root.
	if abs, err := a.Workspace.Abs(file); err == nil {
		if rel, err := a.relToRoot(s.root, abs); err == nil {
			if _, err := fs.Stat(s.repo.FS, rel); err == nil {
				file = rel
			}
		}
	}
	file = strings.TrimPrefix(file, "./")
	return func(f *finding.Flow) bool {
		return f.Sink.File == file && f.Sink.Line == line || f.Source.File == file && f.Source.Line == line
	}, nil
}
