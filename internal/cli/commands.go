// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoNetTools/datawarden/internal/datamap"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/lang"
	"github.com/GoNetTools/datawarden/internal/report"
	"github.com/GoNetTools/datawarden/internal/rules"
	"github.com/GoNetTools/datawarden/internal/scan"
)

func (a *App) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

func (a *App) newReport(res *scan.Result, flows []*finding.Flow, lits []*finding.Literal, rs RuleSet, diffBase string) *report.Report {
	if flows == nil {
		flows = []*finding.Flow{}
	}
	if lits == nil {
		lits = []*finding.Literal{}
	}
	return &report.Report{
		Tool: "datawarden", Version: a.Version, Mode: res.Mode, DiffBase: diffBase, Commit: res.Commit, Started: res.Started,
		Duration: res.Duration.Round(time.Millisecond).String(), FilesScanned: res.FilesScanned, FilesAnalyzed: res.FilesAnalyzed,
		Functions: res.Functions, ChangedFiles: res.ChangedFiles, CallerFiles: res.CallerFiles,
		Flows: flows, Literals: lits, Warnings: res.Warnings, Rules: rs, Catalog: a.Catalog, Links: a.Links,
	}
}

func (a *App) writeReport(path, format string, r *report.Report) error {
	var buf bytes.Buffer
	if err := a.Reporter.Write(&buf, format, r); err != nil {
		return err
	}
	return a.Workspace.WriteFile(path, buf.Bytes())
}

// hasNew reports whether any finding is a violation the baseline does not
// accept; it decides the exit code.
func hasNew(flows []*finding.Flow, lits []*finding.Literal) bool {
	for _, f := range flows {
		if f.IsNew() {
			return true
		}
	}
	for _, l := range lits {
		if l.IsNew() {
			return true
		}
	}
	return false
}

func (a *App) runScan(ctx context.Context, args []string) (int, error) {
	fs := a.flagSet("scan")
	var c common
	c.register(fs)
	var prof profile
	prof.register(fs)
	diff := fs.String("diff", "", "PR mode: scan files changed since the merge base with `ref`, plus their callers")
	format := fs.String("format", "text", "stdout format: text, json, sarif, markdown, gitlab")
	output := fs.String("output", "", "write the --format output to this file instead of stdout")
	sarifOut := fs.String("sarif", "", "also write a SARIF report to `file`")
	mdOut := fs.String("markdown", "", "also write a Markdown summary to `file`")
	jsonOut := fs.String("json", "", "also write a JSON report to `file`")
	glOut := fs.String("gitlab", "", "also write a GitLab SAST report to `file`")
	baselinePath := fs.String("baseline", "", "baseline file (default from config: .datawarden/baseline.json)")
	noBaseline := fs.Bool("no-baseline", false, "ignore the baseline: every violation counts as new")
	literalsOnly := fs.Bool("literals-only", false, "run only the committed-value detector (fast; for pre-commit)")
	staged := fs.Bool("staged", false, "with --literals-only: scan the staged (git index) content of staged files")
	callerDepth := fs.Int("caller-depth", 2, "with --diff: how many levels of callers to include")
	all := fs.Bool("all", false, "text output: also show flows accepted by policy")
	minConf := fs.Float64("min-confidence", 0, "override policy.min_confidence")
	noFail := fs.Bool("no-fail", false, "exit 0 even when there are new violations")
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: datawarden scan [paths...] [flags]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitError, err
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return ExitError, err
	}
	if *minConf > 0 {
		s.cfg.Policy.MinConfidence = *minConf
	}
	req := a.request(s, &c)
	req.DiffBase, req.LiteralsOnly, req.Staged, req.CallerDepth = *diff, *literalsOnly || *staged, *staged, *callerDepth
	res, err := a.runScanner(ctx, &prof, req)
	if err != nil {
		return ExitError, err
	}
	flows, lits := a.Policy.Apply(s.cfg, res.Flows, res.Literals)
	bpath := ""
	if !*noBaseline {
		bpath = *baselinePath
		if bpath == "" {
			bpath = s.inRoot(s.cfg.Baseline)
		} else if bpath, err = a.Workspace.Abs(bpath); err != nil {
			return ExitError, err
		}
	}
	size, unseen, err := a.markBaseline(bpath, flows, lits)
	if err != nil {
		return ExitError, err
	}
	rep := a.newReport(res, flows, lits, s.rules, *diff)
	rep.ShowAll = *all
	rep.BaselineSize = size
	if res.Mode == scan.ModeFull {
		rep.BaselineFixed = len(unseen)
	}
	for _, extra := range []struct{ path, format string }{{*sarifOut, "sarif"}, {*mdOut, "markdown"}, {*jsonOut, "json"}, {*glOut, "gitlab"}} {
		if extra.path == "" {
			continue
		}
		p, err := a.Workspace.Abs(extra.path)
		if err != nil {
			return ExitError, err
		}
		if err := a.writeReport(p, extra.format, rep); err != nil {
			return ExitError, err
		}
	}
	if *output != "" {
		p, err := a.Workspace.Abs(*output)
		if err != nil {
			return ExitError, err
		}
		if err := a.writeReport(p, *format, rep); err != nil {
			return ExitError, err
		}
	} else if err := a.Reporter.Write(a.Stdout, *format, rep); err != nil {
		return ExitError, err
	}
	if hasNew(flows, lits) && !*noFail {
		return ExitViolation, nil
	}
	return ExitClean, nil
}

func (a *App) runBaseline(ctx context.Context, args []string) error {
	fs := a.flagSet("baseline")
	var c common
	c.register(fs)
	var prof profile
	prof.register(fs)
	out := fs.String("output", "", "baseline file to write (default from config: .datawarden/baseline.json)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return err
	}
	if len(s.paths) > 0 {
		return errors.New("baseline always scans the whole repository; drop the path arguments")
	}
	res, err := a.runScanner(ctx, &prof, a.request(s, &c))
	if err != nil {
		return err
	}
	flows, lits := a.Policy.Apply(s.cfg, res.Flows, res.Literals)
	data, entries, err := a.Baselines.Encode(flows, lits, res.Commit, a.Clock())
	if err != nil {
		return err
	}
	path := s.inRoot(s.cfg.Baseline)
	if *out != "" {
		if path, err = a.Workspace.Abs(*out); err != nil {
			return err
		}
	}
	if err := a.Workspace.WriteFile(path, data); err != nil {
		return err
	}
	rel, _ := filepath.Rel(s.root, path)
	fmt.Fprintf(a.Stdout, "datawarden: wrote %d accepted finding(s) to %s — commit it so CI only reports new ones\n", entries, filepath.ToSlash(rel))
	for _, w := range res.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", w)
	}
	return nil
}

func (a *App) runMap(ctx context.Context, args []string) error {
	fs := a.flagSet("map")
	var c common
	c.register(fs)
	var prof profile
	prof.register(fs)
	format := fs.String("format", "dpia", "dpia (Markdown), json, csv or mermaid")
	out := fs.String("output", "", "write to file instead of stdout")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return err
	}
	res, err := a.runScanner(ctx, &prof, a.request(s, &c))
	if err != nil {
		return err
	}
	flows, lits := a.Policy.Apply(s.cfg, res.Flows, res.Literals)
	if _, _, err := a.markBaseline(s.inRoot(s.cfg.Baseline), flows, lits); err != nil {
		return err
	}
	m := a.DataMapper.Build(datamap.Input{Flows: flows, Literals: lits, Schema: res.Schema, Commit: res.Commit, Now: a.Clock(), Catalog: a.Catalog})
	for _, wn := range res.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", wn)
	}
	if *out == "" {
		return a.DataMapper.Write(a.Stdout, *format, m)
	}
	var buf bytes.Buffer
	if err := a.DataMapper.Write(&buf, *format, m); err != nil {
		return err
	}
	p, err := a.Workspace.Abs(*out)
	if err != nil {
		return err
	}
	return a.Workspace.WriteFile(p, buf.Bytes())
}

func (a *App) runRules(args []string) error {
	fs := a.flagSet("rules")
	var c common
	c.register(fs)
	kind := fs.String("kind", "", "only rules of this kind: sink, source, transform")
	langFlag := fs.String("lang", "", "only rules for this language")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return err
	}
	for _, r := range s.rules.All() {
		if *kind != "" && r.Kind != *kind {
			continue
		}
		if *langFlag != "" && !contains(r.Lang, lang.Normalize(*langFlag)) {
			continue
		}
		extra := ""
		switch r.Kind {
		case rules.KindSink:
			extra = r.Dest.Kind
			if r.Dest.Host != "" {
				extra += " " + r.Dest.Host
			}
		case rules.KindSource:
			extra = r.DataType
		case rules.KindTransform:
			extra = r.Transform
		}
		fmt.Fprintf(a.Stdout, "%-40s %-9s %-24s %-28s %s\n", r.ID, r.Kind, strings.Join(r.Lang, ","), extra, r.Origin)
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (a *App) runInit(args []string) error {
	fs := a.flagSet("init")
	root := fs.String("root", ".", "repository root")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := a.Workspace.Abs(*root)
	if err != nil {
		return err
	}
	for _, t := range initTemplates {
		p := filepath.Join(dir, filepath.FromSlash(t.name))
		if _, err := a.Workspace.ReadFile(p); err == nil && !*force {
			fmt.Fprintf(a.Stdout, "exists  %s\n", t.name)
			continue
		}
		if err := a.Workspace.WriteFile(p, []byte(t.body)); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "created %s\n", t.name)
	}
	return nil
}

func (a *App) runComment(args []string) error {
	fs := a.flagSet("comment")
	onlyIfNew := fs.Bool("only-if-new", false, "skip posting when the summary reports no new findings")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: datawarden comment <markdown-file> (from scan --markdown)")
	}
	if a.Commenter == nil {
		return errors.New("posting comments is not configured")
	}
	p, err := a.Workspace.Abs(pos[0])
	if err != nil {
		return err
	}
	body, err := a.Workspace.ReadFile(p)
	if err != nil {
		return err
	}
	if *onlyIfNew && strings.Contains(string(body), "no new sensitive-data leaks") {
		fmt.Fprintln(a.Stdout, "datawarden: no new findings; comment skipped")
		return nil
	}
	what, err := a.Commenter.Post(string(body))
	if isNotInReview(err) {
		fmt.Fprintln(a.Stdout, "datawarden: not a pull/merge request; comment skipped")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "datawarden: %s review comment\n", what)
	return nil
}

// ErrNotInReview is returned by a Commenter when there is no PR/MR to
// post to; the command then succeeds without posting.
var ErrNotInReview = errors.New("not running for a pull/merge request")

func isNotInReview(err error) bool { return err != nil && errors.Is(err, ErrNotInReview) }
