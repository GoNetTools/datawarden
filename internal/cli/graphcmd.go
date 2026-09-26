// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"regexp"

	"github.com/GoNetTools/datawarden/internal/finding"
)

// runGraph scans like `scan` and draws the call graph of the violations:
// sources, the functions the data goes through, their callers and the
// sinks. `datawarden graph -o flows.svg`, then open the image.
func (a *App) runGraph(ctx context.Context, args []string) error {
	fs := a.flagSet("graph")
	var c common
	c.register(fs)
	var prof profile
	prof.register(fs)
	format := fs.String("format", "svg", "svg (an image), dot (Graphviz: dot -Tpng) or mermaid")
	out := fs.String("output", "", "file to write (default datawarden-graph.<format>; - for stdout)")
	fs.StringVar(out, "o", "", "shorthand for --output")
	all := fs.Bool("all", false, "also draw flows the policy accepts")
	funcRe := fs.String("function", "", "only flows whose sink function or call chain matches this `regexp`")
	dataType := fs.String("data-type", "", "only flows of this data type (email, phone, ...)")
	minConf := fs.Float64("min-confidence", 0, "override policy.min_confidence")
	fs.Usage = func() {
		fmt.Fprint(a.Stderr, `Usage: datawarden graph [paths...] [flags]

Scans like "datawarden scan" and draws the call graph behind the
violations: where the data is read, the functions it goes through, the
functions that call them, and the sinks it reaches (colored by
destination). The SVG is laid out by datawarden and opens in a browser;
DOT renders with Graphviz (dot -Tpng graph.dot -o graph.png); Mermaid
renders on GitHub.

`)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if !contains([]string{"svg", "dot", "mermaid"}, *format) {
		return fmt.Errorf("unknown format %q (svg, dot, mermaid)", *format)
	}
	var re *regexp.Regexp
	if *funcRe != "" {
		if re, err = regexp.Compile(*funcRe); err != nil {
			return fmt.Errorf("--function: %w", err)
		}
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return err
	}
	if *minConf > 0 {
		s.cfg.Policy.MinConfidence = *minConf
	}
	res, err := a.runScanner(ctx, &prof, a.request(s, &c))
	if err != nil {
		return err
	}
	for _, wn := range res.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", wn)
	}
	flows, lits := a.Policy.Apply(s.cfg, res.Flows, res.Literals)
	if _, _, err := a.markBaseline(s.inRoot(s.cfg.Baseline), flows, lits); err != nil {
		return err
	}
	var picked []*finding.Flow
	for _, f := range flows {
		if !f.Violation && !*all {
			continue
		}
		if *dataType != "" && f.DataType != *dataType {
			continue
		}
		if re != nil && !flowMatches(re, f) {
			continue
		}
		picked = append(picked, f)
	}
	var buf bytes.Buffer
	if err := a.Grapher.Render(&buf, *format, picked); err != nil {
		return err
	}
	if *out == "-" {
		_, err := a.Stdout.Write(buf.Bytes())
		return err
	}
	path := *out
	if path == "" {
		path = "datawarden-graph." + *format
		if *format == "mermaid" {
			path = "datawarden-graph.mmd"
		}
	}
	p, err := a.Workspace.Abs(path)
	if err != nil {
		return err
	}
	if err := a.Workspace.WriteFile(p, buf.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "wrote %s: %d flow(s)\n", p, len(picked))
	return nil
}

// flowMatches reports whether the sink function or any function of the
// flow's call chain or callers matches re.
func flowMatches(re *regexp.Regexp, f *finding.Flow) bool {
	names := []string{f.Function}
	for _, c := range f.Calls {
		names = append(names, c.Function)
	}
	names = append(names, f.CalledBy...)
	for _, n := range names {
		if re.MatchString(n) {
			return true
		}
	}
	return false
}
