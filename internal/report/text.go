// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// Text renders a human-readable report.
func Text(w io.Writer, r *Report) error {
	r.Sort()
	var b strings.Builder
	langs := []string{}
	for l, n := range r.FilesAnalyzed {
		langs = append(langs, fmt.Sprintf("%s:%d", l, n))
	}
	head := fmt.Sprintf("%s %s · %s scan", r.Tool, r.Version, r.Mode)
	if r.DiffBase != "" {
		head += " vs " + r.DiffBase
	}
	fmt.Fprintf(&b, "%s · %d files", head, r.FilesScanned)
	if len(langs) > 0 {
		sortStrings(langs)
		fmt.Fprintf(&b, " (%s)", strings.Join(langs, " "))
	}
	if r.Functions > 0 {
		fmt.Fprintf(&b, " · %d functions", r.Functions)
	}
	fmt.Fprintf(&b, " · %s\n", r.Duration)
	if r.Mode == "diff" {
		fmt.Fprintf(&b, "changed: %d files, callers: %d files\n", len(r.ChangedFiles), len(r.CallerFiles))
	}
	for _, wn := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", wn)
	}
	b.WriteString("\n")

	for _, f := range r.Flows {
		if !f.Violation && !r.ShowAll {
			continue
		}
		status := "NEW"
		switch {
		case f.Baselined:
			status = "BASELINE"
		case !f.Violation && f.Allowed != "":
			status = "ALLOWED"
		case !f.Violation:
			status = "INFO"
		}
		fmt.Fprintf(&b, "%-8s %-6s %s → %s  [%s]\n", status, f.Severity, f.DataType, destLabel(f.Dest), f.SinkRule)
		fmt.Fprintf(&b, "         source  %s  %s\n", f.Source, f.SourceDesc)
		fmt.Fprintf(&b, "         sink    %s  %s  in %s\n", f.Sink, f.SinkCall, f.Function)
		if len(f.Path) > 2 {
			fmt.Fprintf(&b, "         path    %s\n", shortPath(f.Path))
		}
		if r.ShowCalls {
			writeCalls(&b, f)
		}
		extra := fmt.Sprintf("confidence %.2f", f.Confidence)
		if len(f.Transforms) > 0 {
			extra += " · transforms " + strings.Join(f.Transforms, ",")
		}
		if len(f.Guards) > 0 {
			extra += " · guarded by " + strings.Join(f.Guards, "; ")
		}
		if f.Allowed != "" {
			extra += " · " + f.Allowed
		}
		if f.Fingerprint != "" {
			extra += " · explain: datawarden explain " + shortFP(f.Fingerprint)
		}
		fmt.Fprintf(&b, "         %s\n\n", extra)
	}
	for _, l := range r.Literals {
		if !l.Violation && !r.ShowAll {
			continue
		}
		status := "NEW"
		if l.Baselined {
			status = "BASELINE"
		}
		fmt.Fprintf(&b, "%-8s %-6s literal %s  %s  %s  (%s, confidence %.2f)\n", status, l.Severity, l.DataType, l.Pos, l.Masked, l.Detector, l.Confidence)
	}
	c := r.Counts()
	fmt.Fprintf(&b, "\n%d new violation(s): %d flow(s), %d literal(s)", c.NewFlows+c.NewLiterals, c.NewFlows, c.NewLiterals)
	if n := c.BaselinedFlows + c.BaselinedLiterals; n > 0 {
		fmt.Fprintf(&b, " · %d baselined", n)
	}
	if c.Accepted > 0 {
		fmt.Fprintf(&b, " · %d accepted by policy", c.Accepted)
		if !r.ShowAll {
			b.WriteString(" (--all to show)")
		}
	}
	if r.BaselineFixed > 0 {
		fmt.Fprintf(&b, " · %d baseline entries no longer found", r.BaselineFixed)
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// writeCalls prints a flow's call graph as a tree: each function the data
// goes through, indented by its call depth.
func writeCalls(b *strings.Builder, f *finding.Flow) {
	calls := f.Calls
	if len(calls) == 0 {
		calls = []finding.CallStep{{Function: f.Function, Pos: f.Sink}}
	}
	for i, c := range calls {
		label := "         calls   "
		if i > 0 {
			label = "                 "
		}
		branch := ""
		if c.Depth > 0 {
			branch = strings.Repeat("   ", c.Depth-1) + "└─ "
		}
		note := ""
		switch {
		case len(calls) == 1:
			note = "  (source and sink)"
		case i == 0:
			note = "  (source)"
		case i == len(calls)-1:
			note = "  (sink)"
		}
		fmt.Fprintf(b, "%s%s%s  %s%s\n", label, branch, c.Function, c.Pos, note)
	}
	if len(f.CalledBy) > 0 {
		fmt.Fprintf(b, "         called by  %s\n", strings.Join(f.CalledBy, ", "))
	}
}

func shortPath(p []ir.Pos) string {
	parts := make([]string, 0, len(p))
	prevFile := ""
	for _, q := range p {
		if q.File == prevFile {
			parts = append(parts, fmt.Sprintf(":%d", q.Line))
		} else {
			parts = append(parts, fmt.Sprintf("%s:%d", q.File, q.Line))
			prevFile = q.File
		}
	}
	return strings.Join(parts, " → ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// JSON renders the full report as JSON.
func JSON(w io.Writer, r *Report) error {
	r.Sort()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// shortFP is the prefix of a fingerprint that `datawarden explain` takes.
func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
