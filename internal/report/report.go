// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Package report renders scan results as text, JSON, SARIF, Markdown and
// GitLab SAST reports.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

// Report is everything a renderer needs.
type Report struct {
	Tool          string             `json:"tool"`
	Version       string             `json:"version"`
	Mode          string             `json:"mode"`
	DiffBase      string             `json:"diff_base,omitempty"`
	Commit        string             `json:"commit,omitempty"`
	Started       time.Time          `json:"started"`
	Duration      string             `json:"duration"`
	FilesScanned  int                `json:"files_scanned"`
	FilesAnalyzed map[string]int     `json:"files_analyzed"`
	Functions     int                `json:"functions"`
	ChangedFiles  []string           `json:"changed_files,omitempty"`
	CallerFiles   []string           `json:"caller_files,omitempty"`
	Flows         []*finding.Flow    `json:"flows"`
	Literals      []*finding.Literal `json:"literals"`
	Warnings      []string           `json:"warnings,omitempty"`
	BaselineSize  int                `json:"baseline_size"`
	BaselineFixed int                `json:"baseline_fixed"`

	Rules RuleLookup `json:"-"`
	// ShowAll includes non-violating flows in human-readable output.
	ShowAll bool `json:"-"`
	// Catalog labels data types; nil falls back to the type id.
	Catalog Catalog `json:"-"`
	// Links builds a URL for a source position (CI code browsing); nil
	// renders plain locations.
	Links func(ir.Pos) string `json:"-"`
}

// RuleLookup finds rule metadata by id (implemented by *rules.Set).
type RuleLookup interface {
	ByID(id string) *rules.Rule
}

// Catalog describes data types (implemented by *detect.Classifier).
type Catalog interface {
	Lookup(id string) detect.DataType
}

// Counts summarises the report.
type Counts struct {
	NewFlows, NewLiterals, BaselinedFlows, BaselinedLiterals, Accepted int
}

// Counts computes summary numbers.
func (r *Report) Counts() Counts {
	var c Counts
	for _, f := range r.Flows {
		switch {
		case f.IsNew():
			c.NewFlows++
		case f.Violation:
			c.BaselinedFlows++
		default:
			c.Accepted++
		}
	}
	for _, l := range r.Literals {
		switch {
		case l.IsNew():
			c.NewLiterals++
		case l.Violation:
			c.BaselinedLiterals++
		}
	}
	return c
}

// HasNew reports whether there are new violations.
func (r *Report) HasNew() bool {
	c := r.Counts()
	return c.NewFlows+c.NewLiterals > 0
}

// Sort orders findings: new first, then by severity and location.
func (r *Report) Sort() {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(r.Flows, func(i, j int) bool {
		a, b := r.Flows[i], r.Flows[j]
		if a.IsNew() != b.IsNew() {
			return a.IsNew()
		}
		if a.Violation != b.Violation {
			return a.Violation
		}
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return posLess(a.Sink, b.Sink)
	})
	sort.SliceStable(r.Literals, func(i, j int) bool {
		a, b := r.Literals[i], r.Literals[j]
		if a.IsNew() != b.IsNew() {
			return a.IsNew()
		}
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return posLess(a.Pos, b.Pos)
	})
}

func posLess(a, b ir.Pos) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Col < b.Col
}

// Write renders the report in the named format.
func Write(w io.Writer, format string, r *Report) error {
	switch format {
	case "", "text":
		return Text(w, r)
	case "json":
		return JSON(w, r)
	case "sarif":
		return SARIF(w, r)
	case "markdown", "md":
		return Markdown(w, r)
	case "gitlab", "gitlab-sast":
		return GitLab(w, r)
	}
	return fmt.Errorf("unknown format %q (text, json, sarif, markdown, gitlab)", format)
}

func destLabel(d finding.Destination) string {
	kind := strings.ReplaceAll(d.Kind, "_", "-")
	switch {
	case d.Vendor != "" && d.Host != "":
		return fmt.Sprintf("%s / %s (%s)", d.Vendor, d.Host, kind)
	case d.Host != "":
		return fmt.Sprintf("%s (%s)", d.Host, kind)
	}
	return kind + " (unknown host)"
}

func (r *Report) dataType(id string) detect.DataType {
	if r.Catalog == nil {
		return detect.DataType{ID: id, Label: id}
	}
	return r.Catalog.Lookup(id)
}

func (r *Report) dtLabel(id string) string { return r.dataType(id).Label }

func (r *Report) message(f *finding.Flow) string {
	msg := fmt.Sprintf("%s from %s reaches %s via %s", r.dtLabel(f.DataType), f.SourceDesc, destLabel(f.Dest), f.SinkCall)
	if len(f.Transforms) > 0 {
		msg += fmt.Sprintf(" (after %s)", strings.Join(f.Transforms, ", "))
	}
	return msg
}

func (r *Report) literalMessage(l *finding.Literal) string {
	return fmt.Sprintf("%s committed to the repository: %s", r.dtLabel(l.DataType), l.Masked)
}

// Writer renders reports: the CLI's Reporter.
type Writer struct{}

// Write renders r in format (see Write).
func (Writer) Write(w io.Writer, format string, r *Report) error { return Write(w, format, r) }
