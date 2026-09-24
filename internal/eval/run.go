// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/finding"
)

// Scan is the outcome of one scan of a case directory.
type Scan struct {
	Flows    []*finding.Flow
	Literals []*finding.Literal
	// Wall is the elapsed time of the scan, AllocBytes the memory the
	// process allocated during it (0 when not measured).
	Wall       time.Duration
	AllocBytes uint64
	Files      int
	Functions  int
}

// Scanner scans dir as a repository root with the repository's policy,
// without cache or baseline. minConf > 0 overrides policy.min_confidence.
type Scanner func(ctx context.Context, dir string, minConf float64) (*Scan, error)

// Options configure Run.
type Options struct {
	Manifest *Manifest
	// BaseDir resolves relative case directories (the manifest's directory).
	BaseDir string
	Scan    Scanner
	// Available reports whether a language has a frontend in this build;
	// nil means all are available.
	Available func(lang string) bool
	// Runs is how many times each case is scanned for timing (default 1).
	// Findings come from the first run.
	Runs int
}

// Timing summarises the runs of one case.
type Timing struct {
	Runs      int     `json:"runs"`
	MedianMS  float64 `json:"median_ms"`
	MinMS     float64 `json:"min_ms"`
	MaxMS     float64 `json:"max_ms"`
	AllocMB   float64 `json:"alloc_mb"` // median
	Files     int     `json:"files"`
	Functions int     `json:"functions"`
}

// Point is the score at one confidence threshold.
type Point struct {
	Threshold float64 `json:"threshold"`
	Counts
}

// CaseResult is the result of one case.
type CaseResult struct {
	Name string `json:"name"`
	// Skipped says why the case did not run; the other fields are empty.
	Skipped string  `json:"skipped,omitempty"`
	Outcome Outcome `json:"outcome"`
	Sweep   []Point `json:"sweep,omitempty"`
	Timing  Timing  `json:"timing"`
}

// Result is the result of a whole manifest.
type Result struct {
	Cases []CaseResult `json:"cases"`
	// Total adds up the cases that ran.
	Total Outcome `json:"total"`
	Sweep []Point `json:"sweep"`
}

// Run scans every case and scores it. Each case is scanned Runs times with
// the default policy, plus once at the lowest sweep threshold so flows the
// policy would drop for low confidence still take part in the sweep.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Manifest == nil || o.Scan == nil {
		return nil, errors.New("eval: Manifest and Scan are required")
	}
	runs := o.Runs
	if runs < 1 {
		runs = 1
	}
	m := o.Manifest
	res := &Result{Total: newOutcome()}
	total := make([]Counts, len(m.Thresholds))
	for i := range m.Cases {
		c := &m.Cases[i]
		cr := CaseResult{Name: c.Name}
		if missing := missingLangs(c.Langs, o.Available); len(missing) > 0 {
			cr.Skipped = "no frontend for " + strings.Join(missing, ", ") + " in this build"
			res.Cases = append(res.Cases, cr)
			continue
		}
		dir := c.Dir
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(o.BaseDir, filepath.FromSlash(dir))
		}
		scans := make([]*Scan, 0, runs)
		for r := 0; r < runs; r++ {
			s, err := o.Scan(ctx, dir, 0)
			if err != nil {
				return nil, fmt.Errorf("case %s: %w", c.Name, err)
			}
			scans = append(scans, s)
		}
		cr.Outcome = Score(c, scans[0].Flows, scans[0].Literals, 0)
		cr.Timing = timing(scans)

		low, err := o.Scan(ctx, dir, m.Thresholds[0])
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.Name, err)
		}
		for j, t := range m.Thresholds {
			p := Point{Threshold: t, Counts: Score(c, low.Flows, low.Literals, t).Counts}
			cr.Sweep = append(cr.Sweep, p)
			total[j].add(p.Counts)
		}
		res.Total.add(c.Name, cr.Outcome)
		res.Cases = append(res.Cases, cr)
	}
	for j, t := range m.Thresholds {
		res.Sweep = append(res.Sweep, Point{Threshold: t, Counts: total[j]})
	}
	return res, nil
}

func missingLangs(langs []string, available func(string) bool) []string {
	if available == nil {
		return nil
	}
	var out []string
	for _, l := range langs {
		if !available(l) {
			out = append(out, l)
		}
	}
	return out
}

func timing(scans []*Scan) Timing {
	walls := make([]float64, len(scans))
	allocs := make([]float64, len(scans))
	for i, s := range scans {
		walls[i] = float64(s.Wall.Microseconds()) / 1000
		allocs[i] = float64(s.AllocBytes) / (1 << 20)
	}
	sort.Float64s(walls)
	sort.Float64s(allocs)
	return Timing{
		Runs: len(scans), MedianMS: median(walls), MinMS: walls[0], MaxMS: walls[len(walls)-1],
		AllocMB: median(allocs), Files: scans[0].Files, Functions: scans[0].Functions,
	}
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// epsilon absorbs rounding when a threshold is written as a decimal
// (min_recall: 0.9 for 9 of 10).
const epsilon = 1e-9

// Check returns the cases that score below their min_precision or
// min_recall. Skipped cases are not failures.
func (r *Result) Check(m *Manifest) []string {
	want := map[string]*Case{}
	for i := range m.Cases {
		want[m.Cases[i].Name] = &m.Cases[i]
	}
	var fails []string
	for _, cr := range r.Cases {
		c := want[cr.Name]
		if cr.Skipped != "" || c == nil {
			continue
		}
		if p := cr.Outcome.Precision(); p < c.MinPrecision-epsilon {
			fails = append(fails, fmt.Sprintf("%s: precision %.3f < min_precision %.3f", cr.Name, p, c.MinPrecision))
		}
		if rc := cr.Outcome.Recall(); rc < c.MinRecall-epsilon {
			fails = append(fails, fmt.Sprintf("%s: recall %.3f < min_recall %.3f", cr.Name, rc, c.MinRecall))
		}
	}
	return fails
}
