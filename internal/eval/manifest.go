// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package eval measures how well datawarden finds leaks in a labelled corpus:
// precision, recall and F1 per case, data type and sink category, a sweep
// over confidence thresholds, and scan timings.
//
// A manifest (testdata/eval.yaml) lists cases. Each case is a directory to
// scan plus the leaks a careful reviewer would report in it. Findings that
// match a label are true positives, labels no finding matches are false
// negatives, and every other reported violation is a false positive.
package eval

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultThresholds are the confidence thresholds swept when the manifest
// sets none.
var DefaultThresholds = []float64{0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95}

// Manifest is a labelled corpus.
type Manifest struct {
	// Thresholds are the confidence thresholds for the sweep.
	Thresholds []float64 `yaml:"thresholds"`
	Cases      []Case    `yaml:"cases"`
}

// Case is one directory scanned as a repository root, with its labels.
type Case struct {
	Name string `yaml:"name"`
	// Dir is relative to the manifest's directory (or absolute); for an
	// external case, relative to the fetched repository.
	Dir string `yaml:"dir"`
	// Repo and Commit make the case external: an open-source repository
	// fetched at that commit (datawarden-bench -external), so its code is
	// scanned as published and never copied into this repository.
	Repo   string `yaml:"repo"`
	Commit string `yaml:"commit"`
	// Langs are the frontends the case needs; it is skipped when one is
	// missing from the build (tree-sitter languages without cgo).
	Langs []string `yaml:"langs"`
	// MinPrecision and MinRecall fail Check when the case scores lower.
	MinPrecision float64 `yaml:"min_precision"`
	MinRecall    float64 `yaml:"min_recall"`
	// Flows and Literals are the leaks that should be reported.
	Flows    []FlowLabel    `yaml:"flows"`
	Literals []LiteralLabel `yaml:"literals"`
	// Ambiguous flows are acceptable either way (e.g. data sent to a host
	// that may be first party). Matching findings count as neither true
	// nor false positives.
	Ambiguous []FlowLabel `yaml:"ambiguous"`
}

// FlowLabel identifies an expected source-to-sink flow.
type FlowLabel struct {
	DataType string `yaml:"data_type"`
	SinkRule string `yaml:"sink_rule"`
	// Function is the enclosing function of the sink, matched as a suffix
	// on a name boundary: "service.Register" matches
	// "example.com/app/service.Register" but not "service.PreRegister".
	Function string `yaml:"function"`
	Note     string `yaml:"note"`
}

// LiteralLabel identifies a committed personal-data value.
type LiteralLabel struct {
	DataType string `yaml:"data_type"`
	// File is relative to the case directory, slash-separated.
	File string `yaml:"file"`
	Line int    `yaml:"line"`
	Note string `yaml:"note"`
}

func (l FlowLabel) String() string {
	return fmt.Sprintf("%s → %s in %s", l.DataType, l.SinkRule, l.Function)
}

func (l LiteralLabel) String() string {
	return fmt.Sprintf("%s literal at %s:%d", l.DataType, l.File, l.Line)
}

// Parse decodes and validates a manifest. Unknown keys are errors, so a
// misspelt label field cannot silently match everything.
func Parse(b []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("eval manifest: %w", err)
	}
	if len(m.Thresholds) == 0 {
		m.Thresholds = append([]float64(nil), DefaultThresholds...)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("eval manifest: %w", err)
	}
	return &m, nil
}

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// External reports whether the case is fetched from a repository.
func (c *Case) External() bool { return c.Repo != "" }

func (m *Manifest) validate() error {
	var errs []error
	for i, t := range m.Thresholds {
		if t <= 0 || t > 1 || (i > 0 && t <= m.Thresholds[i-1]) {
			errs = append(errs, fmt.Errorf("thresholds must be increasing values in (0, 1]: %v", m.Thresholds))
			break
		}
	}
	if len(m.Cases) == 0 {
		errs = append(errs, errors.New("no cases"))
	}
	seen := map[string]bool{}
	for i, c := range m.Cases {
		where := fmt.Sprintf("case %d", i+1)
		if c.Name != "" {
			where = "case " + c.Name
		}
		switch {
		case c.Name == "":
			errs = append(errs, fmt.Errorf("%s: missing name", where))
		case seen[c.Name]:
			errs = append(errs, fmt.Errorf("%s: duplicate name", where))
		}
		seen[c.Name] = true
		if c.Dir == "" {
			errs = append(errs, fmt.Errorf("%s: missing dir", where))
		}
		if (c.Repo == "") != (c.Commit == "") || c.Commit != "" && !fullCommit.MatchString(c.Commit) {
			errs = append(errs, fmt.Errorf("%s: an external case needs a repo and a full commit hash", where))
		}
		if c.MinPrecision < 0 || c.MinPrecision > 1 || c.MinRecall < 0 || c.MinRecall > 1 {
			errs = append(errs, fmt.Errorf("%s: min_precision and min_recall must be in [0, 1]", where))
		}
		for _, l := range append(append([]FlowLabel(nil), c.Flows...), c.Ambiguous...) {
			if l.DataType == "" || l.SinkRule == "" || l.Function == "" {
				errs = append(errs, fmt.Errorf("%s: flow label needs data_type, sink_rule and function: %+v", where, l))
			}
		}
		for _, l := range c.Literals {
			if l.DataType == "" || l.File == "" || l.Line <= 0 || strings.Contains(l.File, `\`) {
				errs = append(errs, fmt.Errorf("%s: literal label needs data_type, a slash-separated file and a line: %+v", where, l))
			}
		}
	}
	return errors.Join(errs...)
}
