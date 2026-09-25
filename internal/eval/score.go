// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/finding"
)

// Counts are true positives, false positives and false negatives.
//
// TP counts labels that at least one finding matches, so a leak reported
// twice (two paths to the same sink) is one true positive, not a false
// positive.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// Precision is TP/(TP+FP), or 1 when nothing was reported.
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall is TP/(TP+FN), or 1 when nothing was expected.
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// F1 is the harmonic mean of precision and recall.
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func (c *Counts) add(o Counts) {
	c.TP += o.TP
	c.FP += o.FP
	c.FN += o.FN
}

// Outcome is the score of one case, or of all cases added together.
type Outcome struct {
	Counts
	// Ambiguous counts findings that matched an ambiguous label.
	Ambiguous int `json:"ambiguous"`
	// ByDataType and BySink break the counts down by data type and by sink
	// category (the first segment of the rule id: log, sdk, net, storage,
	// …; "literal" for committed values).
	ByDataType map[string]Counts `json:"by_data_type"`
	BySink     map[string]Counts `json:"by_sink"`
	// Missed and FalsePositives describe the errors, for the report.
	Missed         []string `json:"missed,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty"`
}

func newOutcome() Outcome {
	return Outcome{ByDataType: map[string]Counts{}, BySink: map[string]Counts{}}
}

func (o *Outcome) count(dataType, sink string, c Counts) {
	o.Counts.add(c)
	dt, sk := o.ByDataType[dataType], o.BySink[sink]
	dt.add(c)
	sk.add(c)
	o.ByDataType[dataType], o.BySink[sink] = dt, sk
}

func (o *Outcome) add(name string, x Outcome) {
	o.Counts.add(x.Counts)
	o.Ambiguous += x.Ambiguous
	for k, c := range x.ByDataType {
		v := o.ByDataType[k]
		v.add(c)
		o.ByDataType[k] = v
	}
	for k, c := range x.BySink {
		v := o.BySink[k]
		v.add(c)
		o.BySink[k] = v
	}
	for _, m := range x.Missed {
		o.Missed = append(o.Missed, name+": "+m)
	}
	for _, f := range x.FalsePositives {
		o.FalsePositives = append(o.FalsePositives, name+": "+f)
	}
}

// Score compares a case's labels with the reported findings. Only
// violations count as reported, and only those with at least minConf
// confidence (0 keeps every violation).
func Score(c *Case, flows []*finding.Flow, lits []*finding.Literal, minConf float64) Outcome {
	o := newOutcome()

	matched := make([]bool, len(c.Flows))
	for _, f := range flows {
		if !f.Violation || f.Confidence < minConf {
			continue
		}
		hit := false
		for i, l := range c.Flows {
			if l.matches(f) {
				matched[i], hit = true, true
			}
		}
		if hit {
			continue
		}
		if matchesAny(c.Ambiguous, f) {
			o.Ambiguous++
			continue
		}
		o.count(f.DataType, sinkCategory(f.SinkRule), Counts{FP: 1})
		o.FalsePositives = append(o.FalsePositives, fmt.Sprintf("%s → %s in %s (%s:%d, confidence %.2f)",
			f.DataType, f.SinkRule, f.Function, f.Sink.File, f.Sink.Line, f.Confidence))
	}
	for i, l := range c.Flows {
		if matched[i] {
			o.count(l.DataType, sinkCategory(l.SinkRule), Counts{TP: 1})
		} else {
			o.count(l.DataType, sinkCategory(l.SinkRule), Counts{FN: 1})
			o.Missed = append(o.Missed, withNote(l.String(), l.Note))
		}
	}

	matchedL := make([]bool, len(c.Literals))
	for _, x := range lits {
		if !x.Violation || x.Confidence < minConf {
			continue
		}
		hit := false
		for i, l := range c.Literals {
			if l.DataType == x.DataType && l.File == x.Pos.File && l.Line == x.Pos.Line {
				matchedL[i], hit = true, true
			}
		}
		if !hit {
			o.count(x.DataType, "literal", Counts{FP: 1})
			o.FalsePositives = append(o.FalsePositives, fmt.Sprintf("%s literal at %s:%d (%s, confidence %.2f)",
				x.DataType, x.Pos.File, x.Pos.Line, x.Detector, x.Confidence))
		}
	}
	for i, l := range c.Literals {
		if matchedL[i] {
			o.count(l.DataType, "literal", Counts{TP: 1})
		} else {
			o.count(l.DataType, "literal", Counts{FN: 1})
			o.Missed = append(o.Missed, withNote(l.String(), l.Note))
		}
	}
	sort.Strings(o.FalsePositives)
	return o
}

func (l FlowLabel) matches(f *finding.Flow) bool {
	return l.DataType == f.DataType && l.SinkRule == f.SinkRule && nameSuffix(f.Function, l.Function)
}

func matchesAny(ls []FlowLabel, f *finding.Flow) bool {
	for _, l := range ls {
		if l.matches(f) {
			return true
		}
	}
	return false
}

// nameSuffix reports whether name ends with suffix at a name boundary:
// the whole name, or preceded by '.', ':' or '/'.
func nameSuffix(name, suffix string) bool {
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	if len(name) == len(suffix) {
		return true
	}
	switch name[len(name)-len(suffix)-1] {
	case '.', ':', '/':
		return true
	}
	return false
}

func sinkCategory(rule string) string {
	cat, _, _ := strings.Cut(rule, ".")
	return cat
}

func withNote(s, note string) string {
	if note == "" {
		return s
	}
	return s + " — " + note
}
