// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// WriteJSON writes the result as indented JSON, with precision, recall and
// F1 alongside the raw counts.
func WriteJSON(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// countsJSON is Counts with the derived metrics. It has no methods, so
// embedding it flattens its fields into the enclosing JSON object.
type countsJSON struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

func (c Counts) json() countsJSON {
	return countsJSON{c.TP, c.FP, c.FN, round3(c.Precision()), round3(c.Recall()), round3(c.F1())}
}

// MarshalJSON adds precision, recall and F1 to the counts. Outcome and
// Point embed Counts and would inherit this method, so they define their
// own.
func (c Counts) MarshalJSON() ([]byte, error) { return json.Marshal(c.json()) }

// MarshalJSON writes the counts and metrics next to the breakdowns.
func (o Outcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		countsJSON
		Ambiguous      int               `json:"ambiguous"`
		ByDataType     map[string]Counts `json:"by_data_type"`
		BySink         map[string]Counts `json:"by_sink"`
		Missed         []string          `json:"missed,omitempty"`
		FalsePositives []string          `json:"false_positives,omitempty"`
	}{o.Counts.json(), o.Ambiguous, o.ByDataType, o.BySink, o.Missed, o.FalsePositives})
}

// MarshalJSON writes the threshold next to the counts and metrics.
func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Threshold float64 `json:"threshold"`
		countsJSON
	}{p.Threshold, p.Counts.json()})
}

// WriteText writes aligned tables for a terminal.
func WriteText(w io.Writer, r *Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	b := &errWriter{w: tw}
	b.printf("case\tTP\tFP\tFN\tamb\tprecision\trecall\tF1\tscan median\talloc\tfiles\tfunctions\t\n")
	for _, c := range r.Cases {
		if c.Skipped != "" {
			continue
		}
		o, t := c.Outcome, c.Timing
		b.printf("%s\t%d\t%d\t%d\t%d\t%.2f\t%.2f\t%.2f\t%s\t%.1f MB\t%d\t%d\t\n", c.Name, o.TP, o.FP, o.FN, o.Ambiguous,
			o.Precision(), o.Recall(), o.F1(), ms(t.MedianMS), t.AllocMB, t.Files, t.Functions)
	}
	o := r.Total
	b.printf("total\t%d\t%d\t%d\t%d\t%.2f\t%.2f\t%.2f\t\t\t\t\t\n", o.TP, o.FP, o.FN, o.Ambiguous, o.Precision(), o.Recall(), o.F1())
	b.flush()
	writeList(b, "skipped", skipped(r), "  ", "")

	for _, sec := range []struct {
		title string
		m     map[string]Counts
	}{{"data type", o.ByDataType}, {"sink", o.BySink}} {
		b.printf("\nby %s\n", sec.title)
		b.printf("%s\tTP\tFP\tFN\tprecision\trecall\t\n", sec.title)
		for _, k := range sortedKeys(sec.m) {
			c := sec.m[k]
			b.printf("%s\t%d\t%d\t%d\t%.2f\t%.2f\t\n", k, c.TP, c.FP, c.FN, c.Precision(), c.Recall())
		}
		b.flush()
	}

	b.printf("\nconfidence sweep (reported = violations with confidence ≥ threshold)\n")
	b.printf("threshold\tTP\tFP\tFN\tprecision\trecall\tF1\t\n")
	for _, p := range r.Sweep {
		b.printf("%.2f\t%d\t%d\t%d\t%.2f\t%.2f\t%.2f\t\n", p.Threshold, p.TP, p.FP, p.FN, p.Precision(), p.Recall(), p.F1())
	}
	b.flush()

	writeList(b, "\nmissed (false negatives)", o.Missed, "  ", "")
	writeList(b, "\nfalse positives", o.FalsePositives, "  ", "")
	b.flush()
	return b.err
}

// WriteMarkdown writes the result for a CI job summary or a PR comment.
func WriteMarkdown(w io.Writer, r *Result) error {
	b := &errWriter{w: w}
	o := r.Total
	b.printf("## pii-scanner accuracy\n\n")
	b.printf("**Precision %.2f · recall %.2f · F1 %.2f** (%d TP, %d FP, %d FN", o.Precision(), o.Recall(), o.F1(), o.TP, o.FP, o.FN)
	if o.Ambiguous > 0 {
		b.printf(", %d ambiguous", o.Ambiguous)
	}
	b.printf(")\n\n")
	b.printf("| Case | TP | FP | FN | Precision | Recall | F1 | Scan (median) | Alloc | Files | Functions |\n")
	b.printf("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, c := range r.Cases {
		if c.Skipped != "" {
			continue
		}
		co, t := c.Outcome, c.Timing
		b.printf("| %s | %d | %d | %d | %.2f | %.2f | %.2f | %s | %.1f MB | %d | %d |\n", c.Name, co.TP, co.FP, co.FN,
			co.Precision(), co.Recall(), co.F1(), ms(t.MedianMS), t.AllocMB, t.Files, t.Functions)
	}
	if sk := skipped(r); len(sk) > 0 {
		b.printf("\nSkipped: %s\n", strings.Join(sk, "; "))
	}
	b.printf("\n<details><summary>By data type and sink</summary>\n\n")
	for _, sec := range []struct {
		title string
		m     map[string]Counts
	}{{"Data type", o.ByDataType}, {"Sink", o.BySink}} {
		b.printf("| %s | TP | FP | FN | Precision | Recall |\n|---|--:|--:|--:|--:|--:|\n", sec.title)
		for _, k := range sortedKeys(sec.m) {
			c := sec.m[k]
			b.printf("| `%s` | %d | %d | %d | %.2f | %.2f |\n", k, c.TP, c.FP, c.FN, c.Precision(), c.Recall())
		}
		b.printf("\n")
	}
	b.printf("</details>\n\n")
	b.printf("<details><summary>Confidence sweep</summary>\n\n")
	b.printf("| Threshold | TP | FP | FN | Precision | Recall | F1 |\n|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, p := range r.Sweep {
		b.printf("| %.2f | %d | %d | %d | %.2f | %.2f | %.2f |\n", p.Threshold, p.TP, p.FP, p.FN, p.Precision(), p.Recall(), p.F1())
	}
	b.printf("\n</details>\n")
	writeList(b, "\n**Missed**", o.Missed, "- ", "\n")
	writeList(b, "\n**False positives**", o.FalsePositives, "- ", "\n")
	return b.err
}

func skipped(r *Result) []string {
	var out []string
	for _, c := range r.Cases {
		if c.Skipped != "" {
			out = append(out, c.Name+" ("+c.Skipped+")")
		}
	}
	return out
}

func writeList(b *errWriter, title string, items []string, bullet, gap string) {
	if len(items) == 0 {
		return
	}
	b.printf("%s\n%s", title, gap)
	for _, s := range items {
		b.printf("%s%s\n", bullet, s)
	}
}

func ms(v float64) string {
	if v >= 1000 {
		return fmt.Sprintf("%.2fs", v/1000)
	}
	return fmt.Sprintf("%.0fms", v)
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}

func sortedKeys(m map[string]Counts) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// errWriter keeps the first write error so the report code stays linear.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

func (e *errWriter) flush() {
	if f, ok := e.w.(*tabwriter.Writer); ok && e.err == nil {
		e.err = f.Flush()
	}
}
