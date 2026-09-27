// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Write renders explanations as text or JSON.
func (Explainer) Write(w io.Writer, format string, es []*Explanation) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if es == nil {
			es = []*Explanation{}
		}
		return enc.Encode(es)
	case "text", "":
		var b strings.Builder
		for i, e := range es {
			if i > 0 {
				b.WriteString("\n" + strings.Repeat("─", 72) + "\n\n")
			}
			writeText(&b, e)
		}
		_, err := io.WriteString(w, b.String())
		return err
	}
	return fmt.Errorf("unknown format %q (text, json)", format)
}

func writeText(b *strings.Builder, e *Explanation) {
	fmt.Fprintf(b, "%s  %s → %s  [%s]\n", e.Status, e.DataType, e.Sink.Dest, e.Sink.Rule)
	meta := []string{fmt.Sprintf("confidence %.2f", e.Confidence)}
	if e.Severity != "" {
		meta = append(meta, "severity "+e.Severity)
	}
	if e.Class != "" {
		meta = append(meta, "class "+e.Class)
	}
	if e.Fingerprint != "" {
		meta = append(meta, "fingerprint "+e.Fingerprint)
	}
	fmt.Fprintf(b, "%s\n", strings.Join(meta, " · "))

	fmt.Fprintf(b, "\nWhy the source is %s\n", e.DataType)
	fmt.Fprintf(b, "  %s  %s\n", e.Source.Pos, e.Source.Desc)
	code(b, e.Source.Pos.Line, e.Source.Code)
	for _, w := range e.Source.Why {
		fmt.Fprintf(b, "  - %s\n", w)
	}

	fmt.Fprintf(b, "\nPath\n")
	fn := ""
	for i, s := range e.Steps {
		if s.Func != "" && s.Func != fn {
			fmt.Fprintf(b, "  in %s\n", s.Func)
			fn = s.Func
		}
		fmt.Fprintf(b, "  %2d. %s  %s\n", i+1, s.Pos, s.What)
		code(b, s.Pos.Line, s.Code)
	}

	fmt.Fprintf(b, "\nWhy the sink matched\n")
	fmt.Fprintf(b, "  %s  %s in %s\n", e.Sink.Pos, e.Sink.Call, e.Sink.Func)
	fmt.Fprintf(b, "  rule %s", e.Sink.Rule)
	if e.Sink.Description != "" {
		fmt.Fprintf(b, ": %s", e.Sink.Description)
	}
	b.WriteString("\n")
	if e.Sink.Why != "" {
		fmt.Fprintf(b, "  - %s\n", e.Sink.Why)
	}
	fmt.Fprintf(b, "  - destination: %s\n", e.Sink.Dest)

	fmt.Fprintf(b, "\nPolicy: %s\n", e.Status)
	fmt.Fprintf(b, "  %s\n", e.Policy.Reason)
	if len(e.Policy.Changes) > 0 {
		b.WriteString("  What would change it:\n")
		for _, c := range e.Policy.Changes {
			fmt.Fprintf(b, "  - %s\n", c)
		}
	}

	if len(e.Silence) > 0 {
		b.WriteString("\nTo silence it, when it is not a leak (narrowest first; see docs/FINDINGS.md)\n")
		for i, o := range e.Silence {
			fmt.Fprintf(b, "  %d. When %s:\n", i+1, o.When)
			for _, l := range strings.Split(o.Do, "\n") {
				fmt.Fprintf(b, "       %s\n", l)
			}
		}
	}
}

func code(b *strings.Builder, line int, text string) {
	if text != "" {
		fmt.Fprintf(b, "      %4d │ %s\n", line, text)
	}
}
