// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/ir"
)

// CommentMarker lets CI find and update its previous PR comment.
const CommentMarker = "<!-- datawarden-report -->"

// CILinks returns a link builder for GitHub Actions or GitLab CI based on
// their environment variables, or nil outside CI. getenv is injected
// (os.Getenv in production).
func CILinks(getenv func(string) string) func(p ir.Pos) string {
	if srv, repo, sha := getenv("GITHUB_SERVER_URL"), getenv("GITHUB_REPOSITORY"), getenv("GITHUB_SHA"); srv != "" && repo != "" && sha != "" {
		if h := getenv("DATAWARDEN_HEAD_SHA"); h != "" {
			sha = h
		}
		return func(p ir.Pos) string { return fmt.Sprintf("%s/%s/blob/%s/%s#L%d", srv, repo, sha, p.File, p.Line) }
	}
	if u, sha := getenv("CI_PROJECT_URL"), getenv("CI_COMMIT_SHA"); u != "" && sha != "" {
		return func(p ir.Pos) string { return fmt.Sprintf("%s/-/blob/%s/%s#L%d", u, sha, p.File, p.Line) }
	}
	return nil
}

func mdLoc(link func(ir.Pos) string, p ir.Pos) string {
	txt := fmt.Sprintf("`%s:%d`", p.File, p.Line)
	if link != nil {
		return fmt.Sprintf("[%s:%d](%s)", p.File, p.Line, link(p))
	}
	return txt
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Markdown renders a PR/MR summary comment.
func Markdown(w io.Writer, r *Report) error {
	r.Sort()
	link := r.Links
	c := r.Counts()
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	switch n := c.NewFlows + c.NewLiterals; {
	case n == 0:
		b.WriteString("### datawarden: no new sensitive-data leaks\n\n")
	default:
		fmt.Fprintf(&b, "### datawarden: %d new sensitive-data finding(s)\n\n", n)
	}
	scope := fmt.Sprintf("%s scan", r.Mode)
	if r.DiffBase != "" {
		scope += fmt.Sprintf(" against `%s`", r.DiffBase)
	}
	if r.Mode == "diff" {
		scope += fmt.Sprintf(" · %d changed file(s) + %d caller file(s)", len(r.ChangedFiles), len(r.CallerFiles))
	}
	fmt.Fprintf(&b, "%s · %d new flow(s) · %d new committed value(s) · %d baselined · %s\n\n", scope, c.NewFlows, c.NewLiterals, c.BaselinedFlows+c.BaselinedLiterals, r.Duration)

	if c.NewFlows > 0 {
		b.WriteString("#### New data flows\n\n| Severity | Data | Destination | Sink | Location |\n|---|---|---|---|---|\n")
		for _, f := range r.Flows {
			if !f.IsNew() {
				continue
			}
			data := fmt.Sprintf("**%s**<br><sub>%s</sub>", r.dtLabel(f.DataType), mdEscape(f.SourceDesc))
			if len(f.Transforms) > 0 {
				data += fmt.Sprintf("<br><sub>after %s</sub>", strings.Join(f.Transforms, ", "))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s |\n", f.Severity, data, mdEscape(destLabel(f.Dest)), f.SinkRule, mdLoc(link, f.Sink))
		}
		b.WriteString("\n<details><summary>Flow paths</summary>\n\n")
		for _, f := range r.Flows {
			if !f.IsNew() {
				continue
			}
			fmt.Fprintf(&b, "**%s → %s** in `%s` (confidence %.2f)\n\n", r.dtLabel(f.DataType), mdEscape(destLabel(f.Dest)), f.Function, f.Confidence)
			for i, p := range f.Path {
				note := ""
				switch i {
				case 0:
					note = " — source: " + mdEscape(f.SourceDesc)
				case len(f.Path) - 1:
					note = " — sink: `" + f.SinkCall + "`"
				}
				fmt.Fprintf(&b, "%d. %s%s\n", i+1, mdLoc(link, p), note)
			}
			b.WriteString("\n")
		}
		b.WriteString("</details>\n\n")
	}
	if c.NewLiterals > 0 {
		b.WriteString("#### Personal data committed to the repository\n\n| Severity | Type | Value (masked) | Location |\n|---|---|---|---|\n")
		for _, l := range r.Literals {
			if !l.IsNew() {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", l.Severity, r.dtLabel(l.DataType), l.Masked, mdLoc(link, l.Pos))
		}
		b.WriteString("\n")
	}
	if len(r.Warnings) > 0 {
		b.WriteString("<details><summary>Warnings</summary>\n\n")
		for _, wn := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", mdEscape(wn))
		}
		b.WriteString("\n</details>\n\n")
	}
	if c.NewFlows+c.NewLiterals > 0 {
		b.WriteString("<sub>Fix the flow (drop, mask or tokenize the data), allow it in `.datawarden.yaml` (`policy.allow`), or accept the current state with `datawarden baseline` and commit `.datawarden/baseline.json`.</sub>\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
