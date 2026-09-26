// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

type catalog map[string]string

func (c catalog) Lookup(id string) detect.DataType { return detect.DataType{ID: id, Label: c[id]} }

func sample() *Report {
	return &Report{
		Tool: "datawarden", Version: "t", Mode: "full", Started: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Duration: "2s",
		Flows: []*finding.Flow{{DataType: "national_id", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Violation: true, Severity: "high",
			Sink: ir.Pos{File: "a.go", Line: 4}, Path: []ir.Pos{{File: "a.go", Line: 1}, {File: "a.go", Line: 4}}, Fingerprint: "fp"}},
		Catalog: catalog{"national_id": "National ID number"},
	}
}

func TestLabelsAndLinksAreInjected(t *testing.T) {
	r := sample()
	r.Links = CILinks(func(k string) string {
		return map[string]string{"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "acme/app", "GITHUB_SHA": "abc"}[k]
	})
	var b bytes.Buffer
	if err := Markdown(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "National ID number") || !strings.Contains(out, "https://github.com/acme/app/blob/abc/a.go#L4") {
		t.Errorf("markdown:\n%s", out)
	}
	if CILinks(func(string) string { return "" }) != nil {
		t.Error("no CI environment should mean no links")
	}
}

func TestGitLabUsesReportStartTime(t *testing.T) {
	var b bytes.Buffer
	if err := GitLab(&b, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"start_time": "2026-09-24T00:00:00"`) || !strings.Contains(b.String(), `"end_time": "2026-09-24T00:00:02"`) {
		t.Errorf("gitlab:\n%s", b.String())
	}
}

func TestWithoutCatalogFallsBackToIDs(t *testing.T) {
	r := sample()
	r.Catalog = nil
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil || !strings.Contains(b.String(), "national_id from") {
		t.Errorf("sarif: %v\n%s", err, b.String())
	}
}

// --call-graph prints each flow's call tree in text and Markdown.
func TestCallGraph(t *testing.T) {
	r := &Report{Tool: "datawarden", ShowCalls: true, Flows: []*finding.Flow{{
		DataType: "email", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Violation: true, Severity: "medium",
		Function: "app.Repo.save", Sink: ir.Pos{File: "a.kt", Line: 9},
		Path: []ir.Pos{{File: "a.kt", Line: 2}, {File: "a.kt", Line: 9}},
		Calls: []finding.CallStep{
			{Function: "app.Ui.submit", Pos: ir.Pos{File: "a.kt", Line: 2}},
			{Function: "app.Repo.save", Pos: ir.Pos{File: "a.kt", Line: 9}, Depth: 1},
		},
		CalledBy: []string{"app.Ui.onClick"},
	}, {
		DataType: "phone", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Violation: true, Severity: "medium",
		Function: "app.Ui.track", Sink: ir.Pos{File: "a.kt", Line: 20},
	}}}
	var text bytes.Buffer
	if err := Text(&text, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"calls   app.Ui.submit  a.kt:2  (source)",
		"        └─ app.Repo.save  a.kt:9  (sink)",
		"called by  app.Ui.onClick",
		"calls   app.Ui.track  a.kt:20  (source and sink)",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
	var md bytes.Buffer
	if err := Markdown(&md, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "  - `app.Repo.save` `a.kt:9`") || !strings.Contains(md.String(), "Called by: `app.Ui.onClick`") {
		t.Errorf("markdown:\n%s", md.String())
	}
	r.ShowCalls = false
	text.Reset()
	if err := Text(&text, r); err != nil || strings.Contains(text.String(), "calls ") {
		t.Errorf("without --call-graph:\n%s", text.String())
	}
}
