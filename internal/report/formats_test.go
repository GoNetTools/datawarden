// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/rules"
)

type ruleLookup map[string]*rules.Rule

func (m ruleLookup) ByID(id string) *rules.Rule { return m[id] }

// rich covers every kind of finding a report shows: new, baselined,
// allowed by policy and informational flows, and new and baselined
// literals, in a diff scan with warnings.
func rich() *Report {
	pos := func(line int) ir.Pos { return ir.Pos{File: "app/Repo.kt", Line: line} }
	flow := func(dt, rule, sev string, line int) *finding.Flow {
		return &finding.Flow{DataType: dt, SinkRule: rule, Severity: sev, Source: pos(1), Sink: pos(line),
			Path: []ir.Pos{pos(1), pos(2), pos(line)}, Function: "com.acme.Repo.save", SourceDesc: `identifier "email"`,
			SinkCall: "io.sentry.Sentry.setUser", Dest: finding.Destination{Kind: "third_party", Host: "sentry.io", Vendor: "Sentry"},
			Confidence: 0.9, Fingerprint: "fp-" + rule + dt}
	}
	fresh := flow("email", "sdk.sentry.set_user", "high", 9)
	fresh.Violation = true
	old := flow("phone", "log.android.logcat", "medium", 12)
	old.Violation, old.Baselined, old.Dest = true, true, finding.Destination{Kind: "log", Host: "logcat"}
	allowed := flow("email", "log.android.logcat", "low", 14)
	allowed.Allowed, allowed.Transforms = "transform: masked", []string{"masked"}
	info := flow("dob", "storage.go.sql", "low", 16)
	info.Dest = finding.Destination{Kind: "first_party", Host: "database", FirstParty: true}
	lit := &finding.Literal{DataType: "phone", Pos: ir.Pos{File: "seed.csv", Line: 2}, Masked: "097*****85", Detector: "vn-mobile-prefix",
		Confidence: 0.7, Violation: true, Severity: "medium", Fingerprint: "lit1"}
	oldLit := &finding.Literal{DataType: "email", Pos: ir.Pos{File: "seed.csv", Line: 3}, Masked: "t***@x.vn", Detector: "email-format",
		Confidence: 0.9, Violation: true, Baselined: true, Severity: "medium", Fingerprint: "lit2"}
	return &Report{
		Tool: "datawarden", Version: "t", Mode: "diff", DiffBase: "origin/main", Commit: "abc123",
		Started: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Duration: "1.5s",
		FilesScanned: 3, FilesAnalyzed: map[string]int{"kotlin": 2, "go": 1}, Functions: 7,
		ChangedFiles: []string{"app/Repo.kt"}, CallerFiles: []string{"app/Main.kt"},
		Flows: []*finding.Flow{info, allowed, old, fresh}, Literals: []*finding.Literal{oldLit, lit},
		Warnings: []string{"typescript: 1 file skipped"}, BaselineSize: 2, BaselineFixed: 1,
		Rules: ruleLookup{"sdk.sentry.set_user": {ID: "sdk.sentry.set_user", Description: "Sentry user context", Category: "crash_reporting"}},
	}
}

func render(t *testing.T, format string, r *Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := (Writer{}).Write(&b, format, r); err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	return b.String()
}

func TestCounts(t *testing.T) {
	r := rich()
	c := r.Counts()
	if c.NewFlows != 1 || c.BaselinedFlows != 1 || c.Accepted != 2 || c.NewLiterals != 1 || c.BaselinedLiterals != 1 || !r.HasNew() {
		t.Errorf("counts: %+v", c)
	}
	r.Flows, r.Literals = r.Flows[:3], r.Literals[:1]
	if r.HasNew() {
		t.Error("only baselined and accepted findings left")
	}
}

func TestTextReport(t *testing.T) {
	r := rich()
	out := render(t, "text", r)
	for _, want := range []string{
		"datawarden t · diff scan vs origin/main · 3 files (go:1 kotlin:2) · 7 functions · 1.5s",
		"changed: 1 files, callers: 1 files",
		"warning: typescript: 1 file skipped",
		"NEW      high   email → Sentry / sentry.io (third-party)  [sdk.sentry.set_user]",
		"BASELINE medium phone",
		"app/Repo.kt:1 → :2 → :9",
		"097*****85",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ALLOWED") || strings.Contains(out, "INFO ") {
		t.Errorf("accepted flows are hidden without --all:\n%s", out)
	}
	r.ShowAll = true
	out = render(t, "", r) // the default format is text
	if !strings.Contains(out, "ALLOWED  low    email") || !strings.Contains(out, "INFO     low    dob") {
		t.Errorf("--all shows accepted flows:\n%s", out)
	}
}

func TestMarkdownReport(t *testing.T) {
	out := render(t, "md", rich())
	for _, want := range []string{CommentMarker, "email", "sdk.sentry.set_user", "097*****85"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
	r := rich()
	r.Flows, r.Literals = nil, nil
	if out := render(t, "markdown", r); !strings.Contains(out, "no new sensitive-data leaks") {
		t.Errorf("clean report:\n%s", out)
	}
}

func TestJSONReport(t *testing.T) {
	var got struct {
		Tool     string            `json:"tool"`
		Flows    []finding.Flow    `json:"flows"`
		Literals []finding.Literal `json:"literals"`
	}
	if err := json.Unmarshal([]byte(render(t, "json", rich())), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "datawarden" || len(got.Flows) != 4 || len(got.Literals) != 2 || !got.Flows[0].Violation || got.Flows[0].Baselined {
		t.Errorf("json: %+v", got)
	}
}

func TestSARIFReport(t *testing.T) {
	var got struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID, Name string
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				BaselineState       string            `json:"baselineState"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(render(t, "sarif", rich())), &got); err != nil {
		t.Fatal(err)
	}
	run := got.Runs[0]
	names := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		names[r.Name] = true
	}
	if !names["SensitiveDataFlowSdkSentrySetUser"] || !names["CommittedSensitiveValuePhone"] {
		t.Errorf("rules: %+v", run.Tool.Driver.Rules)
	}
	states := map[string]int{}
	for _, res := range run.Results {
		if res.PartialFingerprints["datawarden/v1"] == "" {
			t.Errorf("result without fingerprint: %+v", res)
		}
		states[res.BaselineState]++
	}
	if states["new"] != 2 || states["unchanged"] != 2 {
		t.Errorf("baseline states: %v", states)
	}
}

func TestGitLabSeverities(t *testing.T) {
	var got struct {
		Vulnerabilities []struct {
			Severity    string `json:"severity"`
			Identifiers []struct {
				Type string `json:"type"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(render(t, "gitlab", rich())), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Vulnerabilities) != 2 { // new violations only
		t.Fatalf("vulnerabilities: %+v", got.Vulnerabilities)
	}
	sev := map[string]bool{}
	for _, v := range got.Vulnerabilities {
		sev[v.Severity] = true
		if v.Identifiers[0].Type != "datawarden_rule" {
			t.Errorf("identifiers: %+v", v.Identifiers)
		}
	}
	if !sev["High"] || !sev["Medium"] {
		t.Errorf("severities: %v", sev)
	}
	for in, want := range map[string]string{"high": "High", "medium": "Medium", "low": "Low", "": "Low"} {
		if got := glSeverity(in); got != want {
			t.Errorf("glSeverity(%q) = %q", in, got)
		}
	}
}

func TestUnknownFormatAndGitLabLinks(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", rich()); err == nil {
		t.Error("unknown format accepted")
	}
	links := CILinks(func(k string) string {
		return map[string]string{"CI_PROJECT_URL": "https://gitlab.example/acme/app", "CI_COMMIT_SHA": "def"}[k]
	})
	if links == nil || links(ir.Pos{File: "a.go", Line: 3}) != "https://gitlab.example/acme/app/-/blob/def/a.go#L3" {
		t.Error("GitLab links")
	}
	head := CILinks(func(k string) string {
		return map[string]string{"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "a/b", "GITHUB_SHA": "merge", "DATAWARDEN_HEAD_SHA": "head"}[k]
	})
	if got := head(ir.Pos{File: "x.ts", Line: 1}); got != "https://github.com/a/b/blob/head/x.ts#L1" {
		t.Errorf("PR head sha: %s", got)
	}
}
