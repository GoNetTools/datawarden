// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/cli"
	"github.com/GoNetTools/datawarden/internal/finding"
)

type jsonReport struct {
	Mode     string             `json:"mode"`
	Flows    []*finding.Flow    `json:"flows"`
	Literals []*finding.Literal `json:"literals"`
	Warnings []string           `json:"warnings"`
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run(context.Background(), args)
	return code, out.String(), errb.String()
}

func scanJSON(t *testing.T, root string, extra ...string) (int, *jsonReport) {
	t.Helper()
	args := append([]string{"scan", "--root", root, "--no-cache", "--format", "json"}, extra...)
	code, out, errs := run(t, args...)
	if code == cli.ExitError {
		t.Fatalf("scan failed: %s", errs)
	}
	var r jsonReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	return code, &r
}

type want struct {
	dataType, rule, fn string
	violation          bool
}

func findFlow(r *jsonReport, w want) *finding.Flow {
	for _, f := range r.Flows {
		if f.DataType == w.dataType && f.SinkRule == w.rule && strings.HasSuffix(f.Function, w.fn) {
			return f
		}
	}
	return nil
}

func expectFlows(t *testing.T, r *jsonReport, wants []want) {
	t.Helper()
	for _, w := range wants {
		f := findFlow(r, w)
		if f == nil {
			t.Errorf("missing flow %+v", w)
			continue
		}
		if f.Violation != w.violation {
			t.Errorf("flow %+v: violation=%v (allowed=%q)", w, f.Violation, f.Allowed)
		}
	}
}

func TestScanGo(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	code, r := scanJSON(t, "../../testdata/goapp")
	if code != cli.ExitViolation {
		t.Errorf("exit = %d, want %d", code, cli.ExitViolation)
	}
	expectFlows(t, r, []want{
		{"email", "sdk.go.sentry.scope", "service.Register$1", true},
		{"national_id", "net.go.http_body", "service.sendSMS", true},
		{"phone", "log.go.stdlib", "service.Register", true},
		{"phone", "log.go.slog", "service.Handler", true},
		{"ip_address", "log.go.fmt_print", "service.Handler", true},
		{"phone", "log.go.stdlib", "service.Safe", false}, // masked
	})
	for _, f := range r.Flows {
		if strings.Contains(f.SourceDesc, "Nickname") || strings.Contains(f.SourceDesc, "Note") || strings.Contains(f.SourceDesc, ".ID") {
			t.Errorf("false positive: %+v", f)
		}
		if f.SinkRule == "net.go.http_body" && f.Dest.Host != "sms.vendor.example" {
			t.Errorf("host not extracted: %+v", f.Dest)
		}
	}
	lits := map[string]bool{}
	for _, l := range r.Literals {
		lits[l.DataType] = true
		if strings.Contains(l.Masked, "example.com") {
			t.Errorf("placeholder email reported: %+v", l)
		}
	}
	// Phone and national ID numbers are found through names, not as
	// committed values: only the email in the fixture is a literal.
	if !lits["email"] {
		t.Errorf("missing literal email: %+v", r.Literals)
	}
	if len(r.Literals) != 1 {
		t.Errorf("literals = %d, want 1 (placeholders filtered): %+v", len(r.Literals), r.Literals)
	}
}

func TestLiteralsOnly(t *testing.T) {
	code, r := scanJSON(t, "../../testdata/goapp", "--literals-only")
	if code != cli.ExitViolation || len(r.Flows) != 0 || len(r.Literals) == 0 || r.Mode != "literals" {
		t.Errorf("code=%d mode=%s flows=%d literals=%d", code, r.Mode, len(r.Flows), len(r.Literals))
	}
	// Pre-commit passes file names: only those files are scanned.
	code, r = scanJSON(t, "../../testdata/goapp", "--literals-only", "../../testdata/goapp/service/customer.go")
	if code != cli.ExitClean || len(r.Literals) != 0 {
		t.Errorf("file list: code=%d literals=%+v", code, r.Literals)
	}
}

func TestErrorsExit2(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".datawarden.yaml"), []byte("policy:\n  fail_on: [nowhere]\n"), 0o644)
	if code, _, _ := run(t, "scan", "--root", dir); code != cli.ExitError {
		t.Errorf("bad config: exit %d", code)
	}
	if code, _, _ := run(t, "frobnicate"); code != cli.ExitError {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, _, _ := run(t, "scan", "--format", "xml", "--root", dir, "--no-cache"); code != cli.ExitError {
		t.Errorf("unknown format: exit %d", code)
	}
}

func TestMapFormats(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	for _, f := range []string{"dpia", "json", "csv", "mermaid"} {
		code, out, errs := run(t, "map", "--root", "../../testdata/goapp", "--no-cache", "--format", f)
		if code != cli.ExitClean || out == "" {
			t.Errorf("map %s: code=%d err=%s", f, code, errs)
		}
		if f == "dpia" && (!strings.Contains(out, "Recipients") || !strings.Contains(out, "sentry.io") || !strings.Contains(out, "model.Customer")) {
			t.Errorf("dpia output incomplete:\n%s", out)
		}
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := run(t, "init", "--root", dir); code != cli.ExitClean {
		t.Fatalf("init: %s", errs)
	}
	for _, f := range []string{".datawarden.yaml", ".datawardenignore", ".datawarden/rules/example.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	// The generated config and rules must load.
	if code, _, errs := run(t, "rules", "--root", dir); code != cli.ExitClean {
		t.Errorf("rules with generated config: %s", errs)
	}
}
