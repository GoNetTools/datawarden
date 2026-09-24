// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/cli"
)

func TestScanKotlinJava(t *testing.T) {
	code, r := scanJSON(t, "../../testdata/android")
	if code != cli.ExitViolation {
		t.Errorf("exit = %d", code)
	}
	expectFlows(t, r, []want{
		{"email", "sdk.sentry.set_user", "CustomerRepo.save", true},
		{"vn_cccd", "sdk.firebase.crashlytics.custom_key", "CustomerRepo.save", true},
		{"phone", "sdk.firebase.analytics", "SignupViewModel.submit", true},
		{"phone", "log.android.logcat", "CustomerRepo.save", true},
		{"phone", "storage.android.shared_prefs", "CustomerRepo.save", true},
		{"dob", "log.jvm.stdout", "SignupViewModel.track", true},
		{"phone", "log.android.logcat", "CustomerRepo.audit", false}, // masked by String.maskPhone()
		{"email", "sdk.sentry.set_extra", "ProfileActivity.show", true},
		{"email", "log.android.logcat", "ProfileActivity.send", true},
		{"person_name", "log.android.logcat", "ProfileActivity.show", true},
	})
	for _, f := range r.Flows {
		if f.SinkRule == "log.jvm.stdout" && strings.HasSuffix(f.Function, "ProfileActivity.show") {
			t.Errorf("getBio() should not carry the profile's email: %+v", f)
		}
		if f.SinkRule == "log.android.logcat" && strings.Contains(f.SourceDesc, "nickname") {
			t.Errorf("nickname is not PII: %+v", f)
		}
	}
}

func TestScanTypeScript(t *testing.T) {
	_, r := scanJSON(t, "../../testdata/web")
	expectFlows(t, r, []want{
		{"email", "sdk.ts.sentry.set_user", "UserService.register", true},
		{"phone", "sdk.ts.mixpanel", "UserService.register", true},
		{"vn_cccd", "net.ts.axios", "UserService.register", true},
		{"dob", "storage.ts.web_storage", "UserService.register", true},
		{"email", "storage.ts.web_storage", "onLogin", true},
		{"phone", "log.ts.console", "logInfo", true},
		{"email", "log.ts.console", "UserService.register", false}, // maskEmail()
	})
	f := findFlow(r, want{"vn_cccd", "net.ts.axios", "UserService.register", true})
	if f != nil && f.Dest.Host != "api.partner-crm.io" {
		t.Errorf("axios host: %+v", f.Dest)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.test", "-c", "user.name=t", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(target, b, 0o644)
	})
}

func TestBaselineDiffAndSARIF(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	copyTree(t, "../../testdata/web", dir)
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-qm", "init")

	if code, _, errs := run(t, "baseline", "--root", dir); code != cli.ExitClean {
		t.Fatalf("baseline: %s", errs)
	}
	if code, out, _ := run(t, "scan", "--root", dir); code != cli.ExitClean {
		t.Fatalf("after baseline exit=%d\n%s", code, out)
	}
	// Moving code around must not create new alerts.
	p := filepath.Join(dir, "src/api/user.ts")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append([]byte("// moved\n\n\n"), b...), 0o644)
	if code, out, _ := run(t, "scan", "--root", dir); code != cli.ExitClean {
		t.Fatalf("line shift created alerts: exit=%d\n%s", code, out)
	}
	git(t, dir, "checkout", "-q", "--", ".")

	// A PR that only changes the callee: the new flow is found through the
	// cached call graph (user.ts is not in the diff).
	git(t, dir, "checkout", "-qb", "feature")
	mask := filepath.Join(dir, "src/lib/mask.ts")
	mb, _ := os.ReadFile(mask)
	mb = append([]byte("import * as Sentry from \"@sentry/react\";\n"), mb...)
	mb = []byte(strings.Replace(string(mb), "console.info(message, data);", "console.info(message, data);\n  Sentry.addBreadcrumb({ message, data });", 1))
	os.WriteFile(mask, mb, 0o644)
	git(t, dir, "commit", "-qam", "breadcrumbs")
	sarif := filepath.Join(dir, "out.sarif")
	code, out, errs := run(t, "scan", "--root", dir, "--diff", "main", "--format", "json", "--sarif", sarif)
	if code != cli.ExitViolation {
		t.Fatalf("diff exit=%d %s\n%s", code, errs, out)
	}
	var r jsonReport
	json.Unmarshal([]byte(out), &r)
	if r.Mode != "diff" {
		t.Errorf("mode=%s warnings=%v", r.Mode, r.Warnings)
	}
	nf := findFlow(&r, want{"phone", "sdk.ts.sentry.set_user", "logInfo", true})
	if nf == nil || nf.Baselined || nf.Source.File != "src/api/user.ts" {
		t.Errorf("expected new flow from caller file: %+v", nf)
	}
	var s struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				BaselineState       string            `json:"baselineState"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	sb, err := os.ReadFile(sarif)
	if err != nil || json.Unmarshal(sb, &s) != nil {
		t.Fatalf("sarif: %v", err)
	}
	if s.Version != "2.1.0" || len(s.Runs) != 1 || len(s.Runs[0].Results) == 0 || len(s.Runs[0].Tool.Driver.Rules) == 0 {
		t.Fatalf("sarif shape: %+v", s)
	}
	newCount := 0
	for _, res := range s.Runs[0].Results {
		if res.PartialFingerprints["piiflow/v1"] == "" || res.Locations[0].PhysicalLocation.Region.StartLine == 0 || strings.HasPrefix(res.Locations[0].PhysicalLocation.ArtifactLocation.URI, "/") {
			t.Errorf("bad sarif result: %+v", res)
		}
		if res.BaselineState == "new" {
			newCount++
		}
	}
	if newCount != 1 {
		t.Errorf("sarif new results = %d, want 1", newCount)
	}
}
