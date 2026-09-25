// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/cache"
	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ingest"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/scan"
)

// ---- fakes ----

// memWorkspace is an in-memory machine: files keyed by absolute path.
type memWorkspace struct {
	wd       string
	files    map[string][]byte
	vcs      scan.VCS
	writeErr error // returned by WriteFile when set
}

func newWorkspace(root string, files map[string]string) *memWorkspace {
	w := &memWorkspace{wd: root, files: map[string][]byte{}, vcs: ingest.NoVCS{}}
	for rel, body := range files {
		w.files[filepath.Join(root, filepath.FromSlash(rel))] = []byte(body)
	}
	return w
}

func (w *memWorkspace) Getwd() (string, error) { return w.wd, nil }
func (w *memWorkspace) Abs(p string) (string, error) {
	if filepath.IsAbs(p) || strings.HasPrefix(p, string(filepath.Separator)) {
		return filepath.Clean(p), nil
	}
	return filepath.Join(w.wd, p), nil
}
func (w *memWorkspace) FindRoot(dir string) string { return testRoot }
func (w *memWorkspace) IsDir(p string) bool {
	p, _ = w.Abs(p)
	for f := range w.files {
		if strings.HasPrefix(f, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
func (w *memWorkspace) Open(root string) scan.Repo {
	fsys := fstest.MapFS{}
	for p, b := range w.files {
		if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
			fsys[filepath.ToSlash(rel)] = &fstest.MapFile{Data: b}
		}
	}
	return scan.Repo{Root: root, FS: fsys, VCS: w.vcs}
}
func (w *memWorkspace) ReadFile(p string) ([]byte, error) {
	b, ok := w.files[filepath.Clean(p)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return b, nil
}
func (w *memWorkspace) WriteFile(p string, data []byte) error {
	if w.writeErr != nil {
		return w.writeErr
	}
	w.files[filepath.Clean(p)] = append([]byte(nil), data...)
	return nil
}

type fakeScanner struct {
	reqs  []scan.Request
	flows func() []*finding.Flow
	err   error
}

func (s *fakeScanner) Run(_ context.Context, req scan.Request) (*scan.Result, error) {
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	res := &scan.Result{Mode: scan.ModeFull, FilesAnalyzed: map[string]int{"kotlin": 1}, Commit: "abc", Duration: 1500 * time.Millisecond}
	if s.flows != nil {
		res.Flows = s.flows()
	}
	return res, nil
}

type fakeCommenter struct {
	bodies []string
	err    error
}

func (c *fakeCommenter) Post(body string) (string, error) {
	c.bodies = append(c.bodies, body)
	if c.err != nil {
		return "", c.err
	}
	return "created", nil
}

var (
	testRoot = filepath.Join(string(filepath.Separator), "repo")
	testNow  = time.Date(2026, 9, 24, 8, 30, 0, 0, time.UTC)
)

func sentryFlow() []*finding.Flow {
	return []*finding.Flow{{
		DataType: "phone", SinkRule: "sdk.sentry.set_user", Dest: finding.Destination{Host: "sentry.io", Kind: "third_party", Vendor: "Sentry"},
		Function: "com.acme.Repo.save", Confidence: 0.9, Source: ir.Pos{File: "app/Repo.kt", Line: 3}, Sink: ir.Pos{File: "app/Repo.kt", Line: 9},
		Path: []ir.Pos{{File: "app/Repo.kt", Line: 3}, {File: "app/Repo.kt", Line: 9}}, SourceDesc: `identifier "phone"`, SinkCall: "io.sentry.Sentry.setUser",
	}}
}

type harness struct {
	app       *App
	ws        *memWorkspace
	scanner   *fakeScanner
	commenter *fakeCommenter
	persisted []bool
	out, errb *bytes.Buffer
}

func newHarness(files map[string]string) *harness {
	h := &harness{ws: newWorkspace(testRoot, files), scanner: &fakeScanner{flows: sentryFlow}, commenter: &fakeCommenter{}, out: &bytes.Buffer{}, errb: &bytes.Buffer{}}
	classifier := detect.NewClassifier(detect.DefaultTaxonomy())
	h.app = &App{
		Stdout: h.out, Stderr: h.errb, Version: "test",
		Workspace: h.ws, Scanner: h.scanner, Commenter: h.commenter, Catalog: classifier,
		OpenCache: func(repo scan.Repo, dir, rulesHash string, persist bool) scan.Cache {
			h.persisted = append(h.persisted, persist)
			return cache.Open(nil, ingest.NewHasher(repo.FS), "test", rulesHash)
		},
		Languages: func() []string { return []string{"go", "kotlin"} },
		Links:     func(p ir.Pos) string { return "https://example.test/" + p.File },
		Clock:     func() time.Time { return testNow },
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	return h.app.Run(context.Background(), args)
}

func (h *harness) file(rel string) string {
	return string(h.ws.files[filepath.Join(testRoot, filepath.FromSlash(rel))])
}

// ---- tests ----

func TestExitCodesFollowBaseline(t *testing.T) {
	h := newHarness(nil)
	if code := h.run("scan", "."); code != ExitViolation {
		t.Fatalf("new violation: exit %d\n%s%s", code, h.out, h.errb)
	}
	if code := h.run("baseline"); code != ExitClean {
		t.Fatalf("baseline: exit %d %s", code, h.errb)
	}
	bl := h.file(".piiflow/baseline.json")
	if !strings.Contains(bl, `"generated": "2026-09-24T08:30:00Z"`) || !strings.Contains(bl, `"function": "com.acme.Repo.save"`) {
		t.Errorf("baseline file:\n%s", bl)
	}
	if code := h.run("scan"); code != ExitClean {
		t.Errorf("baselined finding still fails: exit %d\n%s", code, h.out)
	}
	if code := h.run("scan", "--no-baseline"); code != ExitViolation {
		t.Errorf("--no-baseline: exit %d", code)
	}
	h.scanner.flows = func() []*finding.Flow { f := sentryFlow(); f[0].Function = "com.acme.Repo.update"; return f }
	if code := h.run("scan", "--no-fail"); code != ExitClean || !strings.Contains(h.out.String(), "NEW") {
		t.Errorf("--no-fail: exit %d\n%s", code, h.out)
	}
}

func TestReportWriteFailureExits2(t *testing.T) {
	h := newHarness(nil)
	h.ws.writeErr = errors.New("disk full")
	for _, args := range [][]string{
		{"scan", "--output", "report.json", "--format", "json"},
		{"scan", "--sarif", "piiflow.sarif"},
	} {
		// The scan finds a new violation, so a swallowed write error would exit 1.
		if code := h.run(args...); code != ExitError || !strings.Contains(h.errb.String(), "disk full") {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.errb)
		}
	}
}

func TestReportsAreWrittenThroughTheWorkspace(t *testing.T) {
	h := newHarness(nil)
	h.run("scan", "--sarif", "out/piiflow.sarif", "--markdown", "pr.md", "--format", "json")
	var sarif struct {
		Runs []struct {
			Results []struct{ RuleID string } `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(h.file("out/piiflow.sarif")), &sarif); err != nil || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("sarif: %v %s", err, h.file("out/piiflow.sarif"))
	}
	md := h.file("pr.md")
	if !strings.Contains(md, "Phone number") || !strings.Contains(md, "(https://example.test/app/Repo.kt)") {
		t.Errorf("markdown should use the catalog and injected links:\n%s", md)
	}
	var js struct{ Flows []finding.Flow }
	if err := json.Unmarshal(h.out.Bytes(), &js); err != nil || len(js.Flows) != 1 || js.Flows[0].Fingerprint == "" {
		t.Errorf("stdout json: %v %s", err, h.out)
	}
}

func TestProfilesAreWrittenThroughTheWorkspace(t *testing.T) {
	isPprof := func(b string) bool { return strings.HasPrefix(b, "\x1f\x8b") } // gzipped protobuf
	h := newHarness(nil)
	for _, args := range [][]string{
		{"scan", "--cpuprofile", "prof/scan.cpu", "--memprofile", "prof/scan.mem", "--no-fail"},
		{"baseline", "--cpuprofile", "prof/baseline.cpu"},
		{"map", "--memprofile", "prof/map.mem"},
	} {
		if code := h.run(args...); code != ExitClean {
			t.Fatalf("%v: exit %d %s", args, code, h.errb)
		}
	}
	for _, f := range []string{"prof/scan.cpu", "prof/scan.mem", "prof/baseline.cpu", "prof/map.mem"} {
		if !isPprof(h.file(f)) {
			t.Errorf("%s: not a pprof profile (%d bytes)", f, len(h.file(f)))
		}
	}

	// A failed scan writes no profile; a failed write is an error.
	h = newHarness(nil)
	h.scanner.err = errors.New("go list failed")
	if code := h.run("scan", "--cpuprofile", "scan.cpu"); code != ExitError || h.file("scan.cpu") != "" {
		t.Errorf("failed scan: exit %d, profile %d bytes", code, len(h.file("scan.cpu")))
	}
	h = newHarness(nil)
	h.ws.writeErr = errors.New("disk full")
	if code := h.run("scan", "--memprofile", "scan.mem", "--no-fail"); code != ExitError || !strings.Contains(h.errb.String(), "write profile: disk full") {
		t.Errorf("write error: exit %d, stderr %q", code, h.errb)
	}
}

func TestRulesTestChecksAnnotations(t *testing.T) {
	// The fake scanner reports a Sentry flow at app/Repo.kt:9.
	annotated := strings.Repeat("\n", 7) + "// ruleid: sdk.sentry.set_user\nSentry.setUser(sdt)\n"
	h := newHarness(map[string]string{"examples/app/Repo.kt": annotated})
	if code := h.run("rules", "test", "examples"); code != ExitClean {
		t.Fatalf("exit %d\n%s%s", code, h.out, h.errb)
	}
	if !strings.Contains(h.out.String(), "1 annotation(s), 0 failure(s)") {
		t.Errorf("summary: %s", h.out)
	}
	req := h.scanner.reqs[len(h.scanner.reqs)-1]
	if req.Repo.Root != filepath.Join(testRoot, "examples") || req.Rules == nil || req.Cache == nil {
		t.Errorf("examples must be scanned as their own root with the repository's rules: %+v", req.Repo)
	}

	// A wrong annotation fails: the expected finding is missing and the
	// real one is unannotated.
	h = newHarness(map[string]string{"examples/app/Repo.kt": strings.Replace(annotated, "sdk.sentry.set_user", "sdk.sentry.capture", 1)})
	if code := h.run("rules", "test", "examples"); code != ExitViolation {
		t.Errorf("wrong annotation: exit %d", code)
	}
	if out := h.out.String(); !strings.Contains(out, "FAIL    app/Repo.kt:9: ruleid: sdk.sentry.capture: no finding") || !strings.Contains(out, "unannotated violation") {
		t.Errorf("failures not reported:\n%s", out)
	}

	// Repository rules without an example are listed.
	h = newHarness(map[string]string{
		".piiflow/rules/acme.yaml": "- id: sdk.acme.track\n  lang: kotlin\n  call: com.acme.Track.send\n  dest: {kind: third_party}\n",
		"examples/app/Repo.kt":     annotated,
	})
	if code := h.run("rules", "test", "examples"); code != ExitClean || !strings.Contains(h.out.String(), "repository rules without a ruleid example: sdk.acme.track") {
		t.Errorf("untested repository rule: exit %d\n%s", code, h.out)
	}

	for name, args := range map[string][]string{
		"no annotations": {"rules", "test", "examples"},
		"not a dir":      {"rules", "test", "missing"},
		"no dir":         {"rules", "test"},
	} {
		h = newHarness(map[string]string{"examples/README.md": "no annotations here\n"})
		if code := h.run(args...); code != ExitError {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

func TestRequestIsBuiltFromFlagsConfigAndRepo(t *testing.T) {
	h := newHarness(map[string]string{
		".piiflow.yaml":           "first_party_domains: [api.acme.vn]\nrules: [policy/rules]\n",
		"policy/rules/extra.yaml": "- id: sdk.acme.track\n  lang: kotlin\n  call: com.acme.Track.send\n  dest: {kind: third_party}\n",
		"src/api/user.ts":         "",
	})
	h.ws.wd = filepath.Join(testRoot, "src")
	if code := h.run("scan", "api", "--diff", "origin/main", "--caller-depth", "3", "--no-cache"); code == ExitError {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	req := h.scanner.reqs[0]
	if strings.Join(req.Paths, ",") != "src/api" || req.DiffBase != "origin/main" || req.CallerDepth != 3 {
		t.Errorf("request: paths=%v diff=%q depth=%d", req.Paths, req.DiffBase, req.CallerDepth)
	}
	if len(req.Config.FirstPartyDomains) != 1 || req.Repo.Root != testRoot || h.persisted[0] {
		t.Errorf("config/repo/cache: %+v root=%s persist=%v", req.Config.FirstPartyDomains, req.Repo.Root, h.persisted)
	}
	if code := h.run("rules", "--kind", "sink", "--lang", "kotlin"); code != ExitClean || !strings.Contains(h.out.String(), "sdk.acme.track") {
		t.Errorf("repository rule not loaded:\n%s%s", h.out, h.errb)
	}
}

func TestErrorsExitTwo(t *testing.T) {
	h := newHarness(nil)
	outside := filepath.Join(string(filepath.Separator), "elsewhere", "x.go")
	if code := h.run("scan", outside, "--no-cache"); code != ExitError || !strings.Contains(h.errb.String(), "outside the repository") {
		t.Errorf("path outside repo: exit %d %s", code, h.errb)
	}
	h.scanner.err = errors.New("boom")
	if code := h.run("scan"); code != ExitError || !strings.Contains(h.errb.String(), "boom") {
		t.Errorf("scanner error: exit %d", code)
	}
	if code := h.run("scan", "--format", "xml"); code != ExitError {
		t.Errorf("bad format: exit %d", code)
	}
	if code := h.run("nope"); code != ExitError {
		t.Errorf("unknown command: exit %d", code)
	}
	if code := (&App{Stdout: h.out, Stderr: h.errb}).Run(context.Background(), []string{"scan"}); code != ExitError || !strings.Contains(h.errb.String(), "missing dependencies") {
		t.Errorf("unwired app: exit %d %s", code, h.errb)
	}
}

func TestCommentUsesInjectedCommenter(t *testing.T) {
	h := newHarness(map[string]string{"pr.md": "### piiflow: 1 new PII finding(s)", "clean.md": "### piiflow: no new PII leaks"})
	if code := h.run("comment", "pr.md"); code != ExitClean || !strings.Contains(h.out.String(), "created") || len(h.commenter.bodies) != 1 {
		t.Errorf("post: exit %d %s", code, h.out)
	}
	if code := h.run("comment", "--only-if-new", "clean.md"); code != ExitClean || len(h.commenter.bodies) != 1 {
		t.Errorf("only-if-new should skip without posting: %d bodies", len(h.commenter.bodies))
	}
	h.commenter.err = ErrNotInReview
	if code := h.run("comment", "pr.md"); code != ExitClean || !strings.Contains(h.out.String(), "skipped") {
		t.Errorf("not in review: exit %d %s", code, h.out)
	}
	h.commenter.err = errors.New("403")
	if code := h.run("comment", "pr.md"); code != ExitError {
		t.Errorf("API failure: exit %d", code)
	}
}

func TestInitMapAndVersion(t *testing.T) {
	h := newHarness(nil)
	if code := h.run("init"); code != ExitClean || h.file(".piiflow.yaml") == "" || h.file(".piiflowignore") == "" {
		t.Fatalf("init: %d %s", code, h.errb)
	}
	if h.run("init"); !strings.Contains(h.out.String(), "exists  .piiflow.yaml") {
		t.Errorf("init should not overwrite:\n%s", h.out)
	}
	if code := h.run("map", "--format", "json", "--output", "map.json"); code != ExitClean || !strings.Contains(h.file("map.json"), `"generated": "2026-09-24T08:30:00Z"`) {
		t.Errorf("map: %d %s", code, h.file("map.json"))
	}
	if h.run("version"); !strings.Contains(h.out.String(), "piiflow test (frontends: go, kotlin)") {
		t.Errorf("version: %s", h.out)
	}
}
