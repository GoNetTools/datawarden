// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/GoNetTools/datawarden/internal/baseline"
	"github.com/GoNetTools/datawarden/internal/cache"
	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/datamap"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/explain"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/flowgraph"
	"github.com/GoNetTools/datawarden/internal/ingest"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/policy"
	"github.com/GoNetTools/datawarden/internal/report"
	"github.com/GoNetTools/datawarden/internal/rules"
	"github.com/GoNetTools/datawarden/internal/ruletest"
	"github.com/GoNetTools/datawarden/internal/scan"
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

// Lower returns one valid function and, with a "bad" path, one that
// breaks SSA (two definitions of a variable).
func (s *fakeScanner) Lower(_ context.Context, req scan.Request) (*ir.Module, error) {
	s.reqs = append(s.reqs, req)
	ok := &ir.Func{ID: "com.acme.Repo.save", Lang: "kotlin", File: "Repo.kt", Pos: ir.Pos{File: "Repo.kt", Line: 3}}
	ok.NewBlock()
	email := ok.AddParam("email", "String", ir.Pos{File: "Repo.kt", Line: 3})
	ok.Emit(ir.Instr{Op: ir.OpCall, Dst: ok.Temp(ir.Pos{}), Args: []ir.VarID{email}, Call: &ir.Call{Callee: "Log.d", Name: "d"}})
	m := &ir.Module{Funcs: []*ir.Func{ok}, Classes: []*ir.Class{{Name: "com.acme.Repo", Methods: map[string]string{"save": "com.acme.Repo.save"}}}, Warnings: []string{"kotlin: one file skipped"}}
	if slices.Contains(req.Paths, "bad") {
		bad := &ir.Func{ID: "com.acme.Bad.twice", Lang: "kotlin", File: "Bad.kt"}
		bad.NewBlock()
		v := bad.Temp(ir.Pos{})
		c := bad.ConstVar("x", ir.Pos{})
		bad.Assign(v, ir.Pos{}, c)
		bad.Assign(v, ir.Pos{}, c)
		m.Funcs = append(m.Funcs, bad)
	}
	return m, nil
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
	testRoot = absPath("repo")
	testNow  = time.Date(2026, 9, 24, 8, 30, 0, 0, time.UTC)
)

// absPath is an absolute path on every platform: /elem... on Unix,
// C:\elem... (the temp directory's volume) on Windows, where \elem is
// not absolute.
func absPath(elem ...string) string {
	return filepath.Join(append([]string{filepath.VolumeName(os.TempDir()) + string(filepath.Separator)}, elem...)...)
}

func sentryFlow() []*finding.Flow {
	return []*finding.Flow{{
		DataType: "phone", SinkRule: "sdk.sentry.set_user", Dest: finding.Destination{Host: "sentry.io", Kind: "third_party", Vendor: "Sentry"},
		Function: "com.acme.Repo.save", Confidence: 0.9, Source: ir.Pos{File: "app/Repo.kt", Line: 3}, Sink: ir.Pos{File: "app/Repo.kt", Line: 9},
		Path: []ir.Pos{{File: "app/Repo.kt", Line: 3}, {File: "app/Repo.kt", Line: 9}}, SourceDesc: `identifier "phone"`, SinkCall: "io.sentry.Sentry.setUser",
	}}
}

// testRules loads real rules (app wires the same adapter).
type testRules struct{}

func (testRules) Load(fsys fs.FS, paths ...string) (RuleSet, error) {
	set, err := rules.Load(fsys, paths...)
	if err != nil {
		return nil, err
	}
	return set, nil
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

		Configs:    config.Loader{},
		Rules:      testRules{},
		Policy:     policy.Policies{Catalog: classifier},
		Baselines:  baseline.Codec{},
		Reporter:   report.Writer{},
		DataMapper: datamap.Mapper{},
		Grapher:    flowgraph.Renderer{},
		RuleTester: ruletest.Tester{},
		Links:      func(p ir.Pos) string { return "https://example.test/" + p.File },
		Clock:      func() time.Time { return testNow },
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
	bl := h.file(".datawarden/baseline.json")
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

func TestIRPrintsLoweredFunctions(t *testing.T) {
	h := newHarness(map[string]string{"bad/x.kt": "", "Repo.kt": ""})
	if code := h.run("ir", "--classes"); code != ExitClean {
		t.Fatalf("ir: exit %d %s", code, h.errb)
	}
	for _, want := range []string{"# IR version " + strconv.Itoa(ir.Version) + " · 1 functions", "# Repo.kt:3", "func com.acme.Repo.save(v0:email)", `call Log.d(v0:email)`, "class com.acme.Repo", "save -> com.acme.Repo.save"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, h.out)
		}
	}
	if !strings.Contains(h.errb.String(), "warning: kotlin: one file skipped") {
		t.Errorf("warnings: %s", h.errb)
	}
	if code := h.run("ir", "--format", "json", "--func", "save$"); code != ExitClean || !strings.Contains(h.out.String(), `"id": "com.acme.Repo.save"`) || strings.Contains(h.out.String(), `"classes"`) {
		t.Errorf("json: exit %d\n%s", code, h.out)
	}
	if code := h.run("ir", "bad", "--verify"); code != ExitViolation || !strings.Contains(h.out.String(), "invalid: ") {
		t.Errorf("--verify: exit %d\n%s", code, h.out)
	}
	if code := h.run("ir", "--func", "save$", "--verify"); code != ExitClean {
		t.Errorf("valid IR: exit %d\n%s", code, h.out)
	}
	if code := h.run("ir", "--format", "xml"); code != ExitError {
		t.Errorf("bad format: exit %d", code)
	}
	if code := h.run("ir", "--func", "("); code != ExitError {
		t.Errorf("bad regexp: exit %d", code)
	}
	h.app.Scanner = runOnly{h.scanner}
	if code := h.run("ir"); code != ExitError {
		t.Errorf("scanner without Lower: exit %d", code)
	}
}

type runOnly struct{ Scanner }

func TestCallGraphFlag(t *testing.T) {
	h := newHarness(nil)
	if code := h.run("scan", "--no-fail"); code != ExitClean || strings.Contains(h.out.String(), "calls ") {
		t.Fatalf("default: exit %d\n%s", code, h.out)
	}
	if code := h.run("scan", "--no-fail", "--call-graph"); code != ExitClean || !strings.Contains(h.out.String(), "calls   com.acme.Repo.save  app/Repo.kt:9") {
		t.Errorf("--call-graph: exit %d\n%s", code, h.out)
	}
}

func TestGraphCommand(t *testing.T) {
	h := newHarness(nil)
	if code := h.run("graph"); code != ExitClean || !strings.Contains(h.out.String(), "datawarden-graph.svg: 1 flow(s)") {
		t.Fatalf("graph: exit %d\n%s%s", code, h.out, h.errb)
	}
	if svg := h.file("datawarden-graph.svg"); !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "Repo.save") {
		t.Errorf("svg:\n%s", svg)
	}
	if code := h.run("graph", "--format", "dot", "-o", "-"); code != ExitClean || !strings.HasPrefix(h.out.String(), "digraph datawarden") {
		t.Errorf("dot to stdout: exit %d\n%s", code, h.out)
	}
	if code := h.run("graph", "--format", "mermaid"); code != ExitClean || !strings.HasPrefix(h.file("datawarden-graph.mmd"), "flowchart LR") {
		t.Errorf("mermaid: exit %d\n%s", code, h.errb)
	}
	for _, args := range [][]string{{"--function", "Nothing"}, {"--data-type", "email"}} {
		if code := h.run(append([]string{"graph", "-o", "-", "--format", "dot"}, args...)...); code != ExitClean || strings.Contains(h.out.String(), "Repo.save") {
			t.Errorf("%v: exit %d\n%s", args, code, h.out)
		}
	}
	if code := h.run("graph", "-o", "-", "--format", "dot", "--function", "Repo\\.save$"); code != ExitClean || !strings.Contains(h.out.String(), "Repo.save") {
		t.Errorf("--function match: exit %d\n%s", code, h.out)
	}
	for _, bad := range [][]string{{"--format", "png"}, {"--function", "("}} {
		if code := h.run(append([]string{"graph"}, bad...)...); code != ExitError {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}

func TestReportWriteFailureExits2(t *testing.T) {
	h := newHarness(nil)
	h.ws.writeErr = errors.New("disk full")
	for _, args := range [][]string{
		{"scan", "--output", "report.json", "--format", "json"},
		{"scan", "--sarif", "datawarden.sarif"},
	} {
		// The scan finds a new violation, so a swallowed write error would exit 1.
		if code := h.run(args...); code != ExitError || !strings.Contains(h.errb.String(), "disk full") {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.errb)
		}
	}
}

func TestReportsAreWrittenThroughTheWorkspace(t *testing.T) {
	h := newHarness(nil)
	h.run("scan", "--sarif", "out/datawarden.sarif", "--markdown", "pr.md", "--format", "json")
	var sarif struct {
		Runs []struct {
			Results []struct{ RuleID string } `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(h.file("out/datawarden.sarif")), &sarif); err != nil || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("sarif: %v %s", err, h.file("out/datawarden.sarif"))
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
		".datawarden/rules/acme.yaml": "- id: sdk.acme.track\n  lang: kotlin\n  call: com.acme.Track.send\n  dest: {kind: third_party}\n",
		"examples/app/Repo.kt":        annotated,
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
		".datawarden.yaml":        "first_party_domains: [api.acme.vn]\nrules: [policy/rules]\n",
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

func TestSessionFlags(t *testing.T) {
	other := filepath.Join(testRoot, "services", "api")
	h := newHarness(map[string]string{
		"custom.yaml":          "policy:\n  min_confidence: 0.7\n",
		"services/api/main.go": "package main",
		"rules-in-root/x.yaml": "- id: sdk.acme.x\n  lang: go\n  call: acme.X\n  dest: {kind: log}\n",
		".datawarden.yaml":     "rules: [" + filepath.ToSlash(filepath.Join(testRoot, "rules-in-root")) + "]\n",
	})

	// --root picks the repository; --config replaces .datawarden.yaml.
	if code := h.run("scan", "--root", other, "--config", "custom.yaml", "--no-cache", "--no-fail"); code != ExitClean {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	req := h.scanner.reqs[len(h.scanner.reqs)-1]
	if req.Repo.Root != other || req.Config.Policy.MinConfidence != 0.7 {
		t.Errorf("root=%s min_confidence=%v", req.Repo.Root, req.Config.Policy.MinConfidence)
	}
	// --min-confidence overrides the policy; absolute rule paths inside
	// the repository load.
	if code := h.run("scan", "--min-confidence", "0.9", "--no-cache", "--no-fail"); code != ExitClean {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	req = h.scanner.reqs[len(h.scanner.reqs)-1]
	if req.Config.Policy.MinConfidence != 0.9 {
		t.Errorf("min_confidence = %v", req.Config.Policy.MinConfidence)
	}
	if code := h.run("rules", "--lang", "go"); code != ExitClean || !strings.Contains(h.out.String(), "sdk.acme.x") {
		t.Errorf("absolute rules path: exit %d\n%s%s", code, h.out, h.errb)
	}

	// baseline --output writes where asked.
	if code := h.run("baseline", "--output", "accepted.json", "--no-cache"); code != ExitClean || h.file("accepted.json") == "" {
		t.Errorf("baseline --output: exit %d %s", code, h.errb)
	}

	for name, args := range map[string][]string{
		"missing config":         {"scan", "--config", "nope.yaml", "--no-cache"},
		"baseline with paths":    {"baseline", "services", "--no-cache"},
		"unknown map format":     {"map", "--format", "xml", "--no-cache"},
		"rules outside the repo": {"rules"},
	} {
		h2 := newHarness(nil)
		if name == "rules outside the repo" {
			h2 = newHarness(map[string]string{".datawarden.yaml": "rules: [" + filepath.ToSlash(absPath("elsewhere")) + "]\n"})
		}
		if code := h2.run(args...); code != ExitError {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

func TestErrorsExitTwo(t *testing.T) {
	h := newHarness(nil)
	outside := absPath("elsewhere", "x.go")
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
	h := newHarness(map[string]string{"pr.md": "### datawarden: 1 new sensitive-data finding(s)", "clean.md": "### datawarden: no new sensitive-data leaks"})
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
	if code := h.run("init"); code != ExitClean || h.file(".datawarden.yaml") == "" || h.file(".datawardenignore") == "" {
		t.Fatalf("init: %d %s", code, h.errb)
	}
	if h.run("init"); !strings.Contains(h.out.String(), "exists  .datawarden.yaml") {
		t.Errorf("init should not overwrite:\n%s", h.out)
	}
	if code := h.run("map", "--format", "json", "--output", "map.json"); code != ExitClean || !strings.Contains(h.file("map.json"), `"generated": "2026-09-24T08:30:00Z"`) {
		t.Errorf("map: %d %s", code, h.file("map.json"))
	}
	if h.run("version"); !strings.Contains(h.out.String(), "datawarden test (frontends: go, kotlin)") {
		t.Errorf("version: %s", h.out)
	}
}

func TestExplain(t *testing.T) {
	h := newHarness(map[string]string{"app/Repo.kt": "package app\n\nclass Repo {\n\n\n\n\n\n    fun save() { Sentry.setUser(phone) }\n}\n"})
	h.app.Explainer = explain.Explainer{Names: detect.NewClassifier(detect.DefaultTaxonomy())}
	if code := h.run("explain", "app/Repo.kt:9"); code != ExitClean {
		t.Fatalf("explain file:line: exit %d %s", code, h.errb)
	}
	out := h.out.String()
	for _, want := range []string{
		"NEW  phone → Sentry (third_party), host sentry.io  [sdk.sentry.set_user]",
		"Why the source is phone", `the name ` + "`phone`" + ` matches`,
		"Path", "Why the sink matched", "rule sdk.sentry.set_user",
		"Policy: NEW", "`first_party_domains: [sentry.io]` would make it first party",
		"To silence it", "{sink: sdk.sentry.set_user, data_types: [phone], path: \"app/Repo.kt\"", "datawarden baseline",
		"9 │ fun save() { Sentry.setUser(phone) }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output lacks %q:\n%s", want, out)
		}
	}
	fp := sentryFlow()[0]
	fp.Fingerprint = baseline.FlowFingerprint(fp)
	if code := h.run("explain", fp.Fingerprint[:8], "--format", "json"); code != ExitClean || !strings.Contains(h.out.String(), `"fingerprint": "`+fp.Fingerprint+`"`) {
		t.Errorf("explain fingerprint json: exit %d\n%s%s", code, h.out, h.errb)
	}
	// A baselined flow is explained as BASELINE, with nothing to silence.
	if code := h.run("baseline"); code != ExitClean {
		t.Fatalf("baseline: exit %d", code)
	}
	if code := h.run("explain", "app/Repo.kt:3"); code != ExitClean || !strings.HasPrefix(h.out.String(), "BASELINE") || strings.Contains(h.out.String(), "To silence it") {
		t.Errorf("baselined flow: exit %d\n%s", code, h.out)
	}
	for _, args := range [][]string{{"explain"}, {"explain", "a", "b"}, {"explain", "app/Repo.kt:4"}, {"explain", "nonsense"}, {"explain", "x.kt:0"}, {"explain", "app/Repo.kt:9", "--format", "xml"}} {
		if code := h.run(args...); code != ExitError {
			t.Errorf("%v: exit %d, want an error", args, code)
		}
	}
	// From a saved JSON report: nothing is scanned.
	if code := h.run("scan", "--json", "report.json", "--no-fail", "--no-baseline"); code != ExitClean {
		t.Fatalf("scan --json: exit %d %s", code, h.errb)
	}
	scans := len(h.scanner.reqs)
	if code := h.run("explain", "app/Repo.kt:9", "--report", "report.json"); code != ExitClean || !strings.HasPrefix(h.out.String(), "NEW  phone") {
		t.Errorf("--report: exit %d\n%s%s", code, h.out, h.errb)
	}
	for _, r := range h.scanner.reqs[scans:] {
		if r.Cache != nil {
			t.Errorf("--report scanned the repository")
		}
	}
	h.ws.files[filepath.Join(testRoot, "notes.json")] = []byte(`{"flows": []}`)
	for _, bad := range []string{"missing.json", "notes.json"} {
		if code := h.run("explain", "app/Repo.kt:9", "--report", bad); code != ExitError {
			t.Errorf("--report %s: exit %d", bad, code)
		}
	}
	h.app.Explainer = nil
	if code := h.run("explain", "app/Repo.kt:9"); code != ExitError {
		t.Errorf("no explainer: exit %d", code)
	}
}
