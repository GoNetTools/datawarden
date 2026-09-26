// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/GoNetTools/datawarden/internal/analysis"
	"github.com/GoNetTools/datawarden/internal/cache"
	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ingest"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// ---- fakes ----

type fakeFrontends struct {
	lowered     map[string][]string
	unavailable map[string]bool
	opts        frontend.Options
}

func (f *fakeFrontends) Frontend(lang string, o frontend.Options) (frontend.Frontend, error) {
	if f.unavailable[lang] {
		return nil, errors.New("built without cgo")
	}
	f.opts = o
	return fakeFE{lang: lang, f: f}, nil
}

type fakeFE struct {
	lang string
	f    *fakeFrontends
}

func (fe fakeFE) Lang() string { return fe.lang }

func (fe fakeFE) Lower(_ context.Context, files []string) (*ir.Module, error) {
	if fe.f.lowered == nil {
		fe.f.lowered = map[string][]string{}
	}
	fe.f.lowered[fe.lang] = append(fe.f.lowered[fe.lang], files...)
	m := &ir.Module{Lang: fe.lang}
	for _, f := range files {
		m.Funcs = append(m.Funcs, &ir.Func{ID: fe.lang + ":" + f, File: f, Lang: fe.lang})
	}
	return m, nil
}

type fakeAnalyzer struct {
	funcs []string
	input analysis.Input
}

func (a *fakeAnalyzer) Analyze(_ context.Context, funcs []*ir.Func, in analysis.Input) (*analysis.Result, error) {
	a.input = in
	for _, f := range funcs {
		a.funcs = append(a.funcs, f.ID)
	}
	return &analysis.Result{
		Flows:     []*finding.Flow{{DataType: "email", SinkRule: "log.test"}},
		Summaries: map[string]*analysis.Summary{},
		CallGraph: map[string][]string{},
	}, nil
}

type fakeVCS struct {
	changed []string
	staged  map[string]string
}

func (v fakeVCS) ChangedFiles(context.Context, string) ([]string, error) { return v.changed, nil }
func (v fakeVCS) StagedFiles(context.Context) ([]string, error) {
	var out []string
	for f := range v.staged {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}
func (v fakeVCS) StagedContent(_ context.Context, rel string) ([]byte, error) {
	return []byte(v.staged[rel]), nil
}
func (v fakeVCS) HeadCommit(context.Context) string { return "c0ffee" }

// fakeLiterals reports one "email" hit for every line containing PII.
type fakeLiterals struct{}

func (fakeLiterals) Scan(b []byte) []detect.LiteralHit {
	var out []detect.LiteralHit
	for i, line := range bytes.Split(b, []byte("\n")) {
		if bytes.Contains(line, []byte("PII")) {
			out = append(out, detect.LiteralHit{DataType: "email", Class: "pii", Line: i + 1, Conf: 0.9, Masked: "***"})
		}
		if bytes.Contains(line, []byte("KEY")) {
			out = append(out, detect.LiteralHit{DataType: "private_key", Class: "credential", Line: i + 1, Conf: 0.9, Masked: "***"})
		}
	}
	return out
}

type fakeSchemas struct{ built []*ir.TypeDecl }

func (s *fakeSchemas) ParseProto(path string, _ []byte) []*ir.TypeDecl {
	return []*ir.TypeDecl{{Name: "proto:" + path, Pos: ir.Pos{File: path}}}
}
func (s *fakeSchemas) ParseSQL(path string, _ []byte) []*ir.TypeDecl { return nil }
func (s *fakeSchemas) Build(types []*ir.TypeDecl) *detect.Schema {
	s.built = types
	return detect.BuildSchema(detect.NewClassifier(nil), types)
}

type fixture struct {
	scanner   *Scanner
	frontends *fakeFrontends
	analyzer  *fakeAnalyzer
	schemas   *fakeSchemas
	fsys      fstest.MapFS
	store     *cache.Store
	mem       *cache.Memory
	req       Request
}

func newFixture(t *testing.T, files map[string]string, vcs VCS) *fixture {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	rs, err := rules.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	fx := &fixture{frontends: &fakeFrontends{unavailable: map[string]bool{"java": true}}, analyzer: &fakeAnalyzer{}, schemas: &fakeSchemas{}, fsys: fsys, mem: &cache.Memory{}}
	fx.store = cache.Open(fx.mem, ingest.NewHasher(fsys), "test", rs.Hash())
	fx.scanner = &Scanner{Files: ingest.Lister{}, Frontends: fx.frontends, Analyzer: fx.analyzer, Literals: fakeLiterals{}, Schemas: fx.schemas, Clock: func() time.Time { return now }}
	fx.req = Request{Repo: Repo{Root: "/repo", FS: fsys, VCS: vcs}, Cache: fx.store, Config: config.Default(), Rules: rs}
	return fx
}

// ---- tests ----

func TestFullScanRoutesFilesToFrontends(t *testing.T) {
	fx := newFixture(t, map[string]string{
		"go.mod":            "module x",
		"a.go":              "package a",
		"a_test.go":         "package a",
		".scratch/tool.go":  "package main",
		"app/src/B.kt":      "class B",
		"app/src/C.java":    "class C",
		"web/app.ts":        "export {}",
		"web/app.test.ts":   "PII\nKEY",
		"api/user.proto":    "message U {}",
		"fixtures/seed.sql": "insert PII",
	}, fakeVCS{})
	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"go": "a.go", "kotlin": "app/src/B.kt", "typescript": "web/app.ts"}
	for lang, file := range want {
		if got := fx.frontends.lowered[lang]; len(got) != 1 || got[0] != file {
			t.Errorf("%s lowered %v, want [%s]", lang, got, file)
		}
	}
	if res.Mode != ModeFull || res.Commit != "c0ffee" || len(res.Flows) != 1 || res.Functions != 3 {
		t.Errorf("result: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "java: 1 files skipped: built without cgo") {
		t.Errorf("unavailable frontend not reported: %v", res.Warnings)
	}
	// Test files and fixtures are scanned for literals. Personal data in a
	// test file is scored lower (0.9 * 0.6, under the 0.6 threshold); a
	// credential there is not.
	var got []string
	for _, l := range res.Literals {
		got = append(got, l.Pos.File+":"+l.DataType)
	}
	sort.Strings(got)
	if want := []string{"fixtures/seed.sql:email", "web/app.test.ts:private_key"}; !slices.Equal(got, want) {
		t.Errorf("literals = %v, want %v", got, want)
	}
	if fx.frontends.opts.FS == nil || fx.frontends.opts.Root != "/repo" || fx.frontends.opts.KnownFunc == nil {
		t.Errorf("frontend options not wired: %+v", fx.frontends.opts)
	}
	if fx.analyzer.input.Rules == nil || fx.analyzer.input.Schema == nil || fx.analyzer.input.Lookup == nil || fx.analyzer.input.Callers != nil {
		t.Errorf("analysis input not wired: %+v", fx.analyzer.input)
	}
	if len(fx.schemas.built) != 1 || fx.schemas.built[0].Name != "proto:api/user.proto" {
		t.Errorf("schema files: %+v", fx.schemas.built)
	}
	if len(fx.mem.Data) == 0 || !fx.store.Has("go:a.go") {
		t.Error("cache not updated and saved")
	}
}

func TestDiffModeAddsCallersFromCachedCallGraph(t *testing.T) {
	fx := newFixture(t, map[string]string{
		"go.mod":    "module x",
		"lib.go":    "package x // PII",
		"caller.go": "package x // PII",
		"other.go":  "package x",
	}, fakeVCS{changed: []string{"lib.go"}})
	// Previous full scan: caller.go's function calls lib.go's function.
	fx.store.Update([]*ir.Func{{ID: "go:lib.go", File: "lib.go"}, {ID: "go:caller.go", File: "caller.go"}, {ID: "go:other.go", File: "other.go"}},
		&analysis.Result{CallGraph: map[string][]string{"go:caller.go": {"go:lib.go"}}}, nil, true)
	fx.req.DiffBase = "origin/main"

	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeDiff || strings.Join(res.ChangedFiles, ",") != "lib.go" || strings.Join(res.CallerFiles, ",") != "caller.go" {
		t.Errorf("diff selection: mode=%s changed=%v callers=%v", res.Mode, res.ChangedFiles, res.CallerFiles)
	}
	if got := strings.Join(fx.frontends.lowered["go"], ","); got != "lib.go,caller.go" {
		t.Errorf("lowered %s", got)
	}
	if len(res.Literals) != 1 || res.Literals[0].Pos.File != "lib.go" {
		t.Errorf("literals should only be checked in changed files: %+v", res.Literals)
	}
	if !fx.store.Has("go:other.go") {
		t.Error("partial update dropped an untouched function")
	}
	if fx.analyzer.input.Callers == nil {
		t.Error("a partial run does not give the analysis the cached callers")
	}
}

func TestDiffWithoutCacheFallsBackToFullAnalysis(t *testing.T) {
	fx := newFixture(t, map[string]string{"go.mod": "module x", "a.go": "package a", "b.go": "package a"}, fakeVCS{changed: []string{"a.go"}})
	fx.req.DiffBase = "origin/main"
	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeFull || len(fx.frontends.lowered["go"]) != 2 || len(res.Warnings) == 0 {
		t.Errorf("fallback: mode=%s lowered=%v warnings=%v", res.Mode, fx.frontends.lowered, res.Warnings)
	}
}

func TestStagedScansTheIndexNotTheWorkingTree(t *testing.T) {
	fx := newFixture(t, map[string]string{"seed.json": "clean now", "other.json": "PII"}, fakeVCS{staged: map[string]string{"seed.json": "{\n PII\n}"}})
	fx.req.LiteralsOnly, fx.req.Staged = true, true
	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeLiterals || len(res.Literals) != 1 || res.Literals[0].Pos != (ir.Pos{File: "seed.json", Line: 2}) {
		t.Errorf("staged literals: %+v", res.Literals)
	}
	if len(fx.frontends.lowered) != 0 || len(fx.analyzer.funcs) != 0 {
		t.Error("literals-only must not run frontends or analysis")
	}
}

func TestConfigRestrictsLanguagesAndLiteralThreshold(t *testing.T) {
	fx := newFixture(t, map[string]string{"go.mod": "module x", "a.go": "package a // PII", "B.kt": "class B"}, fakeVCS{})
	fx.req.Config.Languages = []string{"go"}
	fx.req.Config.Literals.MinConfidence = 0.95
	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fx.frontends.lowered["kotlin"]; ok || len(res.Literals) != 0 {
		t.Errorf("languages/threshold ignored: lowered=%v literals=%v", fx.frontends.lowered, res.Literals)
	}
}

func TestMissingDependenciesAreReported(t *testing.T) {
	_, err := (&Scanner{}).Run(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "Scanner.Analyzer") || !strings.Contains(err.Error(), "Request.Repo.FS") {
		t.Errorf("err = %v", err)
	}
}

func TestLowerRunsFrontendsWithoutAnalysis(t *testing.T) {
	fx := newFixture(t, map[string]string{"go.mod": "module x", "a.go": "package a", "app/src/B.kt": "class B"}, fakeVCS{})
	m, err := fx.scanner.Lower(context.Background(), Request{Repo: fx.req.Repo, Config: fx.req.Config, Paths: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Funcs) != 1 || fx.frontends.lowered["go"] != nil || fx.analyzer.input.Rules != nil {
		t.Errorf("lowered %v, funcs %d, analyzer input %+v", fx.frontends.lowered, len(m.Funcs), fx.analyzer.input)
	}
	if fx.frontends.opts.KnownFunc != nil {
		t.Error("no cache, but KnownFunc set")
	}
	if _, err := (&Scanner{}).Lower(context.Background(), Request{}); err == nil {
		t.Error("missing dependencies accepted")
	}
}

func TestContactEmailsInCommunityDocsAreNotLiterals(t *testing.T) {
	fx := newFixture(t, map[string]string{"go.mod": "module x", "CODE_OF_CONDUCT.md": "PII", "docs/SECURITY.md": "PII", "notes.txt": "PII"}, fakeVCS{})
	res, err := fx.scanner.Run(context.Background(), fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Literals) != 1 || res.Literals[0].Pos.File != "notes.txt" {
		t.Errorf("literals: %+v", res.Literals)
	}
}

func TestContactDoc(t *testing.T) {
	for p, want := range map[string]bool{
		"CODE_OF_CONDUCT.md": true, "i18n/es.json": true, "web/src/locales/de/common.json": true,
		"app/src/main/res/values/strings.xml": false, "fixtures/users.json": false, "docs/FAQ.md": false,
	} {
		if got := contactDoc(p); got != want {
			t.Errorf("contactDoc(%s) = %v, want %v", p, got, want)
		}
	}
}
