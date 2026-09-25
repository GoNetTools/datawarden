// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package scan is the pipeline: ingest, frontends, detectors, analysis and
// the cache. Every collaborator is an interface injected by the caller
// (see internal/app for the production wiring), so the pipeline runs
// against in-memory file systems, fake frontends and fake caches in tests.
package scan

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/GoNetTools/datawarden/internal/analysis"
	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ingest"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// Modes.
const (
	ModeFull     = "full"
	ModeDiff     = "diff"
	ModePaths    = "paths"
	ModeLiterals = "literals"
)

// VCS answers version-control questions (ingest.Git, ingest.NoVCS).
type VCS interface {
	ChangedFiles(ctx context.Context, base string) ([]string, error)
	StagedFiles(ctx context.Context) ([]string, error)
	StagedContent(ctx context.Context, rel string) ([]byte, error)
	HeadCommit(ctx context.Context) string
}

// Repo is the repository being scanned.
type Repo struct {
	// Root is the directory on disk. It is only handed to frontends that
	// drive external tools (the Go frontend runs `go list`).
	Root string
	// FS is the repository file system; everything else reads through it.
	FS  fs.FS
	VCS VCS
}

// Cache stores summaries, the call graph and schema hints between runs
// (*cache.Store).
type Cache interface {
	Empty() bool
	Has(id string) bool
	Lookup(id string) *analysis.Summary
	Callers(files []string, depth int) []string
	SchemaTypes(skip map[string]bool) []*ir.TypeDecl
	ResetSchema()
	SetSchema(file string, types []*ir.TypeDecl)
	Update(funcs []*ir.Func, res *analysis.Result, lowered []string, full bool)
	Save() error
}

// Frontends provides a frontend per language (*frontend.Registry).
type Frontends interface {
	Frontend(lang string, o frontend.Options) (frontend.Frontend, error)
}

// Analyzer runs the taint analysis (analysis.Engine).
type Analyzer interface {
	Analyze(ctx context.Context, funcs []*ir.Func, in analysis.Input) (*analysis.Result, error)
}

// LiteralDetector finds sensitive values in text (*detect.LiteralScanner).
type LiteralDetector interface {
	Scan(content []byte) []detect.LiteralHit
}

// SchemaParser extracts and indexes schema hints (detect.Schemas).
type SchemaParser interface {
	ParseProto(path string, src []byte) []*ir.TypeDecl
	ParseSQL(path string, src []byte) []*ir.TypeDecl
	Build(types []*ir.TypeDecl) *detect.Schema
}

// FileLister lists repository files and narrows them to requested paths
// (ingest.Lister).
type FileLister interface {
	// List returns the files not excluded by the default ignore patterns
	// and the repository's .datawardenignore.
	List(fsys fs.FS) ([]ingest.File, error)
	// Select keeps the files named by root-relative files or directories.
	Select(fsys fs.FS, all []ingest.File, paths []string) []ingest.File
}

// Scanner runs scans with injected collaborators.
type Scanner struct {
	Files     FileLister
	Frontends Frontends
	Analyzer  Analyzer
	Literals  LiteralDetector
	Schemas   SchemaParser
	Clock     func() time.Time
}

// Request describes one scan.
type Request struct {
	Repo   Repo
	Cache  Cache
	Config *config.Config
	Rules  analysis.RuleMatcher
	// Paths restricts the scan to root-relative files or directories.
	Paths        []string
	DiffBase     string
	LiteralsOnly bool
	// Staged scans the git index instead of the working tree (literals).
	Staged      bool
	CallerDepth int
	Logf        func(format string, args ...any)
}

// Result is the raw scan output (before baseline and policy).
type Result struct {
	Mode          string
	Flows         []*finding.Flow
	Literals      []*finding.Literal
	FilesWalked   int
	FilesScanned  int
	FilesAnalyzed map[string]int
	Functions     int
	ChangedFiles  []string
	CallerFiles   []string
	Warnings      []string
	Schema        *detect.Schema
	Commit        string
	Started       time.Time
	Duration      time.Duration
}

func (r *Request) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// Run executes a scan.
func (s *Scanner) Run(ctx context.Context, req Request) (*Result, error) {
	if err := s.validate(req); err != nil {
		return nil, err
	}
	start := s.Clock()
	if req.CallerDepth <= 0 {
		req.CallerDepth = 2
	}
	cfg := req.Config
	repo := req.Repo
	res := &Result{
		Mode:          ModeFull,
		FilesAnalyzed: map[string]int{},
		Commit:        repo.VCS.HeadCommit(ctx),
		Started:       start,
	}

	all, err := s.Files.List(repo.FS)
	if err != nil {
		return nil, err
	}
	res.FilesWalked = len(all)
	byRel := map[string]ingest.File{}
	for _, f := range all {
		byRel[f.Rel] = f
	}

	targets, literalTargets, err := s.selectTargets(ctx, req, all, byRel, res)
	if err != nil {
		return nil, err
	}

	// Committed sensitive values.
	if *cfg.Literals.Enabled || req.LiteralsOnly {
		res.Literals, err = s.scanLiterals(ctx, req, literalTargets)
		if err != nil {
			return nil, err
		}
	}
	if req.LiteralsOnly {
		res.Duration = s.Clock().Sub(start)
		return res, nil
	}

	// Frontends.
	prog, lowered := s.lower(ctx, req, targets, res)
	res.Warnings = append(res.Warnings, prog.Warnings...)
	dedupeIDs(prog.Funcs)
	res.Functions = len(prog.Funcs)

	// Schema hints: declarations from lowered code, protobuf and SQL from
	// the whole repository, and cached declarations of untouched files.
	res.Schema = s.buildSchema(req, all, prog, lowered, res.Mode)

	// Taint analysis.
	ar, err := s.Analyzer.Analyze(ctx, prog.Funcs, analysis.Input{
		Rules: req.Rules, Schema: res.Schema, Lookup: req.Cache.Lookup, FirstPartyDomains: cfg.FirstPartyDomains,
	})
	if err != nil {
		return nil, err
	}
	res.Flows = ar.Flows
	req.Cache.Update(prog.Funcs, ar, lowered, res.Mode == ModeFull)
	if err := req.Cache.Save(); err != nil {
		res.Warnings = append(res.Warnings, "cache: "+err.Error())
	}
	res.Duration = s.Clock().Sub(start)
	return res, nil
}

func (s *Scanner) validate(req Request) error {
	var missing []string
	for name, ok := range map[string]bool{
		"Scanner.Files":     s.Files != nil,
		"Scanner.Frontends": s.Frontends != nil,
		"Scanner.Analyzer":  s.Analyzer != nil,
		"Scanner.Literals":  s.Literals != nil,
		"Scanner.Schemas":   s.Schemas != nil,
		"Scanner.Clock":     s.Clock != nil,
		"Request.Repo.FS":   req.Repo.FS != nil,
		"Request.Repo.VCS":  req.Repo.VCS != nil,
		"Request.Cache":     req.Cache != nil,
		"Request.Config":    req.Config != nil,
		"Request.Rules":     req.Rules != nil,
	} {
		if !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("scan: missing dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

// selectTargets decides which files are analyzed and which are checked for
// literals: everything, explicit paths, or (PR mode) changed files plus
// their callers from the cached call graph.
func (s *Scanner) selectTargets(ctx context.Context, req Request, all []ingest.File, byRel map[string]ingest.File, res *Result) (targets, literalTargets []ingest.File, err error) {
	targets, literalTargets = all, all
	switch {
	case req.DiffBase != "":
		changed, err := req.Repo.VCS.ChangedFiles(ctx, req.DiffBase)
		if err != nil {
			return nil, nil, err
		}
		var changedFiles []ingest.File
		for _, rel := range changed {
			if f, ok := byRel[rel]; ok {
				changedFiles = append(changedFiles, f)
				res.ChangedFiles = append(res.ChangedFiles, rel)
			}
		}
		literalTargets = changedFiles
		if req.Cache.Empty() {
			res.Warnings = append(res.Warnings, "no cached call graph for --diff (run a full scan or `datawarden baseline` on the base branch and cache .datawarden/cache); analyzing the whole repository, reporting only new findings")
			req.logf("diff: no call graph cache, falling back to a full analysis")
			break
		}
		res.Mode = ModeDiff
		sel := map[string]bool{}
		targets = nil
		for _, f := range changedFiles {
			sel[f.Rel] = true
			targets = append(targets, f)
		}
		for _, rel := range req.Cache.Callers(res.ChangedFiles, req.CallerDepth) {
			if f, ok := byRel[rel]; ok && !sel[rel] {
				sel[rel] = true
				targets = append(targets, f)
				res.CallerFiles = append(res.CallerFiles, rel)
			}
		}
		req.logf("diff: %d changed files, %d caller files", len(changedFiles), len(res.CallerFiles))
	case len(req.Paths) > 0:
		res.Mode = ModePaths
		targets = s.Files.Select(req.Repo.FS, all, req.Paths)
		literalTargets = targets
	}
	if req.LiteralsOnly {
		res.Mode = ModeLiterals
	}
	if req.Staged {
		files, err := req.Repo.VCS.StagedFiles(ctx)
		if err != nil {
			return nil, nil, err
		}
		literalTargets = nil
		for _, rel := range files {
			if f, ok := byRel[rel]; ok {
				literalTargets = append(literalTargets, f)
			}
		}
	}
	res.FilesScanned = len(literalTargets)
	return targets, literalTargets, nil
}

func (s *Scanner) scanLiterals(ctx context.Context, req Request, files []ingest.File) ([]*finding.Literal, error) {
	var out []*finding.Literal
	minConf := req.Config.Literals.MinConfidence
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Size > ingest.MaxFileSize || f.Size == 0 {
			continue
		}
		var b []byte
		var err error
		if req.Staged {
			b, err = req.Repo.VCS.StagedContent(ctx, f.Rel)
		} else {
			b, err = fs.ReadFile(req.Repo.FS, f.Rel)
		}
		if err != nil {
			continue
		}
		for _, h := range s.Literals.Scan(b) {
			if h.Conf < minConf {
				continue
			}
			out = append(out, &finding.Literal{
				DataType: h.DataType, Pos: ir.Pos{File: f.Rel, Line: h.Line, Col: h.Col}, Masked: h.Masked,
				ValueHash: h.Hash, Confidence: h.Conf, Detector: h.Detector,
			})
		}
	}
	return out, nil
}

// lower runs each language's frontend over its target files.
func (s *Scanner) lower(ctx context.Context, req Request, targets []ingest.File, res *Result) (*ir.Module, []string) {
	cfg := req.Config
	langs := map[string]bool{}
	for _, l := range cfg.Languages {
		langs[lang.Normalize(l)] = true
	}
	groups := map[string][]string{}
	for _, f := range targets {
		l, ok := lang.Lookup(f.Lang)
		if !ok || l.Kind != lang.Code {
			continue
		}
		if f.Test && !cfg.IncludeTests {
			continue
		}
		if l.Ignored(f.Rel) {
			continue
		}
		if len(langs) > 0 && !langs[f.Lang] {
			continue
		}
		groups[f.Lang] = append(groups[f.Lang], f.Rel)
	}
	fopts := frontend.Options{
		Root:      req.Repo.Root,
		FS:        req.Repo.FS,
		BuildTags: cfg.GoBuildTags,
		Logf:      req.Logf,
		KnownFunc: req.Cache.Has,
	}
	prog := &ir.Module{}
	var lowered []string
	langNames := make([]string, 0, len(groups))
	for l := range groups {
		langNames = append(langNames, l)
	}
	sort.Strings(langNames)
	for _, name := range langNames {
		files := groups[name]
		fe, err := s.Frontends.Frontend(name, fopts)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d files skipped: %v", name, len(files), err))
			continue
		}
		t0 := s.Clock()
		m, err := fe.Lower(ctx, files)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		req.logf("%s: lowered %d files, %d functions in %s", name, len(files), len(m.Funcs), s.Clock().Sub(t0).Round(time.Millisecond))
		res.FilesAnalyzed[name] = len(files)
		lowered = append(lowered, files...)
		prog.Merge(m)
	}
	return prog, lowered
}

func (s *Scanner) buildSchema(req Request, all []ingest.File, prog *ir.Module, lowered []string, mode string) *detect.Schema {
	types := append([]*ir.TypeDecl{}, prog.Types...)
	for _, f := range all {
		if f.Lang != lang.Proto && f.Lang != lang.SQL {
			continue
		}
		b, err := fs.ReadFile(req.Repo.FS, f.Rel)
		if err != nil {
			continue
		}
		if f.Lang == lang.Proto {
			types = append(types, s.Schemas.ParseProto(f.Rel, b)...)
		} else {
			types = append(types, s.Schemas.ParseSQL(f.Rel, b)...)
		}
	}
	loweredSet := map[string]bool{}
	for _, f := range lowered {
		loweredSet[f] = true
	}
	if mode == ModeDiff || mode == ModePaths {
		types = append(types, req.Cache.SchemaTypes(loweredSet)...)
	}
	schema := s.Schemas.Build(types)

	byFile := map[string][]*ir.TypeDecl{}
	for _, t := range prog.Types {
		if t.Pos.File != "" && loweredSet[t.Pos.File] {
			byFile[t.Pos.File] = append(byFile[t.Pos.File], t)
		}
	}
	if mode == ModeFull {
		req.Cache.ResetSchema()
	}
	for _, f := range lowered {
		req.Cache.SetSchema(f, byFile[f])
	}
	return schema
}

func dedupeIDs(funcs []*ir.Func) {
	seen := map[string]int{}
	for _, f := range funcs {
		if n, ok := seen[f.ID]; ok {
			seen[f.ID] = n + 1
			f.ID = fmt.Sprintf("%s~%d", f.ID, n+1)
			continue
		}
		seen[f.ID] = 1
	}
}
