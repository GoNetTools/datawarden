// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package cache persists function summaries, the call graph and schema
// hints between runs. Entries are keyed by function ID and validated by the
// content hash of the file that defines the function, so a PR scan can
// reuse everything the PR did not touch.
//
// Storage and hashing are injected: a Persister holds the bytes (a file in
// production, memory in tests) and a Hasher fingerprints repository files.
package cache

import (
	"encoding/json"
	"slices"
	"sort"
	"sync"

	"github.com/GoNetTools/datawarden/internal/analysis"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// FormatVersion changes whenever the on-disk format or the analysis
// semantics change incompatibly, including every new ir.Version.
const FormatVersion = 9

// FileName is the cache file inside the cache directory.
const FileName = "datawarden-cache.json"

// Persister loads and stores the serialized cache.
type Persister interface {
	// Load returns the stored bytes; a missing cache returns (nil, nil).
	Load() ([]byte, error)
	Save(data []byte) error
}

// Hasher returns the content hash of a repository file ("" if missing).
type Hasher interface {
	Hash(rel string) string
}

// Func is a cached function.
type Func struct {
	File     string            `json:"file"`
	FileHash string            `json:"file_hash"`
	Lang     string            `json:"lang"`
	Callees  []string          `json:"callees,omitempty"`
	Summary  *analysis.Summary `json:"summary,omitempty"`
}

// SchemaFile holds the type declarations and class table entries
// extracted from one file.
type SchemaFile struct {
	Hash    string         `json:"hash"`
	Types   []*ir.TypeDecl `json:"types"`
	Classes []*ir.Class    `json:"classes,omitempty"`
}

type document struct {
	Version   int                    `json:"version"`
	Tool      string                 `json:"tool"`
	RulesHash string                 `json:"rules_hash"`
	Funcs     map[string]*Func       `json:"funcs"`
	Schema    map[string]*SchemaFile `json:"schema"`
}

// Store is the cache. It implements scan.Cache.
type Store struct {
	doc       document
	persister Persister
	hasher    Hasher
}

// Open loads the cache through p. A missing, corrupt or incompatible cache
// (other tool version or rule set) yields an empty store, never an error.
func Open(p Persister, h Hasher, tool, rulesHash string) *Store {
	s := &Store{persister: p, hasher: h, doc: document{Version: FormatVersion, Tool: tool, RulesHash: rulesHash, Funcs: map[string]*Func{}, Schema: map[string]*SchemaFile{}}}
	if p == nil {
		return s
	}
	b, err := p.Load()
	if err != nil || len(b) == 0 {
		return s
	}
	var disk document
	if json.Unmarshal(b, &disk) != nil || disk.Version != FormatVersion || disk.RulesHash != rulesHash || disk.Tool != tool {
		return s
	}
	if disk.Funcs != nil {
		s.doc.Funcs = disk.Funcs
	}
	if disk.Schema != nil {
		s.doc.Schema = disk.Schema
	}
	return s
}

// Empty reports whether there is no call graph to work from.
func (s *Store) Empty() bool { return len(s.doc.Funcs) == 0 }

// Has reports whether a function is in the cached call graph.
func (s *Store) Has(id string) bool {
	_, ok := s.doc.Funcs[id]
	return ok
}

// Lookup returns a cached summary if the defining file is unchanged.
func (s *Store) Lookup(id string) *analysis.Summary {
	f, ok := s.doc.Funcs[id]
	if !ok || f.Summary == nil || s.hasher == nil {
		return nil
	}
	if s.hasher.Hash(f.File) != f.FileHash {
		return nil
	}
	return f.Summary
}

// CallersOf returns the functions that called id when the cache was
// written.
func (s *Store) CallersOf(id string) []string {
	var out []string
	for caller, f := range s.doc.Funcs {
		if slices.Contains(f.Callees, id) {
			out = append(out, caller)
		}
	}
	sort.Strings(out)
	return out
}

// Callers returns the files containing (transitive, up to depth) callers of
// functions defined in the given files.
func (s *Store) Callers(files []string, depth int) []string {
	inFiles := map[string]bool{}
	for _, f := range files {
		inFiles[f] = true
	}
	rev := map[string][]string{}
	for id, f := range s.doc.Funcs {
		for _, c := range f.Callees {
			rev[c] = append(rev[c], id)
		}
	}
	var frontier []string
	seen := map[string]bool{}
	for id, f := range s.doc.Funcs {
		if inFiles[f.File] {
			frontier = append(frontier, id)
			seen[id] = true
		}
	}
	out := map[string]bool{}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		var next []string
		for _, id := range frontier {
			for _, caller := range rev[id] {
				if seen[caller] {
					continue
				}
				seen[caller] = true
				next = append(next, caller)
				if f := s.doc.Funcs[caller]; f != nil && !inFiles[f.File] {
					out[f.File] = true
				}
			}
		}
		frontier = next
	}
	res := make([]string, 0, len(out))
	for f := range out {
		res = append(res, f)
	}
	sort.Strings(res)
	return res
}

// Update records the functions analyzed in this run. When full is true the
// previous content is replaced; otherwise functions from re-lowered files
// are replaced and everything else is kept.
func (s *Store) Update(funcs []*ir.Func, res *analysis.Result, loweredFiles []string, full bool) {
	if full {
		s.doc.Funcs = map[string]*Func{}
	} else {
		relowered := map[string]bool{}
		for _, f := range loweredFiles {
			relowered[f] = true
		}
		for id, f := range s.doc.Funcs {
			if relowered[f.File] {
				delete(s.doc.Funcs, id)
			}
		}
	}
	for _, fn := range funcs {
		s.doc.Funcs[fn.ID] = &Func{File: fn.File, FileHash: s.hash(fn.File), Lang: fn.Lang, Callees: res.CallGraph[fn.ID], Summary: res.Summaries[fn.ID]}
	}
}

func (s *Store) hash(rel string) string {
	if s.hasher == nil {
		return ""
	}
	return s.hasher.Hash(rel)
}

// ResetSchema drops all cached schema declarations (full scans).
func (s *Store) ResetSchema() { s.doc.Schema = map[string]*SchemaFile{} }

// SetSchema stores the type declarations and class table entries of one
// file.
func (s *Store) SetSchema(file string, types []*ir.TypeDecl, classes []*ir.Class) {
	s.doc.Schema[file] = &SchemaFile{Hash: s.hash(file), Types: types, Classes: classes}
}

// SchemaTypes returns cached declarations for files not in skip whose
// content is unchanged.
func (s *Store) SchemaTypes(skip map[string]bool) []*ir.TypeDecl {
	var out []*ir.TypeDecl
	for _, e := range s.unchanged(skip) {
		out = append(out, e.Types...)
	}
	return out
}

// Classes returns the cached class table entries of files not in skip
// whose content is unchanged.
func (s *Store) Classes(skip map[string]bool) []*ir.Class {
	var out []*ir.Class
	for _, e := range s.unchanged(skip) {
		out = append(out, e.Classes...)
	}
	return out
}

// unchanged lists, in file order, the schema entries of files not in skip
// whose content still has the cached hash.
func (s *Store) unchanged(skip map[string]bool) []*SchemaFile {
	var files []string
	for f := range s.doc.Schema {
		files = append(files, f)
	}
	sort.Strings(files)
	var out []*SchemaFile
	for _, f := range files {
		if skip[f] {
			continue
		}
		if e := s.doc.Schema[f]; s.hash(f) == e.Hash {
			out = append(out, e)
		}
	}
	return out
}

// Save writes the cache through the persister.
func (s *Store) Save() error {
	if s.persister == nil {
		return nil
	}
	b, err := json.Marshal(s.doc)
	if err != nil {
		return err
	}
	return s.persister.Save(b)
}

// Memory is an in-memory Persister (tests, --no-cache).
type Memory struct {
	mu   sync.Mutex
	Data []byte
}

// Load implements Persister.
func (m *Memory) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.Data...), nil
}

// Save implements Persister.
func (m *Memory) Save(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Data = append([]byte(nil), b...)
	return nil
}
