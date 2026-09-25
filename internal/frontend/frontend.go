// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package frontend defines the per-language frontend interface and a
// Registry the composition root fills explicitly (no init()-time global
// registration), so tests can register fakes.
package frontend

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"sync"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// Frontend converts source files of one language into IR.
type Frontend interface {
	Lang() string
	// Lower converts the given root-relative files. Frontends that need
	// whole-package context (Go) may read more files than listed but only
	// emit functions defined in the listed files.
	Lower(ctx context.Context, files []string) (*ir.Module, error)
}

// Options are passed to frontend factories for one scan.
type Options struct {
	// Root is the repository root on disk. Only frontends that must hand a
	// directory to an external tool (go/packages) use it.
	Root string
	// FS is the repository file system; frontends read sources through it.
	FS        fs.FS
	BuildTags []string
	// Logf receives diagnostics; may be nil.
	Logf func(format string, args ...any)
	// KnownFunc reports whether a function ID exists in the cached call
	// graph. Frontends without whole-program type information use it to
	// resolve calls into files that are not part of a PR scan.
	KnownFunc func(id string) bool
}

// Factory creates a frontend for one scan.
type Factory func(Options) Frontend

// Registrar is what a frontend package needs to make its languages
// available (implemented by *Registry). Frontend packages register through
// it, so they never depend on the registry's implementation.
type Registrar interface {
	Register(lang string, f Factory)
	RegisterUnavailable(lang, reason string)
}

// Registry maps languages to frontend factories.
type Registry struct {
	mu          sync.Mutex
	factories   map[string]Factory
	unavailable map[string]string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[string]Factory{}, unavailable: map[string]string{}}
}

// Register adds a frontend factory for a language.
func (r *Registry) Register(lang string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[lang] = f
	delete(r.unavailable, lang)
}

// RegisterUnavailable records why a language is not available in this
// build (e.g. tree-sitter frontends in a CGO_ENABLED=0 binary).
func (r *Registry) RegisterUnavailable(lang, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.factories[lang]; !ok {
		r.unavailable[lang] = reason
	}
}

// Frontend returns a frontend for lang configured with o.
func (r *Registry) Frontend(lang string, o Options) (Frontend, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.factories[lang]; ok {
		return f(o), nil
	}
	if why, ok := r.unavailable[lang]; ok {
		return nil, fmt.Errorf("%s", why)
	}
	return nil, fmt.Errorf("no frontend registered for %s", lang)
}

// Unavailable maps languages recorded as unavailable in this build to the
// reason.
func (r *Registry) Unavailable() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.unavailable))
	for l, why := range r.unavailable {
		out[l] = why
	}
	return out
}

// Languages lists languages with a frontend.
func (r *Registry) Languages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.factories))
	for l := range r.factories {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}
