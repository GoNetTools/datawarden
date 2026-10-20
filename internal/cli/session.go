// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/scan"
)

// common flags shared by scan, baseline, map and rules.
type common struct {
	root       string
	configPath string
	noCache    bool
	verbose    bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.root, "root", "", "repository root (default: git top-level of the scanned path)")
	fs.StringVar(&c.configPath, "config", "", "config file (default <root>/.datawarden.yaml)")
	fs.BoolVar(&c.noCache, "no-cache", false, "do not read or write the summary cache")
	fs.BoolVar(&c.verbose, "verbose", false, "log progress to stderr")
}

// session is everything a command needs about the repository.
type session struct {
	root  string
	repo  scan.Repo
	paths []string // root-relative, slash-separated
	cfg   *config.Config
	rules RuleSet
	// taxonomy digests the repository's taxonomy files: a change to
	// them, like a rule change, invalidates cached summaries.
	taxonomy string
	logf     func(string, ...any)
}

func (a *App) open(c *common, positional []string) (*session, error) {
	ws := a.Workspace
	s := &session{}
	var err error
	switch {
	case c.root != "":
		if s.root, err = ws.Abs(c.root); err != nil {
			return nil, err
		}
	case len(positional) == 1 && ws.IsDir(positional[0]):
		dir, err := ws.Abs(positional[0])
		if err != nil {
			return nil, err
		}
		s.root = ws.FindRoot(dir)
		if dir == s.root {
			positional = nil
		}
	default:
		wd, err := ws.Getwd()
		if err != nil {
			return nil, err
		}
		s.root = ws.FindRoot(wd)
	}
	for _, p := range positional {
		abs, err := ws.Abs(p)
		if err != nil {
			return nil, err
		}
		rel, err := a.relToRoot(s.root, abs)
		if err != nil {
			return nil, err
		}
		s.paths = append(s.paths, rel)
	}
	s.repo = ws.Open(s.root)

	if c.configPath != "" {
		p, err := ws.Abs(c.configPath)
		if err != nil {
			return nil, err
		}
		b, err := ws.ReadFile(p)
		if err != nil {
			return nil, err
		}
		s.cfg, err = a.Configs.Parse(b, c.configPath)
		if err != nil {
			return nil, err
		}
	} else if s.cfg, err = a.Configs.Load(s.repo.FS, config.FileName, false); err != nil {
		return nil, err
	}

	if s.taxonomy, err = a.loadTaxonomy(s); err != nil {
		return nil, err
	}
	var rulePaths []string
	for _, r := range s.cfg.Rules {
		rel := filepath.ToSlash(r)
		if filepath.IsAbs(r) {
			if rel, err = a.relToRoot(s.root, r); err != nil {
				return nil, fmt.Errorf("rules path %s: %w", r, err)
			}
		}
		rulePaths = append(rulePaths, rel)
	}
	var pluginLangs []string
	for _, f := range s.cfg.Frontends {
		pluginLangs = append(pluginLangs, f.Lang)
	}
	if s.rules, err = a.Rules.Load(s.repo.FS, pluginLangs, rulePaths...); err != nil {
		return nil, err
	}
	if c.verbose {
		s.logf = func(format string, args ...any) { fmt.Fprintf(a.Stderr, "datawarden: "+format+"\n", args...) }
	}
	return s, nil
}

// loadTaxonomy extends the catalog with the repository's taxonomy files
// (config.Taxonomy; missing files are skipped) and returns a digest of
// their contents.
func (a *App) loadTaxonomy(s *session) (string, error) {
	h := sha256.New()
	for _, p := range s.cfg.Taxonomy {
		rel := filepath.ToSlash(p)
		if filepath.IsAbs(p) {
			var err error
			if rel, err = a.relToRoot(s.root, p); err != nil {
				return "", fmt.Errorf("taxonomy path %s: %w", p, err)
			}
		}
		b, err := fs.ReadFile(s.repo.FS, rel)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("taxonomy %s: %w", p, err)
		}
		if err := a.Catalog.Extend(b); err != nil {
			return "", fmt.Errorf("taxonomy %s: %w", p, err)
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}

func (a *App) relToRoot(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%s is outside the repository %s", abs, root)
	}
	return rel, nil
}

// inRoot resolves a config-relative path (baseline, cache dir) to a path on
// the workspace.
func (s *session) inRoot(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.root, filepath.FromSlash(p))
}

func (a *App) request(s *session, c *common) scan.Request {
	return scan.Request{
		Repo:       s.repo,
		Cache:      a.OpenCache(s.repo, s.inRoot(s.cfg.CacheDir), s.cacheKey(), !c.noCache),
		Config:     s.cfg,
		Rules:      s.rules,
		Heuristics: s.rules.Heuristics(),
		Paths:      s.paths,
		Logf:       s.logf,
	}
}

// cacheKey is what cached summaries are valid for: the rules, the
// repository's taxonomy and its external frontends (their commands: a
// change inside a program is not seen, so clear the cache after one).
func (s *session) cacheKey() string {
	key := s.rules.Hash()
	if s.taxonomy != "" {
		key += "+" + s.taxonomy
	}
	if len(s.cfg.Frontends) > 0 {
		b, _ := json.Marshal(s.cfg.Frontends)
		sum := sha256.Sum256(b)
		key += "+fe" + hex.EncodeToString(sum[:8])
	}
	return key
}

// markBaseline marks findings accepted by the baseline file at path (a
// missing file is an empty baseline) and returns the baseline size and the
// entries no longer found.
func (a *App) markBaseline(path string, flows []*finding.Flow, lits []*finding.Literal) (size int, unseen []string, err error) {
	var data []byte
	if path != "" {
		if data, err = a.Workspace.ReadFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 0, nil, err
		}
	}
	size, unseen, err = a.Baselines.Mark(data, flows, lits)
	if err != nil {
		return 0, nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return size, unseen, nil
}

// parseInterspersed allows flags after positional arguments
// ("datawarden scan . --diff origin/main").
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if f := fs.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue
				}
				if i+1 < len(args) {
					flags = append(flags, args[i+1])
					i++
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return append(pos, fs.Args()...), nil
}

// warn prints each warning on stderr.
func (a *App) warn(warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", w)
	}
}
