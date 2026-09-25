// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/config"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/scan"
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
	fs.StringVar(&c.configPath, "config", "", "config file (default <root>/.piiflow.yaml)")
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
	logf  func(string, ...any)
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
	if s.rules, err = a.Rules.Load(s.repo.FS, rulePaths...); err != nil {
		return nil, err
	}
	if c.verbose {
		s.logf = func(format string, args ...any) { fmt.Fprintf(a.Stderr, "piiflow: "+format+"\n", args...) }
	}
	return s, nil
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
		Repo:   s.repo,
		Cache:  a.OpenCache(s.repo, s.inRoot(s.cfg.CacheDir), s.rules.Hash(), !c.noCache),
		Config: s.cfg,
		Rules:  s.rules,
		Paths:  s.paths,
		Logf:   s.logf,
	}
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
// ("piiflow scan . --diff origin/main").
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
