// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the piiflow command line as an App whose
// collaborators (workspace, scanner, cache, commenter, clock) are injected.
// internal/app wires the production implementations; tests wire fakes.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/scan"
)

// Exit codes.
const (
	ExitClean     = 0
	ExitViolation = 1
	ExitError     = 2
)

// Scanner runs scans (*scan.Scanner).
type Scanner interface {
	Run(ctx context.Context, req scan.Request) (*scan.Result, error)
}

// Workspace is the App's view of the machine: the working directory,
// repositories and plain files. platform.OS implements it on disk; tests
// use an in-memory workspace.
type Workspace interface {
	Getwd() (string, error)
	// Abs resolves path against the working directory.
	Abs(path string) (string, error)
	// FindRoot returns the repository root enclosing dir: the nearest
	// directory with .git or .piiflow.yaml, or dir itself.
	FindRoot(dir string) string
	IsDir(path string) bool
	// Open returns the file system and version control of a repository.
	Open(root string) scan.Repo
	ReadFile(path string) ([]byte, error)
	// WriteFile creates parent directories as needed.
	WriteFile(path string, data []byte) error
}

// CacheOpener opens the analysis cache of a repository. persist=false
// (--no-cache) returns a cache that neither reads nor writes storage.
type CacheOpener func(repo scan.Repo, dir, rulesHash string, persist bool) scan.Cache

// Commenter posts the PR/MR summary comment (cicomment.Client).
type Commenter interface {
	Post(body string) (string, error)
}

// Catalog describes data types (*detect.Classifier).
type Catalog interface {
	Lookup(id string) detect.DataType
}

// App is the command line application.
type App struct {
	Stdout, Stderr io.Writer
	Version        string

	Workspace Workspace
	Scanner   Scanner
	OpenCache CacheOpener
	Commenter Commenter
	Catalog   Catalog

	Configs    ConfigLoader
	Rules      RuleLoader
	Policy     Policy
	Baselines  BaselineCodec
	Reporter   Reporter
	DataMapper DataMapper
	RuleTester RuleTester
	// Languages lists the available frontends (for `version`).
	Languages func() []string
	// Links builds CI source links for Markdown reports; may be nil.
	Links func(ir.Pos) string
	Clock func() time.Time
}

const usage = `piiflow — find personal data (PII) flowing to logs, SDKs and third parties.

Usage:
  piiflow scan [paths...] [flags]      scan the repository (or only the given paths)
  piiflow scan --diff origin/main      PR mode: changed files plus their callers
  piiflow baseline                     accept the current findings
  piiflow map --format dpia            personal-data map (dpia, json, csv, mermaid)
  piiflow rules                        print the effective sink/source/transform rules
  piiflow rules test DIR               check annotated examples in DIR against the rules
  piiflow init                         write .piiflow.yaml and .piiflowignore
  piiflow comment piiflow.md           create/update the PR (GitHub) or MR (GitLab) summary comment
  piiflow version

Exit codes: 0 clean, 1 new policy violation, 2 error.
Run "piiflow <command> -h" for flags.
`

// Run executes the command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if err := a.check(); err != nil {
		fmt.Fprintf(a.Stderr, "piiflow: %v\n", err)
		return ExitError
	}
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return ExitError
	}
	var err error
	code := ExitClean
	switch args[0] {
	case "scan":
		code, err = a.runScan(ctx, args[1:])
	case "baseline":
		err = a.runBaseline(ctx, args[1:])
	case "map":
		err = a.runMap(ctx, args[1:])
	case "rules":
		if len(args) > 1 && args[1] == "test" {
			code, err = a.runRulesTest(ctx, args[2:])
		} else {
			err = a.runRules(args[1:])
		}
	case "init":
		err = a.runInit(args[1:])
	case "comment":
		err = a.runComment(args[1:])
	case "version", "--version", "-v":
		langs := []string{}
		if a.Languages != nil {
			langs = a.Languages()
		}
		fmt.Fprintf(a.Stdout, "piiflow %s (frontends: %s)\n", a.Version, strings.Join(langs, ", "))
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
	default:
		fmt.Fprintf(a.Stderr, "piiflow: unknown command %q\n\n%s", args[0], usage)
		return ExitError
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		fmt.Fprintf(a.Stderr, "piiflow: %v\n", err)
		return ExitError
	}
	return code
}

func (a *App) check() error {
	var missing []string
	if a.Stdout == nil || a.Stderr == nil {
		missing = append(missing, "Stdout/Stderr")
	}
	if a.Workspace == nil {
		missing = append(missing, "Workspace")
	}
	if a.Scanner == nil {
		missing = append(missing, "Scanner")
	}
	if a.OpenCache == nil {
		missing = append(missing, "OpenCache")
	}
	if a.Catalog == nil {
		missing = append(missing, "Catalog")
	}
	if a.Clock == nil {
		missing = append(missing, "Clock")
	}
	for name, ok := range map[string]bool{
		"Configs": a.Configs != nil, "Rules": a.Rules != nil, "Policy": a.Policy != nil, "Baselines": a.Baselines != nil,
		"Reporter": a.Reporter != nil, "DataMapper": a.DataMapper != nil, "RuleTester": a.RuleTester != nil,
	} {
		if !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("app is missing dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}
