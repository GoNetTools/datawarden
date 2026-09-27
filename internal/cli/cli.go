// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the datawarden command line as an App whose
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

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/scan"
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

// Lowerer lowers code to IR without analysing it (*scan.Scanner), for
// `datawarden ir`. A Scanner that does not implement it cannot run that
// command.
type Lowerer interface {
	Lower(ctx context.Context, req scan.Request) (*ir.Module, error)
}

// Workspace is the App's view of the machine: the working directory,
// repositories and plain files. platform.OS implements it on disk; tests
// use an in-memory workspace.
type Workspace interface {
	Getwd() (string, error)
	// Abs resolves path against the working directory.
	Abs(path string) (string, error)
	// FindRoot returns the repository root enclosing dir: the nearest
	// directory with .git or .datawarden.yaml, or dir itself.
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
	Grapher    FlowGrapher
	RuleTester RuleTester
	// Explainer explains findings (`datawarden explain`); may be nil.
	Explainer Explainer
	// Languages lists the available frontends (for `version`).
	Languages func() []string
	// Links builds CI source links for Markdown reports; may be nil.
	Links func(ir.Pos) string
	Clock func() time.Time
}

const usage = `datawarden — find sensitive data (PII, PHI, card data, credentials) flowing to logs, SDKs and third parties.

Usage:
  datawarden scan [paths...] [flags]      scan the repository (or only the given paths)
  datawarden scan --diff origin/main      PR mode: changed files plus their callers
  datawarden baseline                     accept the current findings
  datawarden map --format dpia            personal-data map (dpia, json, csv, mermaid)
  datawarden graph [paths...]             draw the call graph of the violations (svg, dot, mermaid)
  datawarden rules                        print the effective sink/source/transform rules
  datawarden rules test DIR               check annotated examples in DIR against the rules
  datawarden explain <fingerprint|file:line>  why a flow was reported, step by step, and what would silence it
  datawarden ir [paths...]                print the IR the analysis reads (--func, --format json, --verify)
  datawarden init                         write .datawarden.yaml and .datawardenignore
  datawarden comment datawarden.md           create/update the PR (GitHub) or MR (GitLab) summary comment
  datawarden version

Exit codes: 0 clean, 1 new policy violation, 2 error.
Run "datawarden <command> -h" for flags.
`

// Run executes the command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if err := a.check(); err != nil {
		fmt.Fprintf(a.Stderr, "datawarden: %v\n", err)
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
	case "graph":
		err = a.runGraph(ctx, args[1:])
	case "rules":
		if len(args) > 1 && args[1] == "test" {
			code, err = a.runRulesTest(ctx, args[2:])
		} else {
			err = a.runRules(args[1:])
		}
	case "ir":
		code, err = a.runIR(ctx, args[1:])
	case "explain":
		code, err = a.runExplain(ctx, args[1:])
	case "init":
		err = a.runInit(args[1:])
	case "comment":
		err = a.runComment(args[1:])
	case "version", "--version", "-v":
		langs := []string{}
		if a.Languages != nil {
			langs = a.Languages()
		}
		fmt.Fprintf(a.Stdout, "datawarden %s (frontends: %s)\n", a.Version, strings.Join(langs, ", "))
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
	default:
		fmt.Fprintf(a.Stderr, "datawarden: unknown command %q\n\n%s", args[0], usage)
		return ExitError
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		fmt.Fprintf(a.Stderr, "datawarden: %v\n", err)
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
		"Reporter": a.Reporter != nil, "DataMapper": a.DataMapper != nil, "Grapher": a.Grapher != nil, "RuleTester": a.RuleTester != nil,
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
