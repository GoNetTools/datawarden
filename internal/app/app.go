// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package app is the composition root: the one place that chooses concrete
// implementations (disk, git, HTTP, wall clock, frontends) and injects them
// into the scanner and the CLI. Everything else depends on interfaces.
package app

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/GoNetTools/datawarden/internal/analysis"
	"github.com/GoNetTools/datawarden/internal/baseline"
	"github.com/GoNetTools/datawarden/internal/cache"
	"github.com/GoNetTools/datawarden/internal/cicomment"
	"github.com/GoNetTools/datawarden/internal/cli"
	"github.com/GoNetTools/datawarden/internal/config"
	"github.com/GoNetTools/datawarden/internal/datamap"
	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/frontend/golang"
	"github.com/GoNetTools/datawarden/internal/frontend/treesitter"
	"github.com/GoNetTools/datawarden/internal/ingest"
	"github.com/GoNetTools/datawarden/internal/platform"
	"github.com/GoNetTools/datawarden/internal/policy"
	"github.com/GoNetTools/datawarden/internal/report"
	"github.com/GoNetTools/datawarden/internal/rules"
	"github.com/GoNetTools/datawarden/internal/ruletest"
	"github.com/GoNetTools/datawarden/internal/scan"
)

// Version is set at build time with
// -ldflags "-X github.com/GoNetTools/datawarden/internal/app.Version=v1.2.3".
var Version = "dev"

// Components are the shared services, exposed so integration tests can
// reuse the production wiring with a different workspace or clock.
type Components struct {
	Classifier *detect.Classifier
	Frontends  *frontend.Registry
	Scanner    *scan.Scanner
}

// NewComponents builds the analysis services with the given clock.
func NewComponents(clock func() time.Time) *Components {
	classifier := detect.NewClassifier(detect.DefaultTaxonomy())
	reg := frontend.NewRegistry()
	golang.Register(reg, nil) // packages.Load
	treesitter.Register(reg)
	return &Components{
		Classifier: classifier,
		Frontends:  reg,
		Scanner: &scan.Scanner{
			Files:     ingest.Lister{},
			Frontends: reg,
			Analyzer:  analysis.Engine{Names: classifier},
			Literals:  &detect.LiteralScanner{Classifier: classifier},
			Schemas:   detect.Schemas{Classifier: classifier},
			Clock:     clock,
		},
	}
}

// Deps overrides parts of the production wiring (tests).
type Deps struct {
	Workspace cli.Workspace
	Clock     func() time.Time
	Getenv    func(string) string
	HTTP      cicomment.Doer
}

// New returns the production application.
func New(stdout, stderr io.Writer) *cli.App {
	return NewWith(stdout, stderr, Deps{})
}

// NewWith returns the application with some dependencies replaced.
func NewWith(stdout, stderr io.Writer, d Deps) *cli.App {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	if d.Workspace == nil {
		d.Workspace = platform.OS{Git: platform.ExecGit}
	}
	if d.HTTP == nil {
		d.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	comp := NewComponents(d.Clock)
	return &cli.App{
		Stdout:    stdout,
		Stderr:    stderr,
		Version:   Version,
		Workspace: d.Workspace,
		Scanner:   comp.Scanner,
		OpenCache: func(repo scan.Repo, dir, rulesHash string, persist bool) scan.Cache {
			var p cache.Persister
			if persist {
				p = platform.FileBlob{Path: filepath.Join(dir, cache.FileName)}
			}
			return cache.Open(p, ingest.NewHasher(repo.FS), Version, rulesHash)
		},
		Commenter: commenter{cicomment.Client{HTTP: d.HTTP, Getenv: d.Getenv, ReadFile: os.ReadFile}},
		Catalog:   comp.Classifier,

		Configs:    config.Loader{},
		Rules:      ruleLoader{},
		Policy:     policy.Policies{Catalog: comp.Classifier},
		Baselines:  baseline.Codec{},
		Reporter:   report.Writer{},
		DataMapper: datamap.Mapper{},
		RuleTester: ruletest.Tester{},
		Languages:  comp.Frontends.Languages,
		Links:      report.CILinks(d.Getenv),
		Clock:      d.Clock,
	}
}

// ruleLoader adapts rules.Load to the CLI's RuleLoader.
type ruleLoader struct{}

func (ruleLoader) Load(fsys fs.FS, paths ...string) (cli.RuleSet, error) {
	set, err := rules.Load(fsys, paths...)
	if err != nil {
		return nil, err // not a typed nil inside the interface
	}
	return set, nil
}

// commenter adapts cicomment errors to the CLI's.
type commenter struct{ c cicomment.Client }

func (c commenter) Post(body string) (string, error) {
	what, err := c.c.Post(body)
	if errors.Is(err, cicomment.ErrNotInReview) {
		return "", cli.ErrNotInReview
	}
	return what, err
}
