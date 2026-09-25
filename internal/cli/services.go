// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"io/fs"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/config"
	"github.com/GoNetTools/pii-scanner/internal/datamap"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
	"github.com/GoNetTools/pii-scanner/internal/report"
	"github.com/GoNetTools/pii-scanner/internal/rules"
	"github.com/GoNetTools/pii-scanner/internal/ruletest"
)

// The services the commands use besides the Workspace, Scanner and cache.
// Each is implemented in its own package and wired by internal/app, so a
// command never depends on how configuration is parsed, rules are loaded,
// policy is applied or reports are rendered.

// ConfigLoader reads repository configuration (config.Loader).
type ConfigLoader interface {
	// Load reads name from fsys; a missing file gives the defaults unless
	// required.
	Load(fsys fs.FS, name string, required bool) (*config.Config, error)
	Parse(data []byte, origin string) (*config.Config, error)
}

// RuleSet is a repository's effective, validated rules (*rules.Set). It is
// also the scanner's rule matcher.
type RuleSet interface {
	Match(lang, kind string, c *ir.Call) []rules.Hit
	ByID(id string) *rules.Rule
	All() []*rules.Rule
	Hash() string
}

// RuleLoader loads the built-in rules merged with repository overrides
// (rules.Load, adapted in internal/app).
type RuleLoader interface {
	Load(fsys fs.FS, paths ...string) (RuleSet, error)
}

// Policy decides which findings are violations under a configuration
// (policy.Policies).
type Policy interface {
	Apply(cfg *config.Config, flows []*finding.Flow, lits []*finding.Literal) ([]*finding.Flow, []*finding.Literal)
}

// BaselineCodec reads and writes baseline documents (baseline.Codec). The
// commands read and write the files through the Workspace.
type BaselineCodec interface {
	// Mark decodes data (nil: no baseline), marks accepted findings and
	// returns the baseline size and the entries no longer found.
	Mark(data []byte, flows []*finding.Flow, lits []*finding.Literal) (size int, unseen []string, err error)
	// Encode builds a baseline of the current violations.
	Encode(flows []*finding.Flow, lits []*finding.Literal, commit string, now time.Time) (data []byte, entries int, err error)
}

// Reporter renders scan reports in a named format (report.Writer).
type Reporter interface {
	Write(w io.Writer, format string, r *report.Report) error
}

// DataMapper builds and renders the personal-data map (datamap.Mapper).
type DataMapper interface {
	Build(in datamap.Input) *datamap.Map
	Write(w io.Writer, format string, m *datamap.Map) error
}

// RuleTester parses and checks annotated rule examples (ruletest.Tester).
type RuleTester interface {
	Parse(fsys fs.FS, root string) ([]ruletest.Annotation, error)
	Check(rs ruletest.Rules, anns []ruletest.Annotation, flows []*finding.Flow) ruletest.Result
}
