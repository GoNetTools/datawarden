// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/scan"
)

// runRulesTest checks annotated example code against the repository's
// effective rules: `datawarden rules test .datawarden/rules/examples`. The
// examples directory is scanned as its own repository root with the
// current repository's rules and policy.
func (a *App) runRulesTest(ctx context.Context, args []string) (int, error) {
	fs := a.flagSet("rules test")
	var c common
	c.register(fs)
	fs.Usage = func() {
		fmt.Fprint(a.Stderr, `Usage: datawarden rules test DIR [flags]

Scans DIR with the repository's rules and policy and checks the annotations
in its files. A comment line applies to the next line:

  // ruleid: <id>      the line must produce a finding for rule <id>
  // ok: <id>          the line must not produce a violation for rule <id>
  // todoruleid: <id>  known miss (fails once it is reported)
  // todook: <id>      known false positive (fails once it is gone)

Every violation in DIR must be annotated. Go examples need a go.mod in DIR.

`)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitError, err
	}
	if len(pos) != 1 {
		fs.Usage()
		return ExitError, errors.New("rules test needs one examples directory")
	}
	s, err := a.open(&c, nil)
	if err != nil {
		return ExitError, err
	}
	dir, err := a.Workspace.Abs(pos[0])
	if err != nil {
		return ExitError, err
	}
	if !a.Workspace.IsDir(dir) {
		return ExitError, fmt.Errorf("%s is not a directory", pos[0])
	}
	repo := a.Workspace.Open(dir)
	anns, err := a.RuleTester.Parse(repo.FS, ".")
	if err != nil {
		return ExitError, err
	}
	if len(anns) == 0 {
		return ExitError, fmt.Errorf("%s has no ruleid/ok annotations", pos[0])
	}
	res, err := a.Scanner.Run(ctx, scan.Request{
		Repo:   repo,
		Cache:  a.OpenCache(repo, "", s.rules.Hash(), false),
		Config: s.cfg,
		Rules:  s.rules,
		Logf:   s.logf,
	})
	if err != nil {
		return ExitError, err
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(a.Stderr, "warning: %s\n", w)
	}
	flows, _ := a.Policy.Apply(s.cfg, res.Flows, res.Literals)
	out := a.RuleTester.Check(s.rules, anns, flows)
	for _, k := range out.Known {
		fmt.Fprintf(a.Stdout, "known   %s\n", k)
	}
	for _, f := range out.Failures {
		fmt.Fprintf(a.Stdout, "FAIL    %s\n", f)
	}
	var untested []string
	for _, r := range s.rules.All() {
		if !strings.HasPrefix(r.Origin, "builtin:") && !out.Covered[r.ID] {
			untested = append(untested, r.ID)
		}
	}
	if len(untested) > 0 {
		fmt.Fprintf(a.Stdout, "repository rules without a ruleid example: %s\n", strings.Join(untested, ", "))
	}
	fmt.Fprintf(a.Stdout, "datawarden: %d annotation(s), %d failure(s), %d known gap(s)\n", len(anns), len(out.Failures), len(out.Known))
	if len(out.Failures) > 0 {
		return ExitViolation, nil
	}
	return ExitClean, nil
}
