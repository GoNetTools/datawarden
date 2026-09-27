// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/scan"
)

// runIR lowers files and prints their IR: `datawarden ir app/Login.kt
// --func login`. It is for people writing rules or frontends who want to
// see what the analysis sees.
func (a *App) runIR(ctx context.Context, args []string) (int, error) {
	fs := a.flagSet("ir")
	var c common
	c.register(fs)
	funcRe := fs.String("func", "", "only functions whose ID matches this `regexp`")
	format := fs.String("format", "text", "output format: text or json")
	classes := fs.Bool("classes", false, "also print the class table")
	verify := fs.Bool("verify", false, "check the IR against docs/IR.md (ir.Verify); exit 1 when it is invalid")
	fs.Usage = func() {
		fmt.Fprint(a.Stderr, `Usage: datawarden ir [paths...] [flags]

Lowers the given files (or the whole repository) to the IR the taint
analysis reads (docs/IR.md) and prints it.

`)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitError, err
	}
	if *format != "text" && *format != "json" {
		return ExitError, fmt.Errorf("unknown format %q (text, json)", *format)
	}
	var re *regexp.Regexp
	if *funcRe != "" {
		if re, err = regexp.Compile(*funcRe); err != nil {
			return ExitError, fmt.Errorf("--func: %w", err)
		}
	}
	s, err := a.open(&c, pos)
	if err != nil {
		return ExitError, err
	}
	lowerer, ok := a.Scanner.(Lowerer)
	if !ok {
		return ExitError, errors.New("this build cannot lower code without scanning")
	}
	m, err := lowerer.Lower(ctx, scan.Request{Repo: s.repo, Config: s.cfg, Paths: s.paths, Logf: s.logf})
	if err != nil {
		return ExitError, err
	}
	a.warn(m.Warnings)
	var funcs []*ir.Func
	for _, f := range m.Funcs {
		if re == nil || re.MatchString(f.ID) {
			funcs = append(funcs, f)
		}
	}
	sort.SliceStable(funcs, func(i, j int) bool {
		if funcs[i].File != funcs[j].File {
			return funcs[i].File < funcs[j].File
		}
		return funcs[i].Pos.Line < funcs[j].Pos.Line
	})
	var invalid []string
	if *verify {
		for _, f := range funcs {
			if err := ir.Verify(f); err != nil {
				invalid = append(invalid, err.Error())
			}
		}
	}
	switch *format {
	case "json":
		out := struct {
			Version int         `json:"version"`
			Funcs   []*ir.Func  `json:"funcs"`
			Classes []*ir.Class `json:"classes,omitempty"`
			Invalid []string    `json:"invalid,omitempty"`
		}{Version: ir.Version, Funcs: funcs, Invalid: invalid}
		if out.Funcs == nil {
			out.Funcs = []*ir.Func{}
		}
		if *classes {
			out.Classes = m.Classes
		}
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return ExitError, err
		}
	default:
		fmt.Fprintf(a.Stdout, "# IR version %d · %d functions\n", ir.Version, len(funcs))
		for _, f := range funcs {
			fmt.Fprintf(a.Stdout, "\n# %s:%d\n%s", f.File, f.Pos.Line, ir.Format(f))
		}
		if *classes {
			fmt.Fprintln(a.Stdout)
			for _, cl := range m.Classes {
				fmt.Fprintf(a.Stdout, "class %s", cl.Name)
				if len(cl.Supers) > 0 {
					fmt.Fprintf(a.Stdout, " : %s", strings.Join(cl.Supers, ", "))
				}
				fmt.Fprintln(a.Stdout)
				names := slices.Sorted(maps.Keys(cl.Methods))
				for _, n := range names {
					fmt.Fprintf(a.Stdout, "  %s -> %s\n", n, cl.Methods[n])
				}
			}
		}
		for _, e := range invalid {
			fmt.Fprintf(a.Stdout, "\ninvalid: %s\n", e)
		}
	}
	if len(invalid) > 0 {
		return ExitViolation, nil
	}
	return ExitClean, nil
}
