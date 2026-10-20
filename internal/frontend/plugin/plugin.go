// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package plugin runs a frontend that lives outside the binary: a program
// that reads a Request as JSON on its standard input and writes an
// ir.Module as JSON on its standard output. docs/IR.md ("External
// frontends") is the contract; the output is checked with ir.Verify before
// the analysis sees it, so a plugin cannot crash the engine.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// Exec runs a program in dir with the given input on its standard input
// and returns its standard output. A non-zero exit is an error whose text
// includes the program's standard error (platform.ExecCommand).
type Exec func(ctx context.Context, dir string, argv []string, input []byte) ([]byte, error)

// Request is what the plugin reads on its standard input.
type Request struct {
	// Version is the IR version the response must use (ir.Version).
	Version int `json:"version"`
	// Lang is the language the plugin is registered for.
	Lang string `json:"lang"`
	// Root is the repository root (absolute); Files are the files to
	// lower, slash-separated and relative to it.
	Root  string   `json:"root"`
	Files []string `json:"files"`
}

// Response is what the plugin writes on its standard output: the IR
// version it produced and the module, in the JSON form `datawarden ir
// --format json` prints.
type Response struct {
	Version int `json:"version"`
	ir.Module
}

// Frontend is a frontend.Frontend backed by a program.
type Frontend struct {
	lang    string
	command []string
	exec    Exec
	opts    frontend.Options
}

// New returns a factory for the plugin: command is the program and its
// arguments, run with exec from the repository root.
func New(lang string, command []string, exec Exec) frontend.Factory {
	return func(o frontend.Options) frontend.Frontend {
		return &Frontend{lang: lang, command: command, exec: exec, opts: o}
	}
}

// Lang implements frontend.Frontend.
func (f *Frontend) Lang() string { return f.lang }

// Lower implements frontend.Frontend: it runs the program once for all
// the files and verifies what it returns.
func (f *Frontend) Lower(ctx context.Context, files []string) (*ir.Module, error) {
	req := Request{Version: ir.Version, Lang: f.lang, Root: f.opts.Root, Files: files}
	if req.Files == nil {
		req.Files = []string{}
	}
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, err := f.exec(ctx, f.opts.Root, f.command, in)
	if err != nil {
		return nil, fmt.Errorf("frontend %s (%s): %w", f.lang, f.command[0], err)
	}
	return Decode(f.lang, out)
}

// Decode parses a plugin's response for lang and checks it: the IR
// version must be ir.Version and every function must pass ir.Verify. A
// function without a language gets lang.
func Decode(lang string, out []byte) (*ir.Module, error) {
	var resp Response
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("frontend %s: output is not a JSON module: %w", lang, err)
	}
	if resp.Version != ir.Version {
		return nil, fmt.Errorf("frontend %s: IR version %d, this datawarden reads version %d", lang, resp.Version, ir.Version)
	}
	m := &resp.Module
	if m.Lang == "" {
		m.Lang = lang
	}
	var bad []string
	for _, fn := range m.Funcs {
		if fn == nil {
			return nil, fmt.Errorf("frontend %s: null function in output", lang)
		}
		if fn.Lang == "" {
			fn.Lang = lang
		}
		if err := ir.Verify(fn); err != nil {
			bad = append(bad, err.Error())
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("frontend %s: invalid IR (see docs/IR.md): %s", lang, strings.Join(bad, "; "))
	}
	if m.Funcs == nil {
		m.Funcs = []*ir.Func{}
	}
	return m, nil
}
