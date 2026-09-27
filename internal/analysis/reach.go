// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// fileDeps approximates which files of the program can use code in which
// others, from what the IR names: a function a call resolves to or names,
// a class a value, load, store or construction has as its type, and for
// languages whose functions are named after their module (module:func),
// any name that starts with a module of the program. It stands in for the
// import graph, which the IR does not keep.
//
// A repository can hold several programs (a server and the browser app it
// serves, a copy of a library shipped as an asset); code in one cannot run
// closures created in another. See closureFlow.field.
type fileDeps struct {
	edges   map[string]map[string]bool
	reached map[string]map[string]bool
}

func newFileDeps(a *analyzer, funcs []*ir.Func) *fileDeps {
	d := &fileDeps{edges: map[string]map[string]bool{}, reached: map[string]map[string]bool{}}
	modules := map[string]string{} // "lib/insecurity" -> "lib/insecurity.ts"
	for _, f := range funcs {
		if i := strings.IndexByte(f.ID, ':'); i > 0 && f.File != "" {
			modules[f.ID[:i]] = f.File
		}
	}
	files := map[string]string{} // name -> file declaring it, "" when none
	fileOfName := func(name string) string {
		name = strings.TrimSuffix(strings.TrimLeft(name, "*&"), "?")
		if file, ok := files[name]; ok {
			return file
		}
		file := ""
		if f := a.funcs[name]; f != nil {
			file = f.File
		} else if c := a.cha.class(name); c != nil {
			file = c.File
		} else {
			// The longest module the name starts with: lib/insecurity.hash,
			// models/user.UserModel.findOne.
			for i := len(name) - 1; i > 0 && file == ""; i-- {
				if name[i] == '.' || name[i] == ':' {
					file = modules[name[:i]]
				}
			}
		}
		files[name] = file
		return file
	}
	for _, f := range funcs {
		if f.File == "" {
			continue
		}
		add := func(name string) {
			if to := fileOfName(name); to != "" && to != f.File {
				d.addEdge(f.File, to)
			}
		}
		add(f.Parent)
		for i := range f.Vars {
			add(f.Vars[i].Type)
		}
		for i := range f.Instrs {
			in := &f.Instrs[i]
			add(in.Func)
			add(in.Owner)
			if c := in.Call; c != nil {
				add(c.Target)
				add(c.Callee)
				add(c.RecvType)
			}
		}
	}
	return d
}

func (d *fileDeps) addEdge(from, to string) {
	m := d.edges[from]
	if m == nil {
		m = map[string]bool{}
		d.edges[from] = m
	}
	m[to] = true
}

// reaches reports whether code in file from can use code in file to,
// directly or through other files.
func (d *fileDeps) reaches(from, to string) bool {
	if from == to {
		return true
	}
	r, ok := d.reached[from]
	if !ok {
		r = map[string]bool{from: true}
		queue := []string{from}
		for len(queue) > 0 {
			f := queue[0]
			queue = queue[1:]
			for to := range d.edges[f] {
				if !r[to] {
					r[to] = true
					queue = append(queue, to)
				}
			}
		}
		d.reached[from] = r
	}
	return r[to]
}

// related reports whether code in file a and code in file b are part of
// one program: one uses the other, or both use the file that declares the
// type of the object between them (ownerFiles).
func (d *fileDeps) related(a, b string, ownerFiles []string) bool {
	if a == "" || b == "" || d.reaches(a, b) || d.reaches(b, a) {
		return true
	}
	for _, o := range ownerFiles {
		if d.reaches(a, o) && d.reaches(b, o) {
			return true
		}
	}
	return false
}
