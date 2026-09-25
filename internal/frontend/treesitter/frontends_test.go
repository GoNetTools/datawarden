// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

// Sources are read through frontend.Options.FS, so tests need no files on disk.
func lower(t *testing.T, fe func(frontend.Options) frontend.Frontend, files map[string]string) *ir.Module {
	t.Helper()
	fsys := fstest.MapFS{}
	var names []string
	for n, src := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(src)}
		names = append(names, n)
	}
	m, err := fe(frontend.Options{FS: fsys}).Lower(context.Background(), names)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func calls(m *ir.Module) map[string]*ir.Call {
	out := map[string]*ir.Call{}
	for _, f := range m.Funcs {
		for _, in := range f.Instrs {
			if in.Call != nil {
				out[in.Call.Name] = in.Call
			}
		}
	}
	return out
}

func TestKotlinResolvesImportsAndMethods(t *testing.T) {
	m := lower(t, NewKotlin, map[string]string{"a/Repo.kt": `package a
import io.sentry.Sentry
class Repo {
  fun save(phone: String) { Sentry.setUser(phone); audit(phone) }
  fun audit(x: String) {}
}`})
	c := calls(m)
	if c["setUser"] == nil || c["setUser"].Callee != "io.sentry.Sentry.setUser" {
		t.Errorf("import resolution: %+v", c["setUser"])
	}
	if c["audit"] == nil || c["audit"].Target != "a.Repo.audit" || !c["audit"].HasRecv {
		t.Errorf("method resolution: %+v", c["audit"])
	}
}

func TestJavaAndTypeScriptReadFromFS(t *testing.T) {
	j := lower(t, NewJava, map[string]string{"p/A.java": `package p;
import android.util.Log;
class A { void f(String email) { Log.d("T", email); } }`})
	if c := calls(j)["d"]; c == nil || c.Callee != "android.util.Log.d" {
		t.Errorf("java: %+v", c)
	}
	ts := lower(t, NewTypeScript, map[string]string{"src/a.ts": `import * as Sentry from "@sentry/react";
export function f(email: string) { Sentry.setUser({ email }); }`})
	if c := calls(ts)["setUser"]; c == nil || c.Callee != "@sentry/react.setUser" {
		t.Errorf("typescript: %+v", c)
	}
}

func TestMissingFileSystemIsAWarning(t *testing.T) {
	m, err := NewKotlin(frontend.Options{}).Lower(context.Background(), []string{"x.kt"})
	if err != nil || len(m.Warnings) != 1 {
		t.Errorf("err=%v warnings=%v", err, m.Warnings)
	}
}
