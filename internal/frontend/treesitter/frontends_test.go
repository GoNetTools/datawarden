// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/ir"
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
	if err := m.Verify(); err != nil {
		t.Errorf("lowered IR does not verify:\n%v", err)
	}
	return m
}

// ops maps each called name to the op of an instruction calling it.
func ops(m *ir.Module) map[string]ir.Op {
	out := map[string]ir.Op{}
	for _, f := range m.Funcs {
		for _, in := range f.Instrs {
			if in.Call != nil {
				out[in.Call.Name] = in.Op
			}
		}
	}
	return out
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

// cancelDuring is a context cancelled after its first few Err calls: while
// a file is being parsed.
type cancelDuring struct {
	context.Context
	calls atomic.Int32
}

func (c *cancelDuring) Err() error {
	if c.calls.Add(1) > 2 {
		return context.Canceled
	}
	return nil
}

func TestCancellationStopsAParse(t *testing.T) {
	src := strings.Repeat("def f(email):\n    log(email)\n", 20000)
	ctx := &cancelDuring{Context: context.Background()}
	m, err := NewPython(frontend.Options{FS: fstest.MapFS{"a.py": {Data: []byte(src)}}}).Lower(ctx, []string{"a.py"})
	if err == nil && m != nil && (len(m.Funcs) > 0 || len(m.Warnings) > 0) {
		t.Errorf("a cancelled parse was lowered: %d functions, warnings %v", len(m.Funcs), m.Warnings)
	}
	if n := ctx.calls.Load(); n < 3 {
		t.Errorf("the parser never checked for cancellation (%d checks)", n)
	}
}

func TestPythonResolvesImportsAndMethods(t *testing.T) {
	m := lower(t, NewPython, map[string]string{
		"app/__init__.py": "",
		"app/util.py":     "def audit(x):\n    pass\n",
		"app/api/views.py": `import sentry_sdk as sdk
from ..util import audit
from . import helpers
from .models import Customer

class Repo:
    def save(self, phone: str):
        sdk.set_user({"phone": phone})
        audit(phone)
        self.check(phone)
        c = Customer(phone)
        c.notify()

    def check(self, x):
        pass
`,
		"app/api/models.py": "class Customer:\n    def notify(self):\n        pass\n",
	})
	c := calls(m)
	if c["set_user"] == nil || c["set_user"].Callee != "sentry_sdk.set_user" {
		t.Errorf("aliased module import: %+v", c["set_user"])
	}
	if c["audit"] == nil || c["audit"].Target != "app.util:audit" {
		t.Errorf("relative import (..): %+v", c["audit"])
	}
	if c["check"] == nil || c["check"].Target != "app.api.views:Repo.check" || !c["check"].HasRecv {
		t.Errorf("self method: %+v", c["check"])
	}
	if c["Customer"] == nil || ops(m)["Customer"] != ir.OpNew || c["Customer"].Callee != "app.api.models.Customer" {
		t.Errorf("constructor through a relative import (.): %+v", c["Customer"])
	}
	if c["notify"] == nil || c["notify"].Target != "app.api.models:Customer.notify" {
		t.Errorf("method on a constructed object: %+v", c["notify"])
	}
}

func TestPythonSchemaHints(t *testing.T) {
	m := lower(t, NewPython, map[string]string{"shop/models.py": `from dataclasses import dataclass
from django.db import models
from pydantic import BaseModel, Field

@dataclass
class Contact:
    email: str
    phone: str | None = None

class Customer(models.Model):
    contact = models.CharField(max_length=20, db_column="phone_number")
    MAX = 3

class SignupIn(BaseModel):
    mail: str = Field(alias="email")

class Service:
    def __init__(self, repo: Repo):
        self.repo = repo

    def run(self):
        pass
`})
	kinds := map[string]*ir.TypeDecl{}
	for _, td := range m.Types {
		kinds[td.Name] = td
	}
	want := map[string]string{"shop.models.Contact": "data", "shop.models.Customer": "entity", "shop.models.SignupIn": "data", "shop.models.Service": "class"}
	for name, kind := range want {
		if td := kinds[name]; td == nil || td.Kind != kind {
			t.Errorf("%s: %+v, want kind %s", name, td, kind)
		}
	}
	if f := kinds["shop.models.Customer"].Fields; len(f) != 1 || f[0].Tags["column"] != "phone_number" {
		t.Errorf("Django db_column (class constants are not fields): %+v", f)
	}
	if f := kinds["shop.models.SignupIn"].Fields; len(f) != 1 || f[0].Tags["json"] != "email" {
		t.Errorf("Pydantic alias: %+v", f)
	}
	if f := kinds["shop.models.Service"].Fields; len(f) != 1 || f[0].Name != "repo" || f[0].Type != "Repo" {
		t.Errorf("__init__ fields typed from parameters: %+v", f)
	}
}

func TestSwiftResolvesTypesAndMethods(t *testing.T) {
	m := lower(t, NewSwift, map[string]string{
		"App/Repo.swift": `import Sentry
final class Repo {
    let store = Store()
    func save(phone: String) {
        SentrySDK.setUser(phone)
        audit(phone)
        store.put(phone)
        Crashlytics.crashlytics().setUserID(phone)
    }
    func audit(_ x: String) {}
}`,
		"App/Store.swift": "final class Store {}\nextension Store {\n    func put(_ v: String) {}\n}\n",
	})
	c := calls(m)
	if c["setUser"] == nil || c["setUser"].Callee != "SentrySDK.setUser" {
		t.Errorf("type reference: %+v", c["setUser"])
	}
	if c["audit"] == nil || c["audit"].Target != "Repo.audit" || !c["audit"].HasRecv {
		t.Errorf("implicit self method: %+v", c["audit"])
	}
	if c["put"] == nil || c["put"].Target != "Store.put" {
		t.Errorf("extension method on a typed field: %+v", c["put"])
	}
	if c["setUserID"] == nil || c["setUserID"].Callee != "Crashlytics.crashlytics().setUserID" {
		t.Errorf("factory call: %+v", c["setUserID"])
	}
}

// Logger privacy is covered end to end by the Swift construct programs.
func TestSwiftSchemaHints(t *testing.T) {
	m := lower(t, NewSwift, map[string]string{"App/Models.swift": `struct Customer: Codable {
    let email: String
    let phone: String?
    enum CodingKeys: String, CodingKey {
        case email = "email_address"
        case phone
    }
}
@Model final class Item { var email: String = "" }
final class Service {
    let repo = Repo()
    func run(email: String) {}
}`})
	kinds := map[string]*ir.TypeDecl{}
	for _, td := range m.Types {
		kinds[td.Name] = td
	}
	if td := kinds["Customer"]; td == nil || td.Kind != "data" || td.Fields[0].Tags["json"] != "email_address" {
		t.Errorf("Codable struct with CodingKeys: %+v", td)
	}
	if td := kinds["Item"]; td == nil || td.Kind != "entity" {
		t.Errorf("SwiftData @Model: %+v", td)
	}
	if td := kinds["Service"]; td == nil || td.Kind != "class" {
		t.Errorf("a class with behaviour: %+v", td)
	}
}

// Arms under constant conditions are not lowered; conditions that depend
// on data keep both arms.
func TestConstantConditions(t *testing.T) {
	m := lower(t, NewPython, map[string]string{"app/c.py": `
DEBUG = False

def f(flag):
    if True:
        live1()
    else:
        dead1()
    if not DEBUG:
        live2()
    else:
        dead2()
    quiet = False
    if quiet:
        dead3()
    again = False
    again = True
    if again:
        live3()
    if flag:
        live4()
    while False:
        dead4()
`})
	c := calls(m)
	for _, name := range []string{"live1", "live2", "live3", "live4"} {
		if c[name] == nil {
			t.Errorf("%s: arm was dropped", name)
		}
	}
	for _, name := range []string{"dead1", "dead2", "dead3", "dead4"} {
		if c[name] != nil {
			t.Errorf("%s: dead arm was lowered", name)
		}
	}
}

// Code inside syntax the grammar cannot parse is still lowered, and the
// file gets a warning instead of being dropped silently.
func TestSyntaxErrorsAreRecoveredAndReported(t *testing.T) {
	m := lower(t, NewKotlin, map[string]string{"a/G.kt": "package a\nfun s(t: String) { println(t) ) }\nfun d(email: String) { log(email) }\n"})
	if calls(m)["log"] == nil {
		t.Error("the function after the syntax error was dropped")
	}
	if len(m.Warnings) != 1 || !strings.Contains(m.Warnings[0], "a/G.kt:2: ") || !strings.Contains(m.Warnings[0], "syntax error") {
		t.Errorf("warnings = %q", m.Warnings)
	}
}

// Loops branch on their condition; switch and when cases on their tests.
func TestConditionsOfLoopsAndCases(t *testing.T) {
	// branchesOn returns, per function, the ops or callee names that
	// define the conditions the function branches on.
	branchesOn := func(m *ir.Module, fn string) []string {
		var out []string
		for _, f := range m.Funcs {
			if !strings.HasSuffix(f.ID, fn) {
				continue
			}
			for _, b := range f.Blocks {
				if b.Term != ir.TermIf {
					continue
				}
				for _, in := range f.Instrs {
					if in.Dst != b.Cond {
						continue
					}
					if in.Call != nil {
						out = append(out, in.Call.Name)
					} else {
						out = append(out, in.Operator)
					}
				}
			}
		}
		return out
	}
	kt := lower(t, NewKotlin, map[string]string{"L.kt": `package app
fun loops(n: Int, m: Int) {
    var i = n
    while (i > 0) { i = i - 1 }
    do { i = i + 1 } while (i < m)
}
fun cases(c: Consents, s: Int) {
    when { c.hasConsent() -> println("a") }
    when (s) { 1, 2 -> println("b") else -> println("c") }
}
`})
	if got := branchesOn(kt, "loops"); len(got) != 2 {
		t.Errorf("Kotlin loops branch on %v", got)
	}
	if got := strings.Join(branchesOn(kt, "cases"), ","); got != "hasConsent,||" {
		t.Errorf("Kotlin when branches on %s", got)
	}
	java := lower(t, NewJava, map[string]string{"L.java": `class L {
    void f(int s, java.util.Iterator<String> it) {
        for (int i = 0; i < s; i++) { }
        do { } while (it.hasNext());
        switch (s) { case 1: break; case 2, 3: s = 0; default: s = 1; }
    }
}`})
	if got := strings.Join(branchesOn(java, "f"), ","); got != "<,hasNext,==,||" {
		t.Errorf("Java branches on %s", got)
	}
	ts := lower(t, NewTypeScript, map[string]string{"l.ts": `export function f(s: number) {
  while (s > 0) { s--; }
  switch (s) { case 1: break; default: s = 2; }
}`})
	if got := strings.Join(branchesOn(ts, "f"), ","); got != ">,==" {
		t.Errorf("TypeScript branches on %s", got)
	}
	py := lower(t, NewPython, map[string]string{"l.py": "def f(n, consents):\n    while n > 0:\n        n -= 1\n    if n and consents.has_consent():\n        print(n)\n"})
	if got := strings.Join(branchesOn(py, "f"), ","); got != "==,and" {
		t.Errorf("Python branches on %s", got)
	}
	sw := lower(t, NewSwift, map[string]string{"l.swift": "func f(n: Int) {\n    var i = n\n    repeat { i -= 1 } while i > 0\n}\n"})
	if got := branchesOn(sw, "f"); len(got) != 1 {
		t.Errorf("Swift repeat-while branches on %v", got)
	}
}

// Swift 5.9–6 syntax the grammar predates parses without errors once
// normalized (#44): typed throws, ownership modifiers, ~Copyable,
// @unchecked, await in conditions, empty associated-value patterns and
// #Preview blocks. The code after each is lowered.
func TestSwiftNewerSyntaxParses(t *testing.T) {
	src := `import SwiftUI

struct Mutex<Value: ~Copyable>: ~Copyable, @unchecked Sendable {
  init(_ initialValue: consuming sending Value) {}
  borrowing func withLock<R: ~Copyable, E: Error>(_ body: (inout sending Value) throws(E) -> sending R) throws(E) -> sending R {
    fatalError()
  }
}

func fetch(id: String) async throws(FetchError) -> Data { Data() }

func memories(api: API) async -> Entry? {
  for memory in api.memories {
    if let asset = memory.assets.first,
      let entry = try? await build(asset)
    {
      return entry
    }
  }
  guard
    let randomImage = try? await api.fetchSearchResults().first
  else {
    return nil
  }
  return first(randomImage)
}

func handle(result: Result<Void, Failure>) {
  switch result {
    case .success(): complete(true)
    case .failure(_): close()
  }
}

#Preview(as: .systemSmall) {
  Widget()
} timeline: {
  Entry.placeholder
}

func after(email: String) { log(email) }
`
	m := lower(t, NewSwift, map[string]string{"W.swift": src})
	if len(m.Warnings) != 0 {
		t.Errorf("warnings = %q", m.Warnings)
	}
	for _, name := range []string{"first", "complete", "close", "log"} {
		if calls(m)[name] == nil {
			t.Errorf("call of %s not lowered", name)
		}
	}
}

// The conformance and construct programs are valid code: every grammar
// must read them without errors, or the constructs they test go
// untested (#44).
func TestConformanceProgramsParseCleanly(t *testing.T) {
	for dir, fe := range map[string]func(frontend.Options) frontend.Frontend{
		"kotlin": NewKotlin, "java": NewJava, "swift": NewSwift, "python": NewPython, "typescript": NewTypeScript,
	} {
		root := filepath.Join("..", "testdata", "conformance", dir)
		var files []string
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				rel, _ := filepath.Rel(root, p)
				files = append(files, filepath.ToSlash(rel))
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		m, err := fe(frontend.Options{FS: os.DirFS(root)}).Lower(context.Background(), files)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range m.Warnings {
			if strings.Contains(w, "syntax error") {
				t.Errorf("%s: %s", dir, w)
			}
		}
	}
}
