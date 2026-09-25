// Copyright 2026 The datawarden Authors
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
	if c["Customer"] == nil || !c["Customer"].Construct || c["Customer"].Callee != "app.api.models.Customer" {
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
