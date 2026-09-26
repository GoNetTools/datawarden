// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package flowgraph

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

func at(line int) ir.Pos { return ir.Pos{File: "app/Repo.kt", Line: line} }

func flows() []*finding.Flow {
	return []*finding.Flow{{
		DataType: "email", SourceDesc: `identifier "email"`, Source: at(2), Sink: at(9), Severity: "medium",
		SinkRule: "log.android.logcat", SinkCall: "android.util.Log.d", Dest: finding.Destination{Kind: "log", Host: "logcat"},
		Function: "com.acme.Repo.save",
		Calls: []finding.CallStep{
			{Function: "com.acme.Ui.submit", Pos: at(2)},
			{Function: "com.acme.Repo.save", Pos: at(9), Depth: 1},
			{Function: "com.acme.Ui.submit", Pos: at(3)}, // back again: a cycle to break
		},
		CalledBy: []string{"com.acme.Ui.onClick"},
	}, {
		DataType: "phone", SourceDesc: `identifier "phone"`, Source: at(4), Sink: at(5), Severity: "high",
		SinkRule: "sdk.sentry.set_user", SinkCall: "io.sentry.Sentry.setUser", Dest: finding.Destination{Kind: "third_party", Vendor: "Sentry"},
		Function: "com.acme.Ui.submit",
	}, {
		// Same source and function as the first: merged.
		DataType: "email", SourceDesc: `identifier "email"`, Source: at(6), Sink: at(9), Severity: "medium",
		SinkRule: "log.android.logcat", SinkCall: "android.util.Log.d", Dest: finding.Destination{Kind: "log", Host: "logcat"},
		Function: "com.acme.Repo.save",
		Calls:    []finding.CallStep{{Function: "com.acme.Ui.submit", Pos: at(6)}, {Function: "com.acme.Repo.save", Pos: at(9), Depth: 1}},
	}}
}

func TestBuild(t *testing.T) {
	g := Build(flows())
	kinds := map[Kind]int{}
	for _, n := range g.Nodes {
		kinds[n.Kind]++
	}
	// Sources: email, phone; functions: submit, save; caller: onClick;
	// sinks: Log.d, Sentry.setUser.
	if kinds[Source] != 2 || kinds[Function] != 2 || kinds[Caller] != 1 || kinds[Sink] != 2 || g.Flows != 3 {
		t.Errorf("nodes: %v", kinds)
	}
	var calls, data int
	for _, e := range g.Edges {
		if e.Calls {
			calls++
		} else {
			data++
		}
	}
	if calls != 1 || data != 7 {
		t.Errorf("edges: %d calls, %d data", calls, data)
	}
	if shortFunc("com.acme.Repo.save") != "Repo.save" || shortFunc("save") != "save" || short("a/b/c.kt:3") != "c.kt:3" {
		t.Error("labels")
	}
}

func TestRender(t *testing.T) {
	for _, format := range Formats {
		var b bytes.Buffer
		if err := (Renderer{}).Render(&b, format, flows()); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		out := b.String()
		for _, want := range []string{"Repo.save", "Log.d → logcat", "Sentry"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q:\n%s", format, want, out)
			}
		}
		if format == "svg" {
			if err := xml.Unmarshal(b.Bytes(), new(struct{})); err != nil {
				t.Errorf("svg is not well-formed XML: %v", err)
			}
			if !strings.Contains(out, `class="edge calls"`) || !strings.Contains(out, "prefers-color-scheme: dark") || !strings.Contains(out, "third party") {
				t.Errorf("svg:\n%s", out)
			}
		}
	}
	if err := (Renderer{}).Render(&bytes.Buffer{}, "png", nil); err == nil {
		t.Error("unknown format accepted")
	}
	var b bytes.Buffer
	if err := SVG(&b, Build(nil)); err != nil || !strings.Contains(b.String(), "No flows to draw.") {
		t.Errorf("empty graph: %v", err)
	}
}
