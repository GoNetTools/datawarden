// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package datamap

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/detect"
	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

func TestBuildUsesInjectedClockAndCatalog(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	schema := detect.BuildSchema(names, []*ir.TypeDecl{{Name: "table:customers", Kind: "table", Pos: ir.Pos{File: "m.sql"},
		Fields: []ir.Field{{Name: "phone_number", Tags: map[string]string{"column": "phone_number"}}}}})
	m := Build(Input{
		Flows:   []*finding.Flow{{DataType: "phone", SinkRule: "sdk.x", Dest: finding.Destination{Kind: "third_party", Vendor: "Sentry", Host: "sentry.io"}, Violation: true}},
		Schema:  schema,
		Now:     time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		Catalog: names,
	})
	if m.Generated != "2026-09-24T00:00:00Z" || len(m.Stores) != 1 || len(m.Recipients) != 1 || m.DataTypes[0].Label != "Phone number" {
		t.Errorf("map: %+v", m)
	}
	var b bytes.Buffer
	if err := Write(&b, "dpia", m); err != nil || !strings.Contains(b.String(), "| Sentry | Third-party processor | sentry.io | phone |") {
		t.Errorf("dpia: %v\n%s", err, b.String())
	}
}

func TestFormats(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	var mp Mapper
	m := mp.Build(Input{
		Flows: []*finding.Flow{
			{DataType: "email", SinkRule: "log.go.stdlib", Dest: finding.Destination{Kind: "log", Host: "stderr"}, Violation: true, Function: "p.f", Sink: ir.Pos{File: "a.go", Line: 3}},
			{DataType: "phone", SinkRule: "storage.go.sql", Dest: finding.Destination{Kind: "first_party", Host: "database", FirstParty: true}, Function: "p.g", Sink: ir.Pos{File: "a.go", Line: 9}},
		},
		Literals: []*finding.Literal{{DataType: "vn_cccd", Pos: ir.Pos{File: "seed.csv", Line: 2}, Violation: true}},
		Now:      time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		Catalog:  names,
	})
	for format, want := range map[string]string{
		"":        "Recipients",
		"md":      "Recipients",
		"json":    `"generated": "2026-09-24T00:00:00Z"`,
		"csv":     "data_type,class,category",
		"mermaid": "flowchart",
	} {
		var b bytes.Buffer
		if err := mp.Write(&b, format, m); err != nil || !strings.Contains(b.String(), want) {
			t.Errorf("%q: %v, lacks %q:\n%s", format, err, want, b.String())
		}
	}
	if err := mp.Write(&bytes.Buffer{}, "xml", m); err == nil {
		t.Error("unknown format accepted")
	}
}

// The DPIA's personal-data table leaves credentials out and names them
// below it.
func TestDPIASeparatesCredentials(t *testing.T) {
	names := detect.NewClassifier(detect.DefaultTaxonomy())
	m := Build(Input{
		Flows: []*finding.Flow{
			{DataType: "email", SinkRule: "log.go.stdlib", Dest: finding.Destination{Kind: "log", Host: "stderr"}, Violation: true},
			{DataType: "access_token", SinkRule: "log.go.stdlib", Dest: finding.Destination{Kind: "log", Host: "stderr"}, Violation: true},
		},
		Catalog: names,
	})
	var b bytes.Buffer
	if err := Write(&b, "dpia", m); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "| Email address (`email`) | pii |") || strings.Contains(out, "| Access token") ||
		!strings.Contains(out, "the code also handles: Access token (`access_token`)") {
		t.Errorf("dpia:\n%s", out)
	}
}
