// Copyright 2026 The piiflow Authors
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
		Fields: []ir.Field{{Name: "so_dien_thoai", Tags: map[string]string{"column": "so_dien_thoai"}}}}})
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
