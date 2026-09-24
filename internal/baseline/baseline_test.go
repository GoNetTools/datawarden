// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/GoNetTools/pii-scanner/internal/finding"
	"github.com/GoNetTools/pii-scanner/internal/ir"
)

func TestFingerprintIgnoresLines(t *testing.T) {
	a := &finding.Flow{DataType: "phone", SinkRule: "log.android.logcat", Dest: finding.Destination{Host: "logcat", Kind: "log"}, Function: "com.acme.Repo.save",
		Source: ir.Pos{File: "a.kt", Line: 10}, Sink: ir.Pos{File: "a.kt", Line: 12}}
	b := *a
	b.Source.Line, b.Sink.Line, b.Sink.File = 40, 42, "b.kt"
	if FlowFingerprint(a) != FlowFingerprint(&b) {
		t.Error("fingerprint changed when only positions changed")
	}
	c := *a
	c.Function = "com.acme.Repo.persist"
	if FlowFingerprint(a) == FlowFingerprint(&c) {
		t.Error("fingerprint should include the enclosing function")
	}
}

func TestRoundTrip(t *testing.T) {
	flows := []*finding.Flow{{DataType: "email", SinkRule: "r", Dest: finding.Destination{Kind: "log"}, Function: "f", Violation: true},
		{DataType: "email", SinkRule: "r2", Dest: finding.Destination{Kind: "first_party"}, Function: "f"}}
	lits := []*finding.Literal{{DataType: "phone", Pos: ir.Pos{File: "x.json", Line: 3}, ValueHash: "abc", Violation: true}}
	b := FromFindings(flows, lits, "deadbeef", time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC))
	if b.Len() != 2 {
		t.Fatalf("entries = %d, want 2 (non-violations excluded)", b.Len())
	}
	var buf bytes.Buffer
	if err := b.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"generated": "2026-09-24T00:00:00Z"`) {
		t.Errorf("clock not used: %s", buf.String())
	}
	l, err := Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	unseen := l.Mark(flows, lits)
	if !flows[0].Baselined || !lits[0].Baselined || flows[1].Baselined || len(unseen) != 0 {
		t.Errorf("mark: %+v %+v unseen=%v", flows[0], lits[0], unseen)
	}
}
