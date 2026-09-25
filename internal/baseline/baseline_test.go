// Copyright 2026 The pii-scanner Authors
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

func TestCodec(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	flows := []*finding.Flow{{DataType: "email", SinkRule: "log.go.stdlib", Function: "p.f", Violation: true, Sink: ir.Pos{File: "a.go", Line: 3}}}
	lits := []*finding.Literal{{DataType: "phone", Pos: ir.Pos{File: "s.csv", Line: 2}, ValueHash: "h", Violation: true}}
	var c Codec
	data, n, err := c.Encode(flows, lits, "abc", now)
	if err != nil || n != 2 || !strings.Contains(string(data), `"commit": "abc"`) {
		t.Fatalf("Encode: %d %v\n%s", n, err, data)
	}

	fresh := []*finding.Flow{{DataType: "email", SinkRule: "log.go.stdlib", Function: "p.f", Violation: true, Sink: ir.Pos{File: "a.go", Line: 30}}}
	size, unseen, err := c.Mark(data, fresh, nil)
	if err != nil || size != 2 || len(unseen) != 1 || !fresh[0].Baselined || fresh[0].Fingerprint == "" {
		t.Errorf("Mark: size=%d unseen=%v err=%v flow=%+v", size, unseen, err, fresh[0])
	}
	for _, empty := range [][]byte{nil, []byte("  \n")} {
		f := []*finding.Flow{{DataType: "email", Violation: true}}
		if size, _, err := c.Mark(empty, f, nil); err != nil || size != 0 || f[0].Baselined || f[0].Fingerprint == "" {
			t.Errorf("empty baseline: %d %v %+v", size, err, f[0])
		}
	}
	if _, _, err := c.Mark([]byte("not json"), nil, nil); err == nil {
		t.Error("corrupt baseline accepted")
	}
	var nilBaseline *Baseline
	if nilBaseline.Len() != 0 || nilBaseline.Has("x") {
		t.Error("nil baseline")
	}
}
