// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type glVendor struct {
	Name string `json:"name"`
}

type glTool struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Vendor  glVendor `json:"vendor"`
	URL     string   `json:"url,omitempty"`
}

type glScan struct {
	Analyzer  glTool `json:"analyzer"`
	Scanner   glTool `json:"scanner"`
	Type      string `json:"type"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Status    string `json:"status"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type glLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type glVuln struct {
	ID          string         `json:"id"`
	Category    string         `json:"category"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Scanner     glScannerRef   `json:"scanner"`
	Location    glLocation     `json:"location"`
	Identifiers []glIdentifier `json:"identifiers"`
}

type glScannerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type glReport struct {
	Version         string   `json:"version"`
	Scan            glScan   `json:"scan"`
	Vulnerabilities []glVuln `json:"vulnerabilities"`
}

func glSeverity(s string) string {
	switch s {
	case "high":
		return "High"
	case "medium":
		return "Medium"
	}
	return "Low"
}

func uuidFrom(s string) string {
	h := sha256.Sum256([]byte(s))
	x := hex.EncodeToString(h[:16])
	return fmt.Sprintf("%s-%s-4%s-a%s-%s", x[0:8], x[8:12], x[13:16], x[17:20], x[20:32])
}

// GitLab renders new violations as a GitLab SAST report
// (artifacts:reports:sast), which shows up in merge request widgets.
func GitLab(w io.Writer, r *Report) error {
	r.Sort()
	const tf = "2006-01-02T15:04:05"
	tool := glTool{ID: "datawarden", Name: "datawarden", Version: r.Version, Vendor: glVendor{Name: "datawarden"}, URL: "https://github.com/GoNetTools/datawarden"}
	start := r.Started
	end, _ := time.ParseDuration(r.Duration)
	rep := glReport{
		Version: "15.0.7",
		Scan: glScan{Analyzer: tool, Scanner: tool, Type: "sast", Status: "success",
			StartTime: start.UTC().Format(tf), EndTime: start.Add(end).UTC().Format(tf)},
		Vulnerabilities: []glVuln{},
	}
	ref := glScannerRef{ID: "datawarden", Name: "datawarden"}
	for _, f := range r.Flows {
		if !f.Violation || f.Baselined {
			continue
		}
		rep.Vulnerabilities = append(rep.Vulnerabilities, glVuln{
			ID: uuidFrom(f.Fingerprint), Category: "sast",
			Name:        fmt.Sprintf("%s sent to %s", r.dtLabel(f.DataType), destLabel(f.Dest)),
			Description: r.message(f) + fmt.Sprintf(". Source: %s. Function: %s. Confidence %.2f.", f.Source, f.Function, f.Confidence),
			Severity:    glSeverity(f.Severity), Scanner: ref,
			Location:    glLocation{File: f.Sink.File, StartLine: f.Sink.Line, EndLine: f.Sink.Line},
			Identifiers: []glIdentifier{{Type: "datawarden_rule", Name: "datawarden " + f.SinkRule, Value: f.SinkRule}, {Type: "datawarden_fingerprint", Name: "fingerprint", Value: f.Fingerprint}},
		})
	}
	for _, l := range r.Literals {
		if !l.Violation || l.Baselined {
			continue
		}
		rep.Vulnerabilities = append(rep.Vulnerabilities, glVuln{
			ID: uuidFrom(l.Fingerprint), Category: "sast",
			Name:        r.dtLabel(l.DataType) + " committed to the repository",
			Description: r.literalMessage(l),
			Severity:    glSeverity(l.Severity), Scanner: ref,
			Location:    glLocation{File: l.Pos.File, StartLine: l.Pos.Line, EndLine: l.Pos.Line},
			Identifiers: []glIdentifier{{Type: "datawarden_rule", Name: "datawarden pii-literal/" + l.DataType, Value: "pii-literal/" + l.DataType}, {Type: "datawarden_fingerprint", Name: "fingerprint", Value: l.Fingerprint}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
