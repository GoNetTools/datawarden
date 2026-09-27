// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	CodeFlows           []sarifCodeFlow   `json:"codeFlows,omitempty"`
	BaselineState       string            `json:"baselineState"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
	Message          *sarifText    `json:"message,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadLoc `json:"locations"`
}

type sarifThreadLoc struct {
	Location sarifLocation `json:"location"`
}

func loc(p ir.Pos, msg string) sarifLocation {
	l := sarifLocation{
		PhysicalLocation: sarifPhysical{
			ArtifactLocation: sarifArtifact{
				URI:       p.File,
				URIBaseID: "%SRCROOT%",
			},
			Region: sarifRegion{
				StartLine:   max(p.Line, 1),
				StartColumn: p.Col,
			},
		},
	}

	if msg != "" {
		l.Message = &sarifText{Text: msg}
	}
	return l
}

var securitySeverity = map[string]string{
	"high":   "8.0",
	"medium": "5.5",
	"low":    "3.0",
}

func level(sev string, baselined bool) string {
	if baselined {
		return "note"
	}
	switch sev {
	case "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

// SARIF renders violations as SARIF 2.1.0 for GitHub code scanning (and
// any other SARIF consumer). Baselined findings are included with
// baselineState "unchanged" and level "note".
func SARIF(w io.Writer, r *Report) error {
	r.Sort()
	ruleMeta := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Flows {
		if !f.Violation {
			continue
		}
		id := "pii-flow/" + f.SinkRule
		if _, ok := ruleMeta[id]; !ok {
			ruleMeta[id] = flowRule(r, id, f)
		}
		var steps []sarifThreadLoc
		for i, p := range f.Path {
			msg := ""
			switch i {
			case 0:
				msg = "source: " + f.SourceDesc
			case len(f.Path) - 1:
				msg = "sink: " + f.SinkCall
			}
			steps = append(steps, sarifThreadLoc{Location: loc(p, msg)})
		}
		state := "new"
		if f.Baselined {
			state = "unchanged"
		}
		results = append(results, sarifResult{
			RuleID:              id,
			Level:               level(f.Severity, f.Baselined),
			Message:             sarifText{Text: r.message(f)},
			Locations:           []sarifLocation{loc(f.Sink, "")},
			PartialFingerprints: map[string]string{"datawarden/v1": f.Fingerprint},
			CodeFlows:           []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: steps}}}},
			BaselineState:       state,
			Properties: map[string]any{
				"data_type":         f.DataType,
				"destination":       f.Dest,
				"confidence":        f.Confidence,
				"transforms":        f.Transforms,
				"function":          f.Function,
				"source":            f.Source.String(),
				"security-severity": securitySeverity[f.Severity],
			},
		})
	}
	for _, l := range r.Literals {
		if !l.Violation {
			continue
		}
		id := "pii-literal/" + l.DataType
		if _, ok := ruleMeta[id]; !ok {
			dt := r.dataType(l.DataType)
			ruleMeta[id] = sarifRule{
				ID: id, Name: "CommittedSensitiveValue" + camel(l.DataType),
				ShortDescription: sarifText{
					Text: dt.Label + " committed to the repository",
				},
				FullDescription: sarifText{
					Text: "A value that validates as " + strings.ToLower(dt.Label) + " is stored in the repository. Replace real personal data and live secrets in fixtures and samples with synthetic values.",
				},
				Help: sarifText{
					Text: "Replace the value with synthetic test data (for card and ID numbers, generate values that fail validation or use documented test ranges; for secrets, revoke the key and load it from a secret store). If it is intentional, accept it with `datawarden baseline`.",
				},
				DefaultConfiguration: map[string]any{"level": level(l.Severity, false)},
				Properties: map[string]any{
					"tags":              []string{"security", "privacy", classTag(l.Class)},
					"security-severity": securitySeverity[l.Severity],
					"precision":         "high",
				},
			}
		}
		state := "new"
		if l.Baselined {
			state = "unchanged"
		}
		results = append(results, sarifResult{
			RuleID:    id,
			Level:     level(l.Severity, l.Baselined),
			Message:   sarifText{Text: r.literalMessage(l)},
			Locations: []sarifLocation{loc(l.Pos, "")},
			PartialFingerprints: map[string]string{
				"datawarden/v1": l.Fingerprint,
			},
			BaselineState: state,
			Properties: map[string]any{
				"data_type":         l.DataType,
				"confidence":        l.Confidence,
				"detector":          l.Detector,
				"security-severity": securitySeverity[l.Severity],
			},
		})
	}
	ids := slices.Sorted(maps.Keys(ruleMeta))
	driver := sarifDriver{
		Name:           r.Tool,
		Version:        r.Version,
		InformationURI: "https://github.com/GoNetTools/datawarden",
	}
	for _, id := range ids {
		driver.Rules = append(driver.Rules, ruleMeta[id])
	}
	if driver.Rules == nil {
		driver.Rules = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}
	out := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:       sarifTool{Driver: driver},
			Results:    results,
			Properties: map[string]any{"mode": r.Mode, "diff_base": r.DiffBase},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func flowRule(r *Report, id string, f *finding.Flow) sarifRule {
	desc := "Personal data reaches " + destLabel(f.Dest)
	full := desc + "."
	if r.Rules != nil {
		if rule := r.Rules.ByID(f.SinkRule); rule != nil {
			if rule.Description != "" {
				full += " " + rule.Description
			}
			if len(rule.Call) > 0 {
				full += " Sink: " + strings.Join(rule.Call, ", ") + "."
			}
		}
	}
	return sarifRule{
		ID: id, Name: "SensitiveDataFlow" + camel(f.SinkRule),
		ShortDescription:     sarifText{Text: desc},
		FullDescription:      sarifText{Text: full},
		Help:                 sarifText{Text: "Remove the sensitive data from this call, mask or tokenize it first, or record the processing as accepted (policy.allow in .datawarden.yaml, or `datawarden baseline`)."},
		DefaultConfiguration: map[string]any{"level": level(f.Severity, false)},
		Properties:           map[string]any{"tags": []string{"security", "privacy", classTag(f.Class), f.Dest.Kind}, "security-severity": securitySeverity[f.Severity], "precision": "medium"},
	}
}

func camel(s string) string {
	var b strings.Builder
	up := true
	for _, r := range s {
		if r == '.' || r == '_' || r == '-' || r == '/' {
			up = true
			continue
		}
		if up {
			b.WriteString(strings.ToUpper(string(r)))
			up = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// classTag is the SARIF tag for a data class; findings from before the
// policy set classes are personal data.
func classTag(class string) string {
	if class == "" {
		return "pii"
	}
	return class
}
