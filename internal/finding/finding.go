// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package finding holds the scanner's result types.
package finding

import "github.com/GoNetTools/datawarden/internal/ir"

// Destination is where a sink sends data.
type Destination struct {
	Host       string `json:"host,omitempty"`
	Kind       string `json:"kind"` // third_party | first_party | log | storage | network | ipc
	FirstParty bool   `json:"first_party"`
	Region     string `json:"region,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
}

// Flow is a path from a PII source to a sink.
type Flow struct {
	DataType   string      `json:"data_type"`       // "email", "national_id"
	Class      string      `json:"class,omitempty"` // "pii", "phi", "pci", "credential"; set by the policy
	Source     ir.Pos      `json:"source"`
	Sink       ir.Pos      `json:"sink"`
	SinkRule   string      `json:"sink_rule"` // "sdk.sentry.set_user"
	Dest       Destination `json:"dest"`
	Path       []ir.Pos    `json:"path"`
	Transforms []string    `json:"transforms,omitempty"` // "masked", "sha256"
	// Guards are the consent checks that must pass for the sink to run
	// ("consent check hasConsent() at app/Track.kt:12").
	Guards     []string `json:"guards,omitempty"`
	Confidence float64  `json:"confidence"`

	// Function is the function enclosing the sink call.
	Function   string `json:"function"`
	Lang       string `json:"lang"`
	SourceDesc string `json:"source_desc"`
	SinkCall   string `json:"sink_call"`

	Fingerprint string `json:"fingerprint"`
	Violation   bool   `json:"violation"`
	Severity    string `json:"severity"` // high | medium | low
	Baselined   bool   `json:"baselined"`
	Allowed     string `json:"allowed,omitempty"` // reason when policy allows it
}

// Literal is PII committed verbatim to the repository.
type Literal struct {
	DataType    string  `json:"data_type"`
	Class       string  `json:"class,omitempty"`
	Pos         ir.Pos  `json:"pos"`
	Masked      string  `json:"masked"`
	ValueHash   string  `json:"value_hash"`
	Confidence  float64 `json:"confidence"`
	Detector    string  `json:"detector"`
	Fingerprint string  `json:"fingerprint"`
	Violation   bool    `json:"violation"`
	Severity    string  `json:"severity"`
	Baselined   bool    `json:"baselined"`
}

// IsNew reports whether the finding is a violation not in the baseline.
func (f *Flow) IsNew() bool { return f.Violation && !f.Baselined }

// IsNew reports whether the finding is a violation not in the baseline.
func (l *Literal) IsNew() bool { return l.Violation && !l.Baselined }
