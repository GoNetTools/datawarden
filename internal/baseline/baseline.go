// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package baseline fingerprints findings and records accepted ones.
//
// A flow's fingerprint hashes its data type, sink rule, destination and
// enclosing function. Line numbers are deliberately left out so moving
// code around, adding lines above a sink, or reformatting does not raise
// new alerts; renaming the enclosing function or changing the destination
// does.
package baseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/GoNetTools/datawarden/internal/finding"
)

// Version of the baseline file format.
const Version = 1

// FlowFingerprint returns the refactor-stable identity of a flow.
func FlowFingerprint(f *finding.Flow) string {
	return hash("flow", f.DataType, f.SinkRule, f.Dest.Host+"|"+f.Dest.Kind, f.Function)
}

// LiteralFingerprint identifies a committed sensitive value in a file.
func LiteralFingerprint(l *finding.Literal) string {
	return hash("literal", l.DataType, l.Pos.File, l.ValueHash)
}

func hash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:12])
}

// Entry is one accepted finding. The descriptive fields are for humans
// reviewing the baseline diff; only Fingerprint is used for matching.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Kind        string `json:"kind"`
	DataType    string `json:"data_type"`
	SinkRule    string `json:"sink_rule,omitempty"`
	Dest        string `json:"dest,omitempty"`
	Function    string `json:"function,omitempty"`
	File        string `json:"file,omitempty"`
}

// Baseline is the accepted state.
type Baseline struct {
	Version   int     `json:"version"`
	Generated string  `json:"generated"`
	Commit    string  `json:"commit,omitempty"`
	Entries   []Entry `json:"entries"`

	set map[string]bool
}

// Empty returns a baseline with no entries.
func Empty() *Baseline { return &Baseline{Version: Version, set: map[string]bool{}} }

// Decode reads a baseline document.
func Decode(r io.Reader) (*Baseline, error) {
	b := Empty()
	if err := json.NewDecoder(r).Decode(b); err != nil {
		return nil, err
	}
	b.set = map[string]bool{}
	for _, e := range b.Entries {
		b.set[e.Fingerprint] = true
	}
	return b, nil
}

// Has reports whether a fingerprint is accepted.
func (b *Baseline) Has(fp string) bool { return b != nil && b.set[fp] }

// Len is the number of entries.
func (b *Baseline) Len() int {
	if b == nil {
		return 0
	}
	return len(b.Entries)
}

// Mark sets fingerprints and the Baselined flag on findings and returns the
// fingerprints of baseline entries that were not seen (fixed or moved).
func (b *Baseline) Mark(flows []*finding.Flow, lits []*finding.Literal) (unseen []string) {
	seen := map[string]bool{}
	for _, f := range flows {
		f.Fingerprint = FlowFingerprint(f)
		f.Baselined = b.Has(f.Fingerprint)
		seen[f.Fingerprint] = true
	}
	for _, l := range lits {
		l.Fingerprint = LiteralFingerprint(l)
		l.Baselined = b.Has(l.Fingerprint)
		seen[l.Fingerprint] = true
	}
	if b == nil {
		return nil
	}
	for _, e := range b.Entries {
		if !seen[e.Fingerprint] {
			unseen = append(unseen, e.Fingerprint)
		}
	}
	return unseen
}

// FromFindings builds a baseline of the current violations.
func FromFindings(flows []*finding.Flow, lits []*finding.Literal, commit string, now time.Time) *Baseline {
	b := &Baseline{Version: Version, Generated: now.UTC().Format(time.RFC3339), Commit: commit, set: map[string]bool{}}
	add := func(e Entry) {
		if b.set[e.Fingerprint] {
			return
		}
		b.set[e.Fingerprint] = true
		b.Entries = append(b.Entries, e)
	}
	for _, f := range flows {
		if !f.Violation {
			continue
		}
		fp := FlowFingerprint(f)
		dest := f.Dest.Kind
		if f.Dest.Host != "" {
			dest = f.Dest.Host + " (" + f.Dest.Kind + ")"
		}
		add(Entry{Fingerprint: fp, Kind: "flow", DataType: f.DataType, SinkRule: f.SinkRule, Dest: dest, Function: f.Function})
	}
	for _, l := range lits {
		if !l.Violation {
			continue
		}
		add(Entry{Fingerprint: LiteralFingerprint(l), Kind: "literal", DataType: l.DataType, File: l.Pos.File})
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		a, c := b.Entries[i], b.Entries[j]
		if a.Kind != c.Kind {
			return a.Kind < c.Kind
		}
		if a.Function+a.File != c.Function+c.File {
			return a.Function+a.File < c.Function+c.File
		}
		return a.Fingerprint < c.Fingerprint
	})
	return b
}

// Encode writes the baseline as stable, diff-friendly JSON.
func (b *Baseline) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// Codec reads and writes baseline documents as bytes, so the caller owns
// file access: the CLI's BaselineCodec.
type Codec struct{}

// Mark decodes data (nil or empty: no baseline), sets fingerprints and the
// Baselined flag on the findings, and returns the number of accepted
// entries and the fingerprints of entries no longer found.
func (Codec) Mark(data []byte, flows []*finding.Flow, lits []*finding.Literal) (size int, unseen []string, err error) {
	b := Empty()
	if len(bytes.TrimSpace(data)) > 0 {
		if b, err = Decode(bytes.NewReader(data)); err != nil {
			return 0, nil, err
		}
	}
	unseen = b.Mark(flows, lits)
	return b.Len(), unseen, nil
}

// Encode builds a baseline of the current violations and returns the
// document and its number of entries.
func (Codec) Encode(flows []*finding.Flow, lits []*finding.Literal, commit string, now time.Time) ([]byte, int, error) {
	b := FromFindings(flows, lits, commit, now)
	var buf bytes.Buffer
	if err := b.Encode(&buf); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), b.Len(), nil
}
