// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package datamap turns flows and schema hints into a personal-data
// inventory: what is collected, where it is stored, who receives it. The
// "dpia" format is a Markdown document laid out to seed a Data Protection
// Impact Assessment (GDPR art. 35) or a comparable privacy impact
// assessment under other data protection laws.
package datamap

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// Recipient is one destination of personal data.
type Recipient struct {
	Vendor     string   `json:"vendor,omitempty"`
	Host       string   `json:"host,omitempty"`
	Kind       string   `json:"kind"`
	Region     string   `json:"region,omitempty"`
	FirstParty bool     `json:"first_party"`
	DataTypes  []string `json:"data_types"`
	Sinks      []string `json:"sinks"`
	Transforms []string `json:"transforms,omitempty"`
	Flows      int      `json:"flows"`
	Violations int      `json:"violations"`
	Examples   []string `json:"examples"`
}

// Store is an entity/table/message holding personal data.
type Store struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Lang   string            `json:"lang"`
	File   string            `json:"file"`
	Fields map[string]string `json:"fields"` // field -> data type
}

// DataType is one data type with everything known about it.
type DataType struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Class      string   `json:"class"`
	Category   string   `json:"category"`
	Sensitive  bool     `json:"sensitive"`
	Sources    []string `json:"sources"`
	StoredIn   []string `json:"stored_in"`
	Recipients []string `json:"recipients"`
	Committed  int      `json:"committed_literals"`
}

// Map is the data inventory.
type Map struct {
	Generated  string          `json:"generated"`
	Commit     string          `json:"commit,omitempty"`
	DataTypes  []*DataType     `json:"data_types"`
	Recipients []*Recipient    `json:"recipients"`
	Stores     []*Store        `json:"stores"`
	Flows      []*finding.Flow `json:"flows"`

	catalog Catalog
}

// Catalog describes data types (implemented by *detect.Classifier).
type Catalog interface {
	Lookup(id string) detect.DataType
}

// Input is everything the map is built from.
type Input struct {
	Flows    []*finding.Flow
	Literals []*finding.Literal
	Schema   *detect.Schema
	Commit   string
	Now      time.Time
	Catalog  Catalog
}

// Build assembles the map.
func Build(in Input) *Map {
	flows, lits, schema, catalog := in.Flows, in.Literals, in.Schema, in.Catalog
	m := &Map{Generated: in.Now.UTC().Format(time.RFC3339), Commit: in.Commit, Flows: flows, catalog: catalog}
	dts := map[string]*DataType{}
	get := func(id string) *DataType {
		if d, ok := dts[id]; ok {
			return d
		}
		t := catalog.Lookup(id)
		d := &DataType{ID: id, Label: t.Label, Class: t.Class, Category: t.Category, Sensitive: t.Sensitive}
		dts[id] = d
		return d
	}
	recips := map[string]*Recipient{}
	for _, f := range flows {
		key := f.Dest.Kind + "|" + f.Dest.Host + "|" + f.Dest.Vendor
		r := recips[key]
		if r == nil {
			r = &Recipient{Vendor: f.Dest.Vendor, Host: f.Dest.Host, Kind: f.Dest.Kind, Region: f.Dest.Region, FirstParty: f.Dest.FirstParty}
			recips[key] = r
		}
		r.Flows++
		if f.Violation {
			r.Violations++
		}
		r.DataTypes = addUniq(r.DataTypes, f.DataType)
		r.Sinks = addUniq(r.Sinks, f.SinkRule)
		for _, x := range f.Transforms {
			r.Transforms = addUniq(r.Transforms, x)
		}
		if len(r.Examples) < 5 {
			r.Examples = addUniq(r.Examples, fmt.Sprintf("%s:%d", f.Sink.File, f.Sink.Line))
		}
		d := get(f.DataType)
		d.Recipients = addUniq(d.Recipients, recipientName(r))
		if len(d.Sources) < 6 {
			d.Sources = addUniq(d.Sources, f.SourceDesc)
		}
	}
	for _, l := range lits {
		get(l.DataType).Committed++
	}
	if schema != nil {
		stores := map[string]*Store{}
		for _, h := range schema.Hints {
			if h.Suppressed || h.Conf < 0.6 {
				continue
			}
			var decl *ir.TypeDecl
			for _, t := range schema.Types {
				if t.Name == h.Type {
					decl = t
					break
				}
			}
			if decl == nil || decl.External {
				continue
			}
			s := stores[decl.Name]
			if s == nil {
				s = &Store{Name: decl.Name, Kind: decl.Kind, Lang: decl.Lang, File: decl.Pos.File, Fields: map[string]string{}}
				stores[decl.Name] = s
			}
			s.Fields[h.Field] = h.DataType
			d := get(h.DataType)
			if persistent(decl.Kind) {
				d.StoredIn = addUniq(d.StoredIn, strings.TrimPrefix(decl.Name, "table:"))
			}
		}
		for _, s := range stores {
			m.Stores = append(m.Stores, s)
		}
		sort.Slice(m.Stores, func(i, j int) bool { return m.Stores[i].Name < m.Stores[j].Name })
	}
	for _, d := range dts {
		sort.Strings(d.Recipients)
		sort.Strings(d.StoredIn)
		m.DataTypes = append(m.DataTypes, d)
	}
	sort.Slice(m.DataTypes, func(i, j int) bool {
		if m.DataTypes[i].Sensitive != m.DataTypes[j].Sensitive {
			return m.DataTypes[i].Sensitive
		}
		return m.DataTypes[i].ID < m.DataTypes[j].ID
	})
	for _, r := range recips {
		sort.Strings(r.DataTypes)
		sort.Strings(r.Sinks)
		m.Recipients = append(m.Recipients, r)
	}
	kindRank := map[string]int{"third_party": 0, "network": 1, "ipc": 2, "log": 3, "storage": 4, "first_party": 5}
	sort.Slice(m.Recipients, func(i, j int) bool {
		a, b := m.Recipients[i], m.Recipients[j]
		if kindRank[a.Kind] != kindRank[b.Kind] {
			return kindRank[a.Kind] < kindRank[b.Kind]
		}
		return recipientName(a) < recipientName(b)
	})
	return m
}

func persistent(kind string) bool {
	return kind == "entity" || kind == "table" || kind == "proto"
}

func recipientName(r *Recipient) string {
	switch {
	case r.Vendor != "":
		return r.Vendor
	case r.Host != "":
		return r.Host
	}
	return r.Kind + " (unknown host)"
}

func addUniq(xs []string, x string) []string {
	if x == "" {
		return xs
	}
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// Write renders the map: dpia (Markdown), json, csv or mermaid.
func Write(w io.Writer, format string, m *Map) error {
	switch format {
	case "", "dpia", "markdown", "md":
		return dpia(w, m)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(m)
	case "csv":
		return writeCSV(w, m)
	case "mermaid":
		return mermaid(w, m)
	}
	return fmt.Errorf("unknown map format %q (dpia, json, csv, mermaid)", format)
}

var kindText = map[string]string{
	"third_party": "Third-party processor", "first_party": "First-party system", "log": "Logs",
	"storage": "Local/device storage", "network": "Network (host not resolved)", "ipc": "Other apps (IPC/clipboard)",
}

func dpia(w io.Writer, m *Map) error {
	var b strings.Builder
	b.WriteString("# Personal data map\n\n")
	fmt.Fprintf(&b, "Generated by datawarden on %s", m.Generated)
	if m.Commit != "" {
		fmt.Fprintf(&b, " from commit `%s`", shortSHA(m.Commit))
	}
	b.WriteString(".\n\nThis inventory is derived from static analysis of the source code. It lists the personal data the code handles, where it is persisted and which systems receive it. It is a starting point for a Data Protection Impact Assessment (GDPR art. 35) or a comparable privacy impact assessment, not a substitute for one: purposes, legal bases, retention periods and data subjects must be filled in by the product owner.\n\n")

	b.WriteString("## 1. Personal data processed\n\n| Data | Class | Category | Sensitive | Stored in | Sent to | Seen as |\n|---|---|---|---|---|---|---|\n")
	var creds []string
	for _, d := range m.DataTypes {
		if d.Class == "credential" {
			creds = append(creds, fmt.Sprintf("%s (`%s`)", d.Label, d.ID))
			continue
		}
		sens := "no"
		if d.Sensitive {
			sens = "**yes**"
		}
		seen := strings.Join(trim(d.Sources, 3), "; ")
		if d.Committed > 0 {
			seen += fmt.Sprintf("; %d value(s) committed in repo", d.Committed)
		}
		fmt.Fprintf(&b, "| %s (`%s`) | %s | %s | %s | %s | %s | %s |\n", d.Label, d.ID, orDash(d.Class), d.Category, sens, orDash(strings.Join(d.StoredIn, ", ")), orDash(strings.Join(d.Recipients, ", ")), esc(seen))
	}
	b.WriteString("\n")
	if len(creds) > 0 {
		fmt.Fprintf(&b, "Credentials are not personal data and are left out of this table; the code also handles: %s. See the JSON or CSV map for where they go.\n\n", strings.Join(creds, ", "))
	}

	b.WriteString("## 2. Recipients and transfers\n\n| Recipient | Type | Host | Data | Safeguards | Flows | Open issues |\n|---|---|---|---|---|---|---|\n")
	for _, r := range m.Recipients {
		safe := "none detected"
		if len(r.Transforms) > 0 {
			safe = strings.Join(r.Transforms, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d | %d |\n", recipientName(r), kindText[r.Kind], orDash(r.Host), strings.Join(r.DataTypes, ", "), safe, r.Flows, r.Violations)
	}
	b.WriteString("\nFor each third-party processor, record the contract/DPA, the processing region and whether the transfer is cross-border; many data protection laws require a transfer mechanism or a separate assessment for sending personal data abroad.\n\n")

	b.WriteString("## 3. Data at rest\n\n")
	if len(m.Stores) == 0 {
		b.WriteString("No entities, tables or messages with personal data fields were found.\n\n")
	} else {
		b.WriteString("| Store | Kind | Defined in | Personal data fields |\n|---|---|---|---|\n")
		for _, s := range m.Stores {
			var fields []string
			for f, dt := range s.Fields {
				fields = append(fields, fmt.Sprintf("`%s` (%s)", f, dt))
			}
			sort.Strings(fields)
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", strings.TrimPrefix(s.Name, "table:"), s.Kind, orDash(s.File), strings.Join(fields, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 4. Flows needing review\n\n")
	n := 0
	for _, f := range m.Flows {
		if !f.Violation {
			continue
		}
		if n == 0 {
			b.WriteString("| Data | Destination | Where | Status |\n|---|---|---|---|\n")
		}
		n++
		status := "new"
		if f.Baselined {
			status = "accepted (baseline)"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s:%d` in `%s` | %s |\n", f.DataType, esc(recipientLabel(f.Dest)), f.Sink.File, f.Sink.Line, f.Function, status)
	}
	if n == 0 {
		b.WriteString("No policy violations.\n")
	}
	b.WriteString("\n## 5. To complete manually\n\n| Processing activity | Purpose | Legal basis / consent | Data subjects | Retention | Owner |\n|---|---|---|---|---|---|\n")
	rows := 0
	for _, r := range m.Recipients {
		if r.Kind == "log" || r.Kind == "first_party" {
			continue
		}
		rows++
		fmt.Fprintf(&b, "| Share %s with %s | | | | | |\n", strings.Join(r.DataTypes, ", "), recipientName(r))
	}
	for _, s := range m.Stores {
		if !persistent(s.Kind) {
			continue
		}
		rows++
		fmt.Fprintf(&b, "| Store personal data in %s | | | | | |\n", strings.TrimPrefix(s.Name, "table:"))
	}
	if rows == 0 {
		b.WriteString("| (no external recipients or stores detected) | | | | | |\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func recipientLabel(d finding.Destination) string {
	if d.Vendor != "" {
		return d.Vendor
	}
	if d.Host != "" {
		return d.Host + " (" + d.Kind + ")"
	}
	return d.Kind
}

func writeCSV(w io.Writer, m *Map) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"data_type", "class", "category", "sensitive", "dest_kind", "dest_host", "vendor", "first_party", "sink_rule", "transforms", "function", "file", "line", "confidence", "violation", "baselined"})
	for _, f := range m.Flows {
		dt := m.catalog.Lookup(f.DataType)
		_ = cw.Write([]string{f.DataType, dt.Class, dt.Category, strconv.FormatBool(dt.Sensitive), f.Dest.Kind, f.Dest.Host, f.Dest.Vendor, strconv.FormatBool(f.Dest.FirstParty),
			f.SinkRule, strings.Join(f.Transforms, ";"), f.Function, f.Sink.File, strconv.Itoa(f.Sink.Line), strconv.FormatFloat(f.Confidence, 'f', 2, 64),
			strconv.FormatBool(f.Violation), strconv.FormatBool(f.Baselined)})
	}
	cw.Flush()
	return cw.Error()
}

func mermaid(w io.Writer, m *Map) error {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	id := func(prefix, s string) string {
		r := strings.NewReplacer(".", "_", "-", "_", " ", "_", "/", "_", ":", "_", "(", "", ")", "")
		return prefix + r.Replace(s)
	}
	for _, d := range m.DataTypes {
		fmt.Fprintf(&b, "  %s([\"%s\"])\n", id("d_", d.ID), d.Label)
	}
	for _, r := range m.Recipients {
		name := recipientName(r)
		fmt.Fprintf(&b, "  %s[\"%s<br/>%s\"]\n", id("r_", name+r.Kind), name, kindText[r.Kind])
		for _, dt := range r.DataTypes {
			arrow := "-->"
			if r.Violations > 0 {
				arrow = "==>"
			}
			fmt.Fprintf(&b, "  %s %s %s\n", id("d_", dt), arrow, id("r_", name+r.Kind))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func trim(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("+%d more", len(xs)-n))
	}
	return xs
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Mapper builds and renders data maps: the CLI's DataMapper.
type Mapper struct{}

// Build assembles the data map (see Build).
func (Mapper) Build(in Input) *Map { return Build(in) }

// Write renders m in format (see Write).
func (Mapper) Write(w io.Writer, format string, m *Map) error { return Write(w, format, m) }
