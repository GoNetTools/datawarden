// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"sort"
	"strings"

	"github.com/GoNetTools/pii-scanner/internal/ir"
)

// Hint is a schema-derived statement that a field holds a data type.
type Hint struct {
	DataType  string  `json:"data_type"`
	Conf      float64 `json:"confidence"`
	Transform string  `json:"transform,omitempty"`
	Via       string  `json:"via"`
	Type      string  `json:"type"`
	Field     string  `json:"field"`
	Pos       ir.Pos  `json:"pos"`
	// Suppressed means the schema explicitly says "not PII" (pii:"-").
	Suppressed bool `json:"suppressed,omitempty"`
	// Contextual hints depend on the owner type (Customer.name) and are not
	// applied to same-named fields of unknown owners.
	Contextual bool `json:"-"`
}

// FieldState is the result of a schema field lookup.
type FieldState int

const (
	FieldUnknown FieldState = iota
	FieldPII
	FieldNotPII
)

// Schema indexes schema hints from struct tags, ORM annotations, protobuf
// messages and SQL migrations.
type Schema struct {
	byTypeField map[string]map[string]Hint
	byField     map[string][]Hint
	typePII     map[string][]string
	known       map[string]bool
	Types       []*ir.TypeDecl
	Hints       []Hint
}

// Tags whose value names the stored/serialized column or key.
var nameTags = []string{"column", "gorm", "db", "bson", "json", "yaml", "xml", "protobuf", "msgpack", "mapstructure", "form", "query",
	"@Column", "@SerializedName", "@JsonProperty", "@Json", "@ColumnInfo", "@Field", "@JsonAlias", "@SerialName", "@Property"}

// Tags/annotations that explicitly mark PII.
var piiTags = []string{"pii", "pii-scanner", "@PII", "@Pii", "@PersonalData", "@Sensitive", "@SensitiveData"}

// Schemas parses schema files and builds indexes with a classifier. It is
// the production implementation of the scanner's schema dependency.
type Schemas struct{ Classifier *Classifier }

// ParseProto implements scan.SchemaParser.
func (Schemas) ParseProto(path string, src []byte) []*ir.TypeDecl { return ParseProto(path, src) }

// ParseSQL implements scan.SchemaParser.
func (Schemas) ParseSQL(path string, src []byte) []*ir.TypeDecl { return ParseSQL(path, src) }

// Build implements scan.SchemaParser.
func (s Schemas) Build(types []*ir.TypeDecl) *Schema { return BuildSchema(s.Classifier, types) }

// BuildSchema indexes type declarations.
func BuildSchema(c *Classifier, types []*ir.TypeDecl) *Schema {
	s := &Schema{byTypeField: map[string]map[string]Hint{}, byField: map[string][]Hint{}, typePII: map[string][]string{}, known: map[string]bool{}, Types: types}
	for _, t := range types {
		keys := typeKeys(t.Name)
		for _, k := range keys {
			s.known[k] = true
		}
		for _, f := range t.Fields {
			h, ok := classifyDeclField(c, t, f)
			if !ok {
				continue
			}
			s.Hints = append(s.Hints, h)
			for _, k := range keys {
				m := s.byTypeField[k]
				if m == nil {
					m = map[string]Hint{}
					s.byTypeField[k] = m
				}
				fk := strings.ToLower(f.Name)
				if old, exists := m[fk]; !exists || h.Conf > old.Conf || h.Suppressed {
					m[fk] = h
				}
			}
			if h.Contextual {
				continue
			}
			nf := normField(f.Name)
			s.byField[nf] = append(s.byField[nf], h)
			for _, tag := range []string{"column", "json", "db"} {
				if v := tagName(f.Tags, tag); v != "" && normField(v) != nf {
					s.byField[normField(v)] = append(s.byField[normField(v)], h)
				}
			}
		}
	}
	// Data types contained in each (non-external) type, including nested
	// struct fields whose type is itself PII-bearing.
	declDTs := map[*ir.TypeDecl]map[string]bool{}
	byKey := map[string][]*ir.TypeDecl{}
	for _, t := range types {
		declDTs[t] = map[string]bool{}
		for _, k := range typeKeys(t.Name) {
			byKey[k] = append(byKey[k], t)
		}
		for _, f := range t.Fields {
			if h, ok := classifyDeclField(c, t, f); ok && !h.Suppressed && h.Conf >= 0.6 {
				declDTs[t][h.DataType] = true
			}
		}
	}
	// One level of nesting through direct struct fields (a Customer with an
	// embedded Address carries the address). Collections of related models
	// (ORM associations: []Article, List<Order>) are not followed; they
	// would make every model "contain" every other model's PII.
	nested := map[*ir.TypeDecl]map[string]bool{}
	for _, t := range types {
		for _, f := range t.Fields {
			if isCollectionType(f.Type) {
				continue
			}
			for _, k := range typeKeys(f.Type) {
				for _, u := range byKey[k] {
					if u == t {
						continue
					}
					for dt := range declDTs[u] {
						if nested[t] == nil {
							nested[t] = map[string]bool{}
						}
						nested[t][dt] = true
					}
				}
			}
		}
	}
	for t, dts := range nested {
		for dt := range dts {
			declDTs[t][dt] = true
		}
	}
	for _, t := range types {
		// Values of service-like classes (repositories, view models) are not
		// "PII values" even if they have PII-named fields.
		if t.External || len(declDTs[t]) == 0 || t.Kind == "class" || t.Kind == "object" {
			continue
		}
		for _, k := range typeKeys(t.Name) {
			for dt := range declDTs[t] {
				if !contains(s.typePII[k], dt) {
					s.typePII[k] = append(s.typePII[k], dt)
				}
			}
			sort.Strings(s.typePII[k])
		}
	}
	return s
}

func classifyDeclField(c *Classifier, t *ir.TypeDecl, f ir.Field) (Hint, bool) {
	h := Hint{Type: t.Name, Field: f.Name, Pos: f.Pos}
	for _, k := range piiTags {
		v, ok := f.Tags[k]
		if !ok {
			continue
		}
		v = strings.TrimSpace(strings.Split(v, ",")[0])
		if v == "-" || strings.EqualFold(v, "false") || strings.EqualFold(v, "none") {
			h.Suppressed, h.Via = true, k+` "-"`
			return h, true
		}
		if v == "" || strings.EqualFold(v, "true") {
			if m, ok := c.Ident(f.Name); ok {
				v = m.DataType
			} else {
				v = "pii"
			}
		}
		h.DataType, h.Conf, h.Via = v, 1.0, tagVia(k, v)
		return h, true
	}
	best, bestVia := Match{}, ""
	contextual := false
	if m, ok := c.Field(t.Name, f.Name); ok {
		best, bestVia = m, "field name "+f.Name
		if _, direct := c.Ident(f.Name); !direct {
			contextual = true
		}
	}
	for _, k := range nameTags {
		v := tagName(f.Tags, k)
		if v == "" {
			continue
		}
		if m, ok := c.Ident(v); ok && m.Conf+0.05 > best.Conf {
			m.Conf += 0.05
			if m.Conf > 0.95 {
				m.Conf = 0.95
			}
			best, bestVia, contextual = m, tagVia(k, v), false
		}
	}
	if best.DataType == "" {
		return h, false
	}
	h.DataType, h.Conf, h.Transform, h.Via, h.Contextual = best.DataType, best.Conf, best.Transform, bestVia, contextual
	return h, true
}

func tagVia(k, v string) string {
	if strings.HasPrefix(k, "@") {
		return k + `("` + v + `")`
	}
	return k + `:"` + v + `"`
}

// tagName extracts the name part of a tag value: `json:"email,omitempty"`
// -> email, `gorm:"column:phone_number;size:20"` -> phone_number,
// `protobuf:"bytes,1,opt,name=email,proto3"` -> email.
func tagName(tags map[string]string, key string) string {
	v, ok := tags[key]
	if !ok {
		return ""
	}
	switch key {
	case "gorm":
		for _, part := range strings.Split(v, ";") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "column") {
				return strings.TrimSpace(kv[1])
			}
		}
		return ""
	case "protobuf":
		for _, part := range strings.Split(v, ",") {
			if strings.HasPrefix(part, "name=") {
				return part[5:]
			}
		}
		return ""
	}
	v = strings.TrimSpace(strings.Split(v, ",")[0])
	if v == "-" {
		return ""
	}
	return v
}

func normField(s string) string {
	return strings.Join(Tokenize(s), "")
}

func typeKeys(name string) []string {
	n := strings.TrimLeft(name, "*[]&?")
	n = strings.TrimSuffix(n, "?")
	if i := strings.IndexAny(n, "<["); i > 0 {
		n = n[:i]
	}
	if n == "" {
		return nil
	}
	short := n
	if i := strings.LastIndexAny(n, "./"); i >= 0 {
		short = n[i+1:]
	}
	if short == n {
		return []string{n}
	}
	return []string{n, short}
}

// Field looks up owner.field. Owner may be qualified, short, a pointer type
// or empty.
func (s *Schema) Field(owner, field string) (Hint, FieldState) {
	if s == nil {
		return Hint{}, FieldUnknown
	}
	fk := strings.ToLower(field)
	for _, k := range typeKeys(owner) {
		if m, ok := s.byTypeField[k]; ok {
			if h, ok := m[fk]; ok {
				if h.Suppressed {
					return h, FieldNotPII
				}
				return h, FieldPII
			}
		}
	}
	for _, k := range typeKeys(owner) {
		if s.known[k] {
			return Hint{}, FieldUnknown // owner known; the field carries no hint
		}
	}
	hs := s.byField[normField(field)]
	if len(hs) == 0 {
		return Hint{}, FieldUnknown
	}
	// Without a resolved owner, only trust hints that agree.
	best := hs[0]
	for _, h := range hs[1:] {
		if h.DataType != best.DataType || h.Suppressed != best.Suppressed {
			return Hint{}, FieldUnknown
		}
		if h.Conf > best.Conf {
			best = h
		}
	}
	if best.Suppressed {
		return best, FieldNotPII
	}
	best.Conf -= 0.05
	return best, FieldPII
}

// TypeDataTypes returns the data types a value of this type carries.
func (s *Schema) TypeDataTypes(typ string) []string {
	if s == nil || typ == "" {
		return nil
	}
	for _, k := range typeKeys(typ) {
		if dts, ok := s.typePII[k]; ok {
			return dts
		}
	}
	return nil
}

// KnownType reports whether the schema has field information for typ.
func (s *Schema) KnownType(typ string) bool {
	if s == nil {
		return false
	}
	for _, k := range typeKeys(typ) {
		if s.known[k] {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func isCollectionType(t string) bool {
	t = strings.TrimLeft(t, "*&")
	if strings.HasPrefix(t, "[]") || strings.HasPrefix(t, "map[") || strings.HasSuffix(t, "[]") {
		return true
	}
	if i := strings.IndexByte(t, '<'); i > 0 {
		switch lastSegment(t[:i]) {
		case "List", "MutableList", "Set", "MutableSet", "Map", "MutableMap", "Collection", "Array", "ArrayList", "HashSet", "HashMap", "Iterable", "Sequence", "Flow", "LiveData", "Observable", "Promise", "Record", "ReadonlyArray":
			return true
		}
	}
	return false
}
