// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Class is a class of sensitive data: personal data, health information,
// cardholder data, credentials, or whatever a taxonomy defines.
type Class struct {
	ID          string `json:"id" yaml:"id"`
	Label       string `json:"label" yaml:"label"`
	Description string `json:"description,omitempty" yaml:"description"`
	// Severity "high" raises the severity of every finding of the class.
	Severity string `json:"severity,omitempty" yaml:"severity"`
}

// DataType describes one kind of sensitive data.
type DataType struct {
	ID    string `json:"id" yaml:"id"`
	Label string `json:"label" yaml:"label"`
	// Class is the id of the data type's class (pii, phi, pci, credential).
	Class string `json:"class" yaml:"class"`
	// Category groups types for the data map: contact, identity, financial,
	// location, device, demographic, health, biometric, online, secret.
	Category string `json:"category" yaml:"category"`
	// Sensitive marks special-category data (GDPR art. 9 and similar
	// "sensitive personal data" definitions: health, biometrics,
	// location, financial/bank data, ethnicity, religion...).
	Sensitive bool `json:"sensitive" yaml:"sensitive"`
	// Severity "high" raises the severity of findings of this type
	// (identity documents).
	Severity string `json:"severity,omitempty" yaml:"severity"`
	// Patterns are space-separated token sequences matched against
	// tokenized identifiers.
	Patterns []string `json:"patterns,omitempty" yaml:"patterns"`
	// Weak patterns are ambiguous abbreviations; matches score lower.
	Weak []string `json:"weak,omitempty" yaml:"weak"`
	// Exclude lists tokens that, when present anywhere in the identifier,
	// mean this is not the data type (e.g. "remote" in remoteAddress).
	Exclude []string `json:"exclude,omitempty" yaml:"exclude"`
	// Values recognise committed values of the type by their shape
	// (a cloud access key, a private key block).
	Values []ValuePattern `json:"values,omitempty" yaml:"values"`
}

// ValuePattern recognises committed values of a data type.
type ValuePattern struct {
	// Name identifies the detector in findings ("aws-access-key-id").
	Name string `json:"name" yaml:"name"`
	// Regex matches the value. The first capture group, if any, is the
	// value itself; otherwise the whole match is.
	Regex      string  `json:"regex" yaml:"regex"`
	Confidence float64 `json:"confidence" yaml:"confidence"`
	// Keywords are substrings one of which a line must contain before the
	// regex runs (case-sensitive). They keep scanning fast.
	Keywords []string `json:"keywords,omitempty" yaml:"keywords"`
	// MinEntropy is the minimum Shannon entropy, in bits per character,
	// of the value; it rules out placeholders such as "sk_live_xxxxxxxx".
	MinEntropy float64 `json:"min_entropy,omitempty" yaml:"min_entropy"`
}

// Taxonomy is a set of classes and the data types in them.
type Taxonomy struct {
	Classes []Class    `yaml:"classes"`
	Types   []DataType `yaml:"data_types"`
}

//go:embed builtin/datatypes.yaml
var builtinTaxonomy []byte

// ParseTaxonomy decodes and validates a taxonomy document. Unknown keys
// are errors.
func ParseTaxonomy(b []byte) (Taxonomy, error) {
	var t Taxonomy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return Taxonomy{}, fmt.Errorf("taxonomy: %w", err)
	}
	if err := t.Validate(); err != nil {
		return Taxonomy{}, fmt.Errorf("taxonomy: %w", err)
	}
	return t, nil
}

// Validate checks that ids are unique, every type names a declared class,
// and value patterns compile.
func (t Taxonomy) Validate() error {
	var errs []error
	classes := map[string]bool{}
	for _, c := range t.Classes {
		switch {
		case c.ID == "" || c.Label == "":
			errs = append(errs, fmt.Errorf("class %q needs an id and a label", c.ID))
		case classes[c.ID]:
			errs = append(errs, fmt.Errorf("class %s is declared twice", c.ID))
		}
		if c.Severity != "" && c.Severity != "high" {
			errs = append(errs, fmt.Errorf("class %s: severity must be empty or high", c.ID))
		}
		classes[c.ID] = true
	}
	types := map[string]bool{}
	for _, d := range t.Types {
		where := "data type " + d.ID
		switch {
		case d.ID == "" || d.Label == "" || d.Category == "":
			errs = append(errs, fmt.Errorf("%s needs an id, a label and a category", where))
		case types[d.ID]:
			errs = append(errs, fmt.Errorf("%s is declared twice", where))
		}
		types[d.ID] = true
		if !classes[d.Class] {
			errs = append(errs, fmt.Errorf("%s: class %q is not declared", where, d.Class))
		}
		if d.Severity != "" && d.Severity != "high" {
			errs = append(errs, fmt.Errorf("%s: severity must be empty or high", where))
		}
		if len(d.Patterns)+len(d.Weak)+len(d.Values) == 0 {
			errs = append(errs, fmt.Errorf("%s needs patterns, weak patterns or values", where))
		}
		for _, p := range append(append([]string(nil), d.Patterns...), d.Weak...) {
			if strings.TrimSpace(p) == "" || p != strings.ToLower(p) {
				errs = append(errs, fmt.Errorf("%s: pattern %q must be lower-case words", where, p))
			}
		}
		for _, v := range d.Values {
			if v.Name == "" || v.Confidence <= 0 || v.Confidence > 1 {
				errs = append(errs, fmt.Errorf("%s: value pattern %q needs a name and a confidence in (0, 1]", where, v.Name))
			}
			if re, err := regexp.Compile(v.Regex); err != nil || v.Regex == "" {
				errs = append(errs, fmt.Errorf("%s: value pattern %s: bad regex: %v", where, v.Name, err))
			} else if re.NumSubexp() > 1 {
				errs = append(errs, fmt.Errorf("%s: value pattern %s: use (?:...) groups; only the value may be captured", where, v.Name))
			}
			if len(v.Keywords) == 0 {
				errs = append(errs, fmt.Errorf("%s: value pattern %s needs keywords (substrings every match contains)", where, v.Name))
			}
			if v.MinEntropy < 0 || v.MinEntropy > 8 {
				errs = append(errs, fmt.Errorf("%s: value pattern %s: min_entropy must be in [0, 8]", where, v.Name))
			}
		}
	}
	return errors.Join(errs...)
}

// BuiltinTaxonomy returns the embedded taxonomy
// (internal/detect/builtin/datatypes.yaml).
func BuiltinTaxonomy() Taxonomy {
	t, err := ParseTaxonomy(builtinTaxonomy)
	if err != nil {
		panic(err) // the embedded file is checked by TestBuiltinTaxonomy
	}
	return t
}

// DefaultTaxonomy returns a copy of the built-in data types. Patterns are
// English identifier words.
func DefaultTaxonomy() []DataType { return BuiltinTaxonomy().Types }

// DefaultClasses returns the built-in classes.
func DefaultClasses() []Class { return BuiltinTaxonomy().Classes }
