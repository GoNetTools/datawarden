// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package config loads .datawarden.yaml.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GoNetTools/datawarden/internal/lang"
)

// FileName is the default config file name at the repository root.
const FileName = ".datawarden.yaml"

// Allow suppresses matching flows as accepted by policy.
type Allow struct {
	Sink      string   `yaml:"sink,omitempty" json:"sink,omitempty"`
	DataTypes []string `yaml:"data_types,omitempty" json:"data_types,omitempty"`
	DestHost  string   `yaml:"dest_host,omitempty" json:"dest_host,omitempty"`
	DestKinds []string `yaml:"dest_kinds,omitempty" json:"dest_kinds,omitempty"`
	Path      string   `yaml:"path,omitempty" json:"path,omitempty"` // glob on the sink file
	Reason    string   `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// Policy decides which flows are violations.
type Policy struct {
	// FailOn lists destination kinds whose flows are violations.
	FailOn []string `yaml:"fail_on" json:"fail_on"`
	// SafeTransforms make a flow acceptable when any of them was applied.
	SafeTransforms []string `yaml:"safe_transforms" json:"safe_transforms"`
	// MinConfidence is the minimum confidence for a flow to be a violation.
	MinConfidence float64 `yaml:"min_confidence" json:"min_confidence"`
	// FailOnLiterals makes committed sensitive values violations.
	FailOnLiterals *bool `yaml:"fail_on_literals" json:"fail_on_literals"`
	// IgnoreDataTypes drops these data types entirely.
	IgnoreDataTypes []string `yaml:"ignore_data_types" json:"ignore_data_types,omitempty"`
	// IgnoreClasses drops every data type of these classes (pii, phi,
	// pci, credential).
	IgnoreClasses []string `yaml:"ignore_classes" json:"ignore_classes,omitempty"`
	// Classes override fail_on and safe_transforms for one class of data:
	// hashing a password is the right thing to do, hashing a phone number
	// is not.
	Classes map[string]ClassPolicy `yaml:"classes" json:"classes,omitempty"`
	Allow   []Allow                `yaml:"allow" json:"allow,omitempty"`
	// ConsentGuarded lists destination kinds whose flows are acceptable
	// when they run only after a consent check passed (the flow's
	// guards): analytics sent once the user opted in.
	ConsentGuarded []string `yaml:"consent_guarded" json:"consent_guarded,omitempty"`
}

// ClassPolicy overrides the policy for one class of data. Empty fields
// keep the general policy.
type ClassPolicy struct {
	FailOn         []string `yaml:"fail_on" json:"fail_on,omitempty"`
	SafeTransforms []string `yaml:"safe_transforms" json:"safe_transforms,omitempty"`
	ConsentGuarded []string `yaml:"consent_guarded" json:"consent_guarded,omitempty"`
}

// Literals configures the committed-value (literal) detector.
type Literals struct {
	Enabled       *bool   `yaml:"enabled" json:"enabled"`
	MinConfidence float64 `yaml:"min_confidence" json:"min_confidence"`
}

// Config is .datawarden.yaml.
type Config struct {
	Version int `yaml:"version" json:"version"`
	// Languages restricts analysis (default: every supported language found).
	Languages []string `yaml:"languages" json:"languages,omitempty"`
	// IncludeTests analyzes test sources for flows (literals always scan them).
	IncludeTests bool `yaml:"include_tests" json:"include_tests"`
	// FirstPartyDomains turns network sinks to these hosts into first-party.
	FirstPartyDomains []string `yaml:"first_party_domains" json:"first_party_domains,omitempty"`
	// Rules are extra rule files or directories (default .datawarden/rules).
	Rules    []string `yaml:"rules" json:"rules,omitempty"`
	Baseline string   `yaml:"baseline" json:"baseline"`
	CacheDir string   `yaml:"cache_dir" json:"cache_dir"`
	// MinConfidence drops flows below this confidence from all output.
	MinConfidence float64  `yaml:"min_confidence" json:"min_confidence"`
	Literals      Literals `yaml:"literals" json:"literals"`
	Policy        Policy   `yaml:"policy" json:"policy"`
	// Go build flags / tags passed to go/packages.
	GoBuildTags []string `yaml:"go_build_tags" json:"go_build_tags,omitempty"`

	Path string `yaml:"-" json:"-"`
}

// Default returns the built-in configuration.
func Default() *Config {
	t := true
	return &Config{
		Version:       1,
		Rules:         []string{".datawarden/rules"},
		Baseline:      ".datawarden/baseline.json",
		CacheDir:      ".datawarden/cache",
		MinConfidence: 0.35,
		Literals:      Literals{Enabled: &t, MinConfidence: 0.6},
		Policy: Policy{
			FailOn:         []string{"third_party", "log", "network", "storage", "ipc"},
			SafeTransforms: []string{"masked", "redacted", "encrypted", "tokenized", "anonymized", "pii-checked"},
			MinConfidence:  0.55,
			FailOnLiterals: &t,
			Classes: map[string]ClassPolicy{
				// Credentials exist to be sent to the services they unlock, so
				// network calls are not violations; logs, analytics and
				// storage are. Hashing a password is the point of hashing.
				"credential": {
					FailOn:         []string{"third_party", "log", "storage", "ipc"},
					SafeTransforms: []string{"masked", "redacted", "encrypted", "tokenized", "pii-checked", "hashed", "sha256", "sha512"},
				},
			},
		},
	}
}

// Load reads name from fsys on top of the defaults. A missing file is an
// error only when required (an explicit --config).
func Load(fsys fs.FS, name string, required bool) (*Config, error) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			return Default(), nil
		}
		return nil, err
	}
	return Parse(b, name)
}

// Parse decodes a config document on top of the defaults.
func Parse(data []byte, origin string) (*Config, error) {
	c := Default()
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	c.Path = origin
	if c.Literals.Enabled == nil {
		t := true
		c.Literals.Enabled = &t
	}
	if c.Policy.FailOnLiterals == nil {
		t := true
		c.Policy.FailOnLiterals = &t
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	kinds := map[string]bool{"third_party": true, "first_party": true, "log": true, "storage": true, "network": true, "ipc": true}
	check := func(key string, ks []string) error {
		for _, k := range ks {
			if !kinds[k] {
				return fmt.Errorf("%s: %s: unknown destination kind %q", c.Path, key, k)
			}
		}
		return nil
	}
	if err := check("policy.fail_on", c.Policy.FailOn); err != nil {
		return err
	}
	if err := check("policy.consent_guarded", c.Policy.ConsentGuarded); err != nil {
		return err
	}
	for _, class := range slices.Sorted(maps.Keys(c.Policy.Classes)) {
		cp := c.Policy.Classes[class]
		if err := check("policy.classes."+class+".fail_on", cp.FailOn); err != nil {
			return err
		}
		if err := check("policy.classes."+class+".consent_guarded", cp.ConsentGuarded); err != nil {
			return err
		}
	}
	for _, l := range c.Languages {
		if !lang.IsCode(l) {
			return fmt.Errorf("%s: languages: unsupported language %q (supported: %s)", c.Path, l, strings.Join(lang.CodeNames(), ", "))
		}
	}
	return nil
}

// Template is written by `datawarden init`.
const Template = `# datawarden configuration. All keys are optional.
version: 1

# Languages to analyze for flows (default: all supported that are present).
# languages: [go, kotlin, java, typescript]

# Analyze test sources for flows too (literal detection always scans them).
include_tests: false

# Network sinks whose URL host matches these domains are first-party.
first_party_domains: []
#  - api.example.com

# Extra rule files/directories; rules with the same id replace built-ins,
# and "- {id: <id>, disabled: true}" turns one off.
rules: [.datawarden/rules]

baseline: .datawarden/baseline.json
cache_dir: .datawarden/cache

literals:
  enabled: true
  min_confidence: 0.6

policy:
  # Destination kinds that count as violations.
  fail_on: [third_party, log, network, storage, ipc]
  # A flow is acceptable if one of these transforms was applied first.
  # Hashes (sha256, hashed) are left out on purpose: phone numbers and
  # national ID numbers are low-entropy and hashes of them are reversible.
  # pii-checked: a PII detector found none (if (!containsPii(msg)) log(msg)).
  safe_transforms: [masked, redacted, encrypted, tokenized, anonymized, pii-checked]
  min_confidence: 0.55
  fail_on_literals: true
  ignore_data_types: []
  # Drop whole classes of data: pii, phi (health), pci (cardholder data),
  # credential (passwords, tokens, keys).
  ignore_classes: []
  # Per-class overrides of fail_on and safe_transforms. Credentials are
  # meant to be sent to the services they unlock (network), and a hashed
  # password is fine; a hashed phone number is not.
  classes:
    credential:
      fail_on: [third_party, log, storage, ipc]
      safe_transforms: [masked, redacted, encrypted, tokenized, pii-checked, hashed, sha256, sha512]
  # Destination kinds whose flows are acceptable when they run only after
  # a consent check passed (if (consents.hasConsent()) analytics.track(...)).
  # Findings show the check either way.
  consent_guarded: []
  #  - third_party
  allow: []
  #  - sink: sdk.sentry.set_user
  #    data_types: [email]
  #    reason: DPA with Sentry, EU data region
  #  - dest_host: api.example.com
`

// Loader reads configuration: the CLI's ConfigLoader.
type Loader struct{}

// Load reads name from fsys (see Load).
func (Loader) Load(fsys fs.FS, name string, required bool) (*Config, error) {
	return Load(fsys, name, required)
}

// Parse decodes a configuration document (see Parse).
func (Loader) Parse(data []byte, origin string) (*Config, error) { return Parse(data, origin) }
