// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Package config loads .piiflow.yaml.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GoNetTools/pii-scanner/internal/lang"
)

// FileName is the default config file name at the repository root.
const FileName = ".piiflow.yaml"

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
	// FailOnLiterals makes committed PII literals violations.
	FailOnLiterals *bool `yaml:"fail_on_literals" json:"fail_on_literals"`
	// IgnoreDataTypes drops these data types entirely.
	IgnoreDataTypes []string `yaml:"ignore_data_types" json:"ignore_data_types,omitempty"`
	Allow           []Allow  `yaml:"allow" json:"allow,omitempty"`
}

// Literals configures the committed-PII literal detector.
type Literals struct {
	Enabled       *bool   `yaml:"enabled" json:"enabled"`
	MinConfidence float64 `yaml:"min_confidence" json:"min_confidence"`
}

// Config is .piiflow.yaml.
type Config struct {
	Version int `yaml:"version" json:"version"`
	// Languages restricts analysis (default: every supported language found).
	Languages []string `yaml:"languages" json:"languages,omitempty"`
	// IncludeTests analyzes test sources for flows (literals always scan them).
	IncludeTests bool `yaml:"include_tests" json:"include_tests"`
	// FirstPartyDomains turns network sinks to these hosts into first-party.
	FirstPartyDomains []string `yaml:"first_party_domains" json:"first_party_domains,omitempty"`
	// Rules are extra rule files or directories (default .piiflow/rules).
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
		Rules:         []string{".piiflow/rules"},
		Baseline:      ".piiflow/baseline.json",
		CacheDir:      ".piiflow/cache",
		MinConfidence: 0.35,
		Literals:      Literals{Enabled: &t, MinConfidence: 0.6},
		Policy: Policy{
			FailOn:         []string{"third_party", "log", "network", "storage", "ipc"},
			SafeTransforms: []string{"masked", "redacted", "encrypted", "tokenized", "anonymized"},
			MinConfidence:  0.55,
			FailOnLiterals: &t,
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
	for _, k := range c.Policy.FailOn {
		if !kinds[k] {
			return fmt.Errorf("%s: policy.fail_on: unknown destination kind %q", c.Path, k)
		}
	}
	for _, l := range c.Languages {
		if !lang.IsCode(l) {
			return fmt.Errorf("%s: languages: unsupported language %q (supported: %s)", c.Path, l, strings.Join(lang.CodeNames(), ", "))
		}
	}
	return nil
}

// Abs resolves a config-relative path against root.
func Abs(root, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, filepath.FromSlash(p))
}

// Template is written by `piiflow init`.
const Template = `# piiflow configuration. All keys are optional.
version: 1

# Languages to analyze for flows (default: all supported that are present).
# languages: [go, kotlin, java, typescript]

# Analyze test sources for flows too (literal detection always scans them).
include_tests: false

# Network sinks whose URL host matches these domains are first-party.
first_party_domains: []
#  - api.example.vn

# Extra rule files/directories; rules with the same id replace built-ins,
# and "- {id: <id>, disabled: true}" turns one off.
rules: [.piiflow/rules]

baseline: .piiflow/baseline.json
cache_dir: .piiflow/cache

literals:
  enabled: true
  min_confidence: 0.6

policy:
  # Destination kinds that count as violations.
  fail_on: [third_party, log, network, storage, ipc]
  # A flow is acceptable if one of these transforms was applied first.
  # Hashes (sha256, hashed) are left out on purpose: phone numbers and
  # CCCD numbers are low-entropy and hashes of them are reversible.
  safe_transforms: [masked, redacted, encrypted, tokenized, anonymized]
  min_confidence: 0.55
  fail_on_literals: true
  ignore_data_types: []
  allow: []
  #  - sink: sdk.sentry.set_user
  #    data_types: [email]
  #    reason: DPA with Sentry, EU data region
  #  - dest_host: api.example.vn
`

// Loader reads configuration: the CLI's ConfigLoader.
type Loader struct{}

// Load reads name from fsys (see Load).
func (Loader) Load(fsys fs.FS, name string, required bool) (*Config, error) {
	return Load(fsys, name, required)
}

// Parse decodes a configuration document (see Parse).
func (Loader) Parse(data []byte, origin string) (*Config, error) { return Parse(data, origin) }
