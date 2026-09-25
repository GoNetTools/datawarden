// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// The secrets below are assembled at run time so that no complete
// credential-shaped string is committed (push protection, secret scanners).
func join(parts ...string) string { return strings.Join(parts, "") }

func TestCredentialNames(t *testing.T) {
	c := NewClassifier(DefaultTaxonomy())
	for name, want := range map[string]string{
		"password":              "password",
		"newPassword":           "password",
		"user_passwd":           "password",
		"apiKey":                "api_key",
		"stripeApiKey":          "api_key",
		"X-Api-Key":             "api_key",
		"accessToken":           "access_token",
		"refresh_token":         "access_token",
		"bearerToken":           "access_token",
		"clientSecret":          "secret_key",
		"AWS_SECRET_ACCESS_KEY": "secret_key",
		"privateKey":            "private_key",
		"sessionId":             "session_token",
		"patientMrn":            "medical_record_number",
		"medicalRecordNumber":   "medical_record_number",
	} {
		m, ok := c.Ident(name)
		if !ok || m.DataType != want {
			t.Errorf("%s: got %+v %v, want %s", name, m, ok, want)
		}
		if ok && c.Lookup(m.DataType).Class == "" {
			t.Errorf("%s: %s has no class", name, m.DataType)
		}
	}
	for _, name := range []string{
		"passwordPolicy", "passwordResetUrl", "forgotPassword", "passwordEncoder", "isPasswordVisible", "passwordLength",
		"apiKeyHeader", "apiKeyName", "accessTokenExpiry", "accessTokenUrl", "secretName", "secretArn", "privateKeyPath",
		"sessionTimeout", "nextPageToken", "csrfToken", "tokenizer", "keyboard", "primaryKey", "cacheKey",
	} {
		if m, ok := c.Ident(name); ok && c.Lookup(m.DataType).Class == "credential" {
			t.Errorf("%s: false positive %+v", name, m)
		}
	}
	if m, ok := c.Ident("passwordHash"); !ok || m.DataType != "password" || m.Transform != "hashed" {
		t.Errorf("passwordHash: %+v %v", m, ok)
	}
}

func TestSecretValues(t *testing.T) {
	s := &LiteralScanner{Classifier: NewClassifier(DefaultTaxonomy())}
	b62 := "Zx8Qm2Lp4Rt7Wv9Ks3Nd6Hf1Jc5Gb0Ya"
	cases := []struct{ line, dt, det string }{
		{join(`aws_key = "AKIA`, "Q7ZK4MP2WX9LRT3B", `"`), "api_key", "aws-access-key-id"},
		{join(`STRIPE=sk_`, `live_`, b62), "api_key", "stripe-secret-key"},
		{join(`"maps": "AIza`, "SyD4k9Lq2Xw7Pz3Mn8Rt5Vb1Hc6Jg0Fe2Ks", `"`), "api_key", "google-api-key"},
		{join(`token: gh`, `p_`, b62, "Ab4Q"), "access_token", "github-token"},
		{join(`SLACK=xox`, `b-`, "1234-5678-", b62), "access_token", "slack-token"},
		{join(`auth = "eyJ`, `hbGciOiJIUzI1NiJ9.eyJ`, `zdWIiOiJ1c2VyLTQyIn0.`, b62, `"`), "access_token", "jwt"},
		{join(`-----BEGIN RSA `, `PRIVATE KEY-----`), "private_key", "private-key-block"},
		{join(`key: glpat-`, b62), "access_token", "gitlab-token"},
	}
	for _, tc := range cases {
		hits := s.Scan([]byte(tc.line))
		if len(hits) != 1 || hits[0].DataType != tc.dt || hits[0].Detector != tc.det {
			t.Errorf("%s: %+v, want one %s from %s", tc.line, hits, tc.dt, tc.det)
			continue
		}
		if m := hits[0].Masked; len(m) != 12 || !strings.HasSuffix(m, "********") || strings.Contains(tc.line, m[4:]) {
			t.Errorf("%s: mask %q reveals the secret", tc.line, m)
		}
	}
	for _, line := range []string{
		join(`aws_key = "AKIA`, `IOSFODNN7EXAMPLE"`), // AWS documentation key
		join(`sk_`, `live_xxxxxxxxxxxxxxxxxxxxxxxx`),
		join(`gh`, `p_`, strings.Repeat("a", 36)), // too little entropy
		join(`const token = "${GITHUB`, `_TOKEN}"`),
		join(`eyJ`, `hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ`, `zdWIiOiIxMjM0NTY3ODkwIn0.`, `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`), // jwt.io
		"the api key goes in the AKIA field",
	} {
		if hits := s.Scan([]byte(line)); len(hits) != 0 {
			t.Errorf("%s: placeholder reported: %+v", line, hits)
		}
	}
	if hits := (&LiteralScanner{Classifier: s.Classifier, MinConf: 0.96}).Scan([]byte(cases[0].line)); len(hits) != 0 {
		t.Errorf("MinConf ignored: %+v", hits)
	}
}

func TestValuePatternValidation(t *testing.T) {
	base := func(v ValuePattern) Taxonomy {
		return Taxonomy{Classes: []Class{{ID: "credential", Label: "c"}}, Types: []DataType{{ID: "k", Label: "K", Class: "credential", Category: "secret", Values: []ValuePattern{v}}}}
	}
	for name, v := range map[string]ValuePattern{
		"no keywords":    {Name: "x", Regex: `x`, Confidence: 0.5},
		"two captures":   {Name: "x", Regex: `(a)(b)`, Confidence: 0.5, Keywords: []string{"a"}},
		"bad entropy":    {Name: "x", Regex: `x`, Confidence: 0.5, Keywords: []string{"x"}, MinEntropy: 9},
		"bad regex":      {Name: "x", Regex: `(`, Confidence: 0.5, Keywords: []string{"x"}},
		"bad confidence": {Name: "x", Regex: `x`, Confidence: 2, Keywords: []string{"x"}},
	} {
		if err := base(v).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := base(ValuePattern{Name: "x", Regex: `k-(\w+)`, Confidence: 0.5, Keywords: []string{"k-"}}).Validate(); err != nil {
		t.Errorf("valid pattern rejected: %v", err)
	}
	if entropy("") != 0 || entropy("aaaa") != 0 || entropy("ab") != 1 {
		t.Error("entropy")
	}
	if maskSecret("short") != "********" {
		t.Error("short secrets are fully masked")
	}
}
