// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strconv"
	"strings"
	"testing"
)

// withCheckDigit completes a synthetic number so it passes Luhn.
func withCheckDigit(prefix string) string {
	for d := 0; d < 10; d++ {
		n := prefix + strconv.Itoa(d)
		if luhn(n) {
			return n
		}
	}
	panic("unreachable")
}

// breakLuhn changes the check digit.
func breakLuhn(n string) string {
	last := (int(n[len(n)-1]-'0') + 1) % 10
	return n[:len(n)-1] + strconv.Itoa(last)
}

func TestCardNetworks(t *testing.T) {
	for _, c := range []struct {
		name string
		num  string
		want float64
	}{
		{"visa 16", withCheckDigit("453201884730215"), 0.85},
		{"visa 13", withCheckDigit("401288817382"), 0.85},
		{"mastercard 5x", withCheckDigit("531938027461527"), 0.85},
		{"mastercard 2-series", withCheckDigit("222384017365291"), 0.85},
		{"amex", withCheckDigit("37829301746152"), 0.85},
		{"jcb", withCheckDigit("353018274619038"), 0.85},
		{"discover", withCheckDigit("601173829104736"), 0.8},
		{"unionpay", withCheckDigit("620583910274618"), 0.8},
		{"visa without luhn", breakLuhn(withCheckDigit("453201884730215")), 0},
		{"documented test card", "4111111111111111", 0},
		{"unknown network", withCheckDigit("100000384729164"), 0},
		{"too short", withCheckDigit("45320188473"), 0},
		{"trivial digits", withCheckDigit("453201" + strings.Repeat("0", 9)), 0},
	} {
		if got := cardConf(c.num); got != c.want {
			t.Errorf("%s (%s): cardConf = %v, want %v", c.name, c.num, got, c.want)
		}
	}
}

func TestSSNValidation(t *testing.T) {
	for ssn, want := range map[string]bool{
		"536-90-4399": true, "000-12-3456": false, "666-12-3456": false, "912-12-3456": false,
		"536-00-4399": false, "536-90-0000": false, "078-05-1120": false, "123-45-6789": false,
	} {
		p := strings.Split(ssn, "-")
		if got := validSSN(p[0], p[1], p[2]); got != want {
			t.Errorf("validSSN(%s) = %v", ssn, got)
		}
	}
}

func TestSchemaParserWrappers(t *testing.T) {
	c := NewClassifier(DefaultTaxonomy())
	if len(c.Types()) != len(DefaultTaxonomy()) || c.Known("nope") || !c.Known("email") {
		t.Error("classifier types")
	}
	if dt := c.Lookup("loyalty_card"); dt.Category != "custom" || dt.Label != "loyalty card" {
		t.Errorf("custom type: %+v", dt)
	}
	s := Schemas{Classifier: c}
	proto := s.ParseProto("u.proto", []byte("syntax = \"proto3\";\npackage acme;\nmessage User { string email = 1; }\n"))
	sql := s.ParseSQL("m.sql", []byte("CREATE TABLE users (id BIGINT, phone_number TEXT);\n"))
	if len(proto) != 1 || len(sql) != 1 {
		t.Fatalf("proto=%+v sql=%+v", proto, sql)
	}
	schema := s.Build(append(proto, sql...))
	if h, st := schema.Field("table:users", "phone_number"); st != FieldPII || h.DataType != "phone" {
		t.Errorf("sql hint: %+v %v", h, st)
	}
}

func TestEmailConfidence(t *testing.T) {
	for _, c := range []struct {
		line string
		want float64
	}{
		{`"email": "tran.mai@gmail.com"`, 0.8},
		{`"email": "tran.mai@shop.vn"`, 0.8},
		{`"email": "tran.mai@shop.museum"`, 0.5},
		{`"email": "support@shop.vn"`, 0},
		{`"email": "noreply-alerts@shop.vn"`, 0},
		{`"email": "a@example.com"`, 0},
		{`"email": "a@mail.example"`, 0},
		{`logo: "icon@2x.png"`, 0},
		{`"@sentry/browser@7.1.0"`, 0},
		{`Author: Tran Mai <tran.mai@gmail.com>`, 0},
		{`"email": "${user}@gmail.com"`, 0},
		{`this@Outer.run()`, 0},
		{`"email": "a@camelCase.com"`, 0},
	} {
		m := reEmail.FindStringIndex(c.line)
		if m == nil {
			if c.want != 0 {
				t.Errorf("%s: no match", c.line)
			}
			continue
		}
		if got := emailConf(c.line[m[0]:m[1]], c.line, m[0]); got != c.want {
			t.Errorf("emailConf(%s) = %v, want %v", c.line, got, c.want)
		}
	}
}
