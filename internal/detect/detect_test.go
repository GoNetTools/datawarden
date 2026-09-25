// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"reflect"
	"testing"
	"time"
)

var testC = NewClassifier(DefaultTaxonomy())

func TestTokenize(t *testing.T) {
	cases := map[string][]string{
		"phoneNumber":     {"phone", "number"},
		"USER_EMAIL_ADDR": {"user", "email", "addr"},
		"CCCDNumber":      {"cccd", "number"},
		"user.email2":     {"user", "email", "2"},
		"HTTPServer":      {"http", "server"},
	}
	for in, want := range cases {
		if got := Tokenize(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Tokenize(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClassifyIdent(t *testing.T) {
	pii := map[string]string{
		"email": "email", "userEmail": "email", "customer_email_address": "email", "eMail": "email",
		"phoneNumber": "phone", "msisdn": "phone", "CUSTOMER_PHONE": "phone", "mobileNo": "phone",
		"cccd": "vn_cccd", "cccdNumber": "vn_cccd", "cmnd": "vn_cccd", "bhxh": "insurance_id",
		"birthDate": "dob", "dateOfBirth": "dob", "dob": "dob",
		"fullName": "person_name", "first_name": "person_name",
		"homeAddress": "address", "shippingAddress": "address",
		"remoteAddr": "ip_address", "clientIp": "ip_address",
		"accountNumber": "bank_account", "iban": "bank_account",
		"cardNumber": "credit_card", "latitude": "location", "imei": "device_id", "taxCode": "tax_id",
		"licensePlate": "license_plate", "gender": "gender",
	}
	for name, want := range pii {
		m, ok := testC.Ident(name)
		if !ok || m.DataType != want {
			t.Errorf("testC.Ident(%q) = %+v, %v; want %s", name, m, ok, want)
		}
	}
	notPII := []string{
		"emailValidator", "isEmailValid", "emailRegex", "phoneFormatter", "EMAIL_KEY", "hasPhone", "emailService",
		"serverAddress", "listenAddress", "ipAddressAllowlist", "microphone", "fileName", "className", "userId",
		"emailSent", "phoneLayout", "raceCondition", "emailCount", "onEmailChanged", "hashMapOf",
		// Vietnamese identifier words are not supported: code is written in English.
		"soDienThoai", "sdt", "hoTen", "ngaySinh", "diaChi", "soTaiKhoan",
	}
	for _, name := range notPII {
		if m, ok := testC.Ident(name); ok {
			t.Errorf("testC.Ident(%q) = %+v; want no match", name, m)
		}
	}
}

func TestClassifyTransformWords(t *testing.T) {
	m, ok := testC.Ident("maskedPhone")
	if !ok || m.DataType != "phone" || m.Transform != "masked" {
		t.Fatalf("maskedPhone: %+v", m)
	}
	m, ok = testC.Ident("emailHash")
	if !ok || m.Transform != "hashed" {
		t.Fatalf("emailHash: %+v", m)
	}
	if x := TransformFromFuncName("maskPhone"); x != "masked" {
		t.Errorf("maskPhone -> %q", x)
	}
	if x := TransformFromFuncName("sha256Hex"); x != "sha256" {
		t.Errorf("sha256Hex -> %q", x)
	}
	if x := TransformFromFuncName("hashMapOf"); x != "" {
		t.Errorf("hashMapOf -> %q", x)
	}
}

func TestClassifyFieldEntityName(t *testing.T) {
	if m, ok := testC.Field("com.acme.Customer", "name"); !ok || m.DataType != "person_name" {
		t.Errorf("Customer.name: %+v %v", m, ok)
	}
	if _, ok := testC.Field("com.acme.Product", "name"); ok {
		t.Errorf("Product.name should not be PII")
	}
}

func TestLiteralScanner(t *testing.T) {
	s := &LiteralScanner{Classifier: testC, MinConf: 0.6, Now: func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) }}
	src := `{"phoneNumber": "0912 837 465", "cccd": "001099017384", "email": "nguyen.van.a@gmail.com"}
{"phone": "0912345678", "email": "test@example.com", "cccd": "001099012345"}
card: 4539 1488 0343 6467
test card 4111111111111111
iban: DE44500105175407324931
ssn: 536-90-4399
id 123456789012
"@sentry/browser@7.1.0"
+84 983 715 204
`
	hits := s.Scan([]byte(src))
	got := map[string]int{}
	for _, h := range hits {
		got[h.DataType]++
		if h.Masked == "" || h.Hash == "" {
			t.Errorf("hit without masked/hash: %+v", h)
		}
	}
	want := map[string]int{"phone": 2, "vn_cccd": 1, "email": 1, "credit_card": 1, "bank_account": 1, "us_ssn": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("literal hits = %v, want %v\n%+v", got, want, hits)
	}
}

func TestValidators(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !validCCCD("079203017384", now) {
		t.Error("valid HCMC CCCD rejected")
	}
	if validCCCD("003099017384", now) { // 003 is not a province code
		t.Error("bad province accepted")
	}
	if validCCCD("079399017384", now) { // born 2099
		t.Error("future birth year accepted")
	}
	if !luhn("4539148803436467") || luhn("4539148803436468") {
		t.Error("luhn")
	}
	if !validIBAN("DE44500105175407324931") || validIBAN("DE44500105175407324932") {
		t.Error("iban")
	}
	if _, ok := normalizeVNPhone("+84 983 715 204"); !ok {
		t.Error("+84 phone rejected")
	}
	if _, ok := normalizeVNPhone("0123456789"); ok {
		t.Error("placeholder phone accepted")
	}
	if MaskValue("email", "nguyen@gmail.com") != "n*****@gmail.com" {
		t.Errorf("mask email: %s", MaskValue("email", "nguyen@gmail.com"))
	}
}

func TestParseProtoAndSQL(t *testing.T) {
	proto := `syntax = "proto3";
package acme.user.v1;
message Customer {
  string id = 1;
  string phone_number = 2;
  string contact = 3 [(pii) = "email"];
  Address addr = 4; // pii: address
  message Address { string street = 1; }
  enum Kind { KIND_UNSPECIFIED = 0; }
}`
	types := ParseProto("user.proto", []byte(proto))
	if len(types) != 2 || types[0].Name != "acme.user.v1.Customer" || len(types[0].Fields) != 4 {
		t.Fatalf("proto: %+v", types)
	}
	if types[0].Fields[2].Tags["pii"] != "email" || types[0].Fields[3].Tags["pii"] != "address" {
		t.Errorf("proto pii options: %+v", types[0].Fields)
	}
	sql := `CREATE TABLE IF NOT EXISTS "customers" (
  id BIGSERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  contact_no VARCHAR(20), -- pii: phone
  note TEXT,
  CONSTRAINT uq UNIQUE (contact_no)
);
ALTER TABLE customers ADD COLUMN birth_date DATE;`
	tt := ParseSQL("001_init.sql", []byte(sql))
	if len(tt) != 1 || len(tt[0].Fields) != 5 {
		t.Fatalf("sql: %+v", tt)
	}
	s := BuildSchema(testC, tt)
	for field, want := range map[string]string{"full_name": "person_name", "contact_no": "phone", "birth_date": "dob"} {
		h, st := s.Field("table:customers", field)
		if st != FieldPII || h.DataType != want {
			t.Errorf("%s: %+v %v", field, h, st)
		}
	}
	if _, st := s.Field("table:customers", "note"); st == FieldPII {
		t.Error("note should not be PII")
	}
}

func TestCustomTaxonomy(t *testing.T) {
	// The classifier is built from whatever taxonomy it is given.
	c := NewClassifier([]DataType{{ID: "loyalty_card", Label: "Loyalty card", Patterns: []string{"the thanh vien", "loyalty card"}}})
	if m, ok := c.Ident("soTheThanhVien"); !ok || m.DataType != "loyalty_card" {
		t.Errorf("custom type: %+v %v", m, ok)
	}
	if _, ok := c.Ident("email"); ok {
		t.Error("types outside the taxonomy must not match")
	}
	if c.Lookup("loyalty_card").Label != "Loyalty card" || c.Known("email") {
		t.Error("lookup")
	}
}
