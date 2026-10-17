// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"github.com/GoNetTools/datawarden/internal/ir"

	"reflect"
	"testing"
)

var testC = NewClassifier(DefaultTaxonomy())

func TestTokenize(t *testing.T) {
	cases := map[string][]string{
		"phoneNumber":     {"phone", "number"},
		"USER_EMAIL_ADDR": {"user", "email", "addr"},
		"SSNNumber":       {"ssn", "number"},
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
		"nationalId": "national_id", "citizenIdNumber": "national_id", "socialInsuranceNumber": "insurance_id",
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
		"soDienThoai", "sdt", "hoTen", "ngaySinh", "diaChi", "soTaiKhoan", "cccd", "cmnd", "bhxh", "bhyt",
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
	s := &LiteralScanner{Classifier: testC, MinConf: 0.6}
	// Phone and national ID numbers are found through names and schema
	// hints, not as committed values.
	src := `{"phoneNumber": "0912 837 465", "nationalId": "001099017384", "email": "nguyen.van.a@gmail.com"}
{"phone": "0912345678", "email": "test@example.com", "nationalId": "001099012345"}
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
	want := map[string]int{"email": 1, "credit_card": 1, "bank_account": 1, "us_ssn": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("literal hits = %v, want %v\n%+v", got, want, hits)
	}
}

func TestValidators(t *testing.T) {
	if !luhn("4539148803436467") || luhn("4539148803436468") {
		t.Error("luhn")
	}
	if !validIBAN("DE44500105175407324931") || validIBAN("DE44500105175407324932") {
		t.Error("iban")
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

// TestClassifyCardData covers the cardholder data types of PCI DSS: the
// card number, the security code, the expiry date, track data and the
// cardholder name, and the look-alikes that are not cards.
func TestClassifyCardData(t *testing.T) {
	want := map[string]string{
		"cardNumber": "credit_card", "primaryAccountNumber": "credit_card", "pan": "credit_card", "cardPan": "credit_card", "ccNum": "credit_card",
		"cvv": "card_security_code", "cvc": "card_security_code", "cvv2": "card_security_code", "cardCvv": "card_security_code",
		"securityCode": "card_security_code", "cardSecurityCode": "card_security_code", "cardVerificationValue": "card_security_code", "card_verification_code": "card_security_code",
		"cardExpiry": "card_expiry", "cardExpiration": "card_expiry", "expMonth": "card_expiry", "expYear": "card_expiry", "expiryMonth": "card_expiry",
		"expiryYear": "card_expiry", "validThru": "card_expiry", "ccExp": "card_expiry", "expiryDate": "card_expiry", "expirationDate": "card_expiry",
		"track2Data": "card_track_data", "track1": "card_track_data", "trackData": "card_track_data", "magneticStripe": "card_track_data", "magstripe": "card_track_data",
		"pinBlock": "card_track_data", "cardPin": "card_track_data", "emvData": "card_track_data",
		"cardholderName": "cardholder_name", "cardHolderName": "cardholder_name", "nameOnCard": "cardholder_name", "cardholder": "cardholder_name",
	}
	for name, dt := range want {
		m, ok := testC.Ident(name)
		if !ok || m.DataType != dt {
			t.Errorf("Ident(%q) = %+v, %v; want %s", name, m, ok, dt)
		}
		if c := testC.Lookup(m.DataType).Class; c != "pci" {
			t.Errorf("%s: class %s, want pci", m.DataType, c)
		}
	}
	// The expiry date of anything else is not cardholder data, and the
	// bare words are weak: a bare expiryDate scores below a cardExpiry.
	for _, name := range []string{"tokenExpiryDate", "sessionExpiry", "certificateExpirationDate", "passwordExpiryDate", "couponExpiryDate", "subscriptionExpiration", "cacheExpiry", "licenseExpiryDate",
		"trackingNumber", "trackId", "gitTracked", "trackEvent", "cardType", "cardBrand", "cardLast4", "cardToken", "cvvLength", "cvvFieldLabel", "securityCodeLength", "otpSecurityCode",
		"cardholderAgreement", "pinCode", "zipCode"} {
		if m, ok := testC.Ident(name); ok && testC.Lookup(m.DataType).Class == "pci" {
			t.Errorf("Ident(%q) = %+v; want no cardholder data", name, m)
		}
	}
	weak, _ := testC.Ident("expiryDate")
	strong, _ := testC.Ident("cardExpiry")
	if weak.Conf >= strong.Conf {
		t.Errorf("expiryDate %.2f should score below cardExpiry %.2f", weak.Conf, strong.Conf)
	}
	if m, ok := testC.Field("com.acme.Cardholder", "name"); !ok || m.DataType != "cardholder_name" {
		t.Errorf("Cardholder.name: %+v %v", m, ok)
	}
	if m, ok := testC.Field("model.Card", "HolderName"); !ok || m.DataType != "cardholder_name" {
		t.Errorf("Card.HolderName: %+v %v", m, ok)
	}
	if m, ok := testC.Field("model.Account", "HolderName"); !ok || m.DataType != "person_name" {
		t.Errorf("Account.HolderName: %+v %v", m, ok)
	}
	if m, ok := testC.Getter("getCvv"); !ok || m.DataType != "card_security_code" {
		t.Errorf("getCvv: %+v %v", m, ok)
	}
}

// TestSchemaSensitiveMarkers covers the built-in markers (pii, pci, phi,
// sensitive, @PII, @PCI, @Sensitive...) and the repository's own
// (SchemaOptions.SensitiveMarkers).
func TestSchemaSensitiveMarkers(t *testing.T) {
	types := []*ir.TypeDecl{
		{Name: "p.Card", Kind: "struct", Fields: []ir.Field{
			{Name: "Number", Type: "string", Tags: map[string]string{"pci": "credit_card"}},
			{Name: "Code", Type: "string", Tags: map[string]string{"pci": "true"}},
			{Name: "Holder", Type: "string", Tags: map[string]string{"mask": "cardholder_name"}},
			{Name: "ExpMonth", Type: "string", Tags: map[string]string{"sensitive": ""}},
			{Name: "Note", Type: "string", Tags: map[string]string{"mask": "-"}},
			{Name: "Theme", Type: "string", Tags: map[string]string{"json": "theme"}},
		}},
		{Name: "com.acme.Patient", Kind: "class", Fields: []ir.Field{
			{Name: "record", Type: "String", Tags: map[string]string{"@PHI": ""}},
			{Name: "contact", Type: "String", Tags: map[string]string{"@Masked": "phone"}},
			{Name: "nickname", Type: "String", Tags: map[string]string{"@Masked": ""}},
			{Name: "diagnosis", Type: "String", Tags: map[string]string{"@Confidential": ""}},
		}},
	}
	// Built-in markers only: mask and @Masked mean nothing.
	s := BuildSchema(testC, types)
	for field, want := range map[string]string{"Number": "credit_card", "Code": "pci", "ExpMonth": "card_expiry"} {
		if h, st := s.Field("p.Card", field); st != FieldPII || h.DataType != want || h.Conf != 1 {
			t.Errorf("Card.%s: %+v %v, want %s", field, h, st, want)
		}
	}
	if _, st := s.Field("p.Card", "Holder"); st != FieldUnknown {
		t.Errorf("Card.Holder: mask is not a built-in marker, got %v", st)
	}
	if h, st := s.Field("com.acme.Patient", "record"); st != FieldPII || h.DataType != "phi" {
		t.Errorf("Patient.record: %+v %v", h, st)
	}
	if h, st := s.Field("com.acme.Patient", "diagnosis"); st != FieldPII || h.DataType != "health" {
		t.Errorf("Patient.diagnosis: %+v %v", h, st)
	}
	if testC.Lookup("pci").Class != "pci" || testC.Lookup("phi").Class != "phi" || testC.Lookup("loyalty").Class != "pii" {
		t.Error("a class id used as a data type belongs to that class")
	}
	// With the repository's markers.
	s = BuildSchema(testC, types, SchemaOptions{SensitiveMarkers: []string{"mask", "@Masked"}})
	if h, st := s.Field("p.Card", "Holder"); st != FieldPII || h.DataType != "cardholder_name" || h.Via != `mask:"cardholder_name"` {
		t.Errorf("Card.Holder: %+v %v", h, st)
	}
	if _, st := s.Field("p.Card", "Note"); st != FieldNotPII {
		t.Errorf("Card.Note: mask:\"-\" suppresses, got %v", st)
	}
	if h, st := s.Field("com.acme.Patient", "contact"); st != FieldPII || h.DataType != "phone" {
		t.Errorf("Patient.contact: %+v %v", h, st)
	}
	if h, st := s.Field("com.acme.Patient", "nickname"); st != FieldPII || h.DataType != "pii" {
		t.Errorf("Patient.nickname: %+v %v", h, st)
	}
	if dts := s.TypeDataTypes("p.Card"); len(dts) != 4 {
		t.Errorf("Card carries %v", dts)
	}
}
