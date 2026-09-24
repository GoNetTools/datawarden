// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// BenchmarkLiteralScan scans ~1 MB of JSON-like text in which one line in
// eight holds personal data, the rest ordinary numbers and words.
func BenchmarkLiteralScan(b *testing.B) {
	var sb strings.Builder
	for i := 0; sb.Len() < 1<<20; i++ {
		if i%8 == 0 {
			fmt.Fprintf(&sb, `{"phoneNumber": "0912 837 465", "cccd": "001099017384", "email": "nguyen.van.a@gmail.com", "row": %d}`+"\n", i)
		} else {
			fmt.Fprintf(&sb, `{"id": %d, "sku": "SKU-%08d", "price": %d.%02d, "status": "shipped", "note": "left at door"}`+"\n", i, i*7, i%500, i%100)
		}
	}
	content := []byte(sb.String())
	s := &LiteralScanner{Classifier: NewClassifier(DefaultTaxonomy()), MinConf: 0.6, Now: func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) }}
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(s.Scan(content)) == 0 {
			b.Fatal("no hits")
		}
	}
}

// BenchmarkClassifierIdent classifies a mix of PII and ordinary identifiers.
func BenchmarkClassifierIdent(b *testing.B) {
	c := NewClassifier(DefaultTaxonomy())
	names := []string{"phoneNumber", "customerEmail", "user_phone_number", "birthDate", "fullName", "cccd",
		"orderID", "retryCount", "httpClient", "nickname", "createdAt", "requestBody", "shippingAddressLine1", "ipAddr"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, n := range names {
			c.Ident(n)
		}
	}
}
