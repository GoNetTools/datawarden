// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"unicode"
)

// Tokenize splits an identifier into lower-case words. It understands
// camelCase, PascalCase, ACRONYMWords, snake_case, kebab-case, dotted paths
// and letter/digit boundaries:
//
//	phoneNumber     -> [phone number]
//	USER_EMAIL_ADDR -> [user email addr]
//	CCCDNumber      -> [cccd number]
//	user.email2     -> [user email 2]
func Tokenize(s string) []string {
	var out []string
	rs := []rune(s)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			out = append(out, strings.ToLower(string(rs[start:end])))
		}
		start = -1
	}
	for i, r := range rs {
		isAlnum := unicode.IsLetter(r) || unicode.IsDigit(r)
		if !isAlnum {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := rs[i-1]
		switch {
		case unicode.IsLower(prev) && unicode.IsUpper(r):
			flush(i)
			start = i
		case unicode.IsUpper(prev) && unicode.IsUpper(r) && i+1 < len(rs) && unicode.IsLower(rs[i+1]):
			// "CCCDNumber": split before the 'N'.
			flush(i)
			start = i
		case unicode.IsDigit(prev) != unicode.IsDigit(r):
			flush(i)
			start = i
		}
	}
	flush(len(rs))
	return out
}
