// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"unicode"
)

// vnFold maps Vietnamese letters with diacritics to plain ASCII so that
// "Số điện thoại" and "soDienThoai" tokenize the same way.
var vnFold = func() map[rune]rune {
	m := map[rune]rune{}
	add := func(to rune, from string) {
		for _, r := range from {
			m[r] = to
		}
	}
	add('a', "àáạảãâầấậẩẫăằắặẳẵ")
	add('A', "ÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴ")
	add('e', "èéẹẻẽêềếệểễ")
	add('E', "ÈÉẸẺẼÊỀẾỆỂỄ")
	add('i', "ìíịỉĩ")
	add('I', "ÌÍỊỈĨ")
	add('o', "òóọỏõôồốộổỗơờớợởỡ")
	add('O', "ÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠ")
	add('u', "ùúụủũưừứựửữ")
	add('U', "ÙÚỤỦŨƯỪỨỰỬỮ")
	add('y', "ỳýỵỷỹ")
	add('Y', "ỲÝỴỶỸ")
	add('d', "đ")
	add('D', "Đ")
	return m
}()

// Fold removes Vietnamese diacritics.
func Fold(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if f, ok := vnFold[r]; ok {
			b.WriteRune(f)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Tokenize splits an identifier into lower-case words. It understands
// camelCase, PascalCase, ACRONYMWords, snake_case, kebab-case, dotted paths
// and letter/digit boundaries:
//
//	soDienThoai     -> [so dien thoai]
//	SDT_KHACH_HANG  -> [sdt khach hang]
//	CCCDNumber      -> [cccd number]
//	user.email2     -> [user email 2]
func Tokenize(s string) []string {
	s = Fold(s)
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
