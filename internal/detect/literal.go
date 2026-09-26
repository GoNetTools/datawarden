// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// LiteralHit is a PII value found verbatim in a file (e.g. a real card
// number committed in a fixture). The raw value is never stored; only a
// masked rendering and a hash for baselining.
type LiteralHit struct {
	DataType string  `json:"data_type"`
	Line     int     `json:"line"`
	Col      int     `json:"col"`
	Masked   string  `json:"masked"`
	Hash     string  `json:"value_hash"`
	Conf     float64 `json:"confidence"`
	Detector string  `json:"detector"`
}

// LiteralScanner finds sensitive values (literals) in text.
type LiteralScanner struct {
	// Classifier recognises labels next to values ("ssn": ...).
	Classifier *Classifier
	// MinConf drops weaker hits (the policy applies its own threshold).
	MinConf float64
}

var (
	reEmail = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b`)
	reCard  = regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`)
	reSSN   = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	reIBAN  = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
)

var placeholderEmailDomains = []string{
	"example.com", "example.org", "example.net", "test.com", "domain.com", "email.com", "mycompany.com",
	"yourcompany.com", "company.com", "acme.com", "foo.com", "bar.com", "sample.com", "mail.com", "yourdomain.com",
	"users.noreply.github.com", "noreply.github.com", "localhost", "anthropic.com",
}

var roleLocalParts = set("noreply", "no-reply", "donotreply", "do-not-reply", "support", "info", "admin", "contact", "hello",
	"sales", "security", "abuse", "postmaster", "webmaster", "privacy", "team", "dev", "devs", "git", "user", "test", "root",
	"john.doe", "jane.doe", "johndoe", "janedoe", "foo", "bar", "someone", "somebody", "name", "email", "your.email",
	"youremail", "username", "example", "help", "billing", "careers", "jobs", "press", "legal", "office", "hr", "marketing",
	"notifications", "notification", "alerts", "bot", "ci", "build", "release", "ops", "devops", "it", "mail", "noc",
	"opensource", "open-source", "oss", "conduct", "community", "maintainers", "feedback", "hi", "hey", "team-security", "psirt", "cert")

var fileTLDs = set("png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "js", "ts", "tsx", "jsx", "css", "scss", "json", "xml",
	"kt", "java", "go", "py", "rb", "md", "txt", "html", "htm", "yaml", "yml", "lock", "zip", "gz", "tar", "pdf", "map", "vue", "class", "jar", "aar", "so", "dll", "exe")

var testCards = set("4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "5555555555554444",
	"5105105105105100", "5200828282828210", "378282246310005", "371449635398431", "6011111111111117", "6011000990139424",
	"3530111333300000", "3566002020360505", "30569309025904", "38520000023237", "4000000000000002", "4000000000009995",
	"4000000000000077", "4000000000003220", "2223003122003222", "6200000000000005", "5454545454545454", "4917610000000000",
	"4444333322221111", "4000000000000010", "4000002500003155", "5200000000000007", "4988438843884305")

var docIBANs = set("GB82WEST12345698765432", "DE89370400440532013000", "GB33BUKB20201555555555", "FR1420041010050500013M02606", "NL91ABNA0417164300")

// Scan returns the sensitive values found in content.
func (s *LiteralScanner) Scan(content []byte) []LiteralHit {
	if looksBinary(content) {
		return nil
	}
	minConf := s.MinConf
	var hits []LiteralHit
	lineNo := 0
	for len(content) > 0 {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			line, content = content[:i], content[i+1:]
		} else {
			line, content = content, nil
		}
		if len(line) > 4096 { // minified bundles, base64 blobs
			continue
		}
		if s.Classifier != nil {
			hits = s.Classifier.scanValues(hits, string(line), lineNo, minConf)
		}
		if !bytes.ContainsAny(line, "0123456789@") {
			continue
		}
		str := string(line)
		var ctx map[string]bool
		ctxFor := func() map[string]bool {
			if ctx == nil {
				if s.Classifier != nil {
					ctx = s.Classifier.ContextTypes(str)
				}
				if ctx == nil {
					ctx = map[string]bool{}
				}
			}
			return ctx
		}
		emit := func(dt string, start int, raw string, conf float64, det string) {
			if conf < minConf {
				return
			}
			hits = append(hits, LiteralHit{DataType: dt, Line: lineNo, Col: start + 1, Masked: MaskValue(dt, raw), Hash: valueHash(dt, raw), Conf: round2(conf), Detector: det})
		}
		taken := make([][2]int, 0, 2)
		overlaps := func(a, b int) bool {
			for _, t := range taken {
				if a < t[1] && b > t[0] {
					return true
				}
			}
			return false
		}

		if strings.IndexByte(str, '@') >= 0 {
			for _, m := range reEmail.FindAllStringIndex(str, -1) {
				v := str[m[0]:m[1]]
				if conf := emailConf(v, str, m[0]); conf > 0 {
					if ctxFor()["email"] {
						conf += 0.1
					}
					emit("email", m[0], v, conf, "email-format")
					taken = append(taken, [2]int{m[0], m[1]})
				}
			}
		}
		for _, m := range reCard.FindAllStringIndex(str, -1) {
			if overlaps(m[0], m[1]) {
				continue
			}
			d := onlyDigits(str[m[0]:m[1]])
			if !cardGrouping(str[m[0]:m[1]]) || decimalPart(str, m[0], m[1]) {
				continue
			}
			if conf := cardConf(d); conf > 0 {
				if ctxFor()["credit_card"] {
					conf += 0.1
				}
				emit("credit_card", m[0], d, conf, "luhn+iin")
				taken = append(taken, [2]int{m[0], m[1]})
			}
		}
		for _, m := range reSSN.FindAllStringSubmatchIndex(str, -1) {
			if overlaps(m[0], m[1]) {
				continue
			}
			v := str[m[0]:m[1]]
			if validSSN(str[m[2]:m[3]], str[m[4]:m[5]], str[m[6]:m[7]]) {
				conf := 0.6
				if ctxFor()["us_ssn"] {
					conf = 0.92
				}
				emit("us_ssn", m[0], v, conf, "ssn-structure")
			}
		}
		for _, m := range reIBAN.FindAllStringIndex(str, -1) {
			v := strings.ReplaceAll(str[m[0]:m[1]], " ", "")
			if validIBAN(v) && !docIBANs[v] {
				conf := 0.8
				if ctxFor()["bank_account"] {
					conf = 0.95
				}
				emit("bank_account", m[0], v, conf, "iban-mod97")
			}
		}
	}
	return hits
}

func round2(f float64) float64 {
	if f > 1 {
		f = 1
	}
	return float64(int(f*100+0.5)) / 100
}

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func onlyDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigitByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func emailConf(v, line string, at int) float64 {
	i := strings.LastIndexByte(v, '@')
	local, domain := strings.ToLower(v[:i]), strings.ToLower(v[i+1:])
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	if fileTLDs[tld] {
		return 0
	}
	for _, d := range placeholderEmailDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return 0
		}
	}
	if strings.HasSuffix(domain, ".test") || strings.HasSuffix(domain, ".invalid") || strings.HasSuffix(domain, ".example") || strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".internal") {
		return 0
	}
	if roleLocalParts[local] || strings.HasPrefix(local, "noreply") || strings.HasPrefix(local, "no-reply") {
		return 0
	}
	// Test and demo accounts: test123@gmail.com, dummy@acme.io.
	switch strings.TrimRight(local, "0123456789._-") {
	case "test", "testuser", "tester", "testing", "dummy", "demo", "fake", "sample", "example", "foo", "bar", "foobar", "john.doe", "jane.doe", "johndoe", "janedoe":
		return 0
	}
	// npm scopes / version pins: "@sentry/browser@7.1.0", "pkg@1.2.3".
	if at > 0 && (line[at-1] == '/' || line[at-1] == '@') {
		return 0
	}
	if strings.Contains(local, "${") || strings.Contains(local, "%s") {
		return 0
	}
	// Kotlin labels (this@Outer.x), decorators and camelCase "domains" are code.
	if local == "this" || local == "super" || local == "it" {
		return 0
	}
	d := v[i+1:]
	for j := 1; j < len(d); j++ {
		if d[j] >= 'A' && d[j] <= 'Z' && d[j-1] >= 'a' && d[j-1] <= 'z' {
			return 0
		}
	}
	// Attribution lines are contact data of maintainers, not user PII.
	ll := strings.ToLower(line)
	for _, w := range []string{"copyright", "author", "maintainer", "contributor", "signed-off-by", "co-authored-by", "license", "credits"} {
		if strings.Contains(ll, w) {
			return 0
		}
	}
	if len(tld) != 2 && !commonTLDs[tld] {
		return 0.5
	}
	return 0.8
}

var commonTLDs = set("com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "ai", "app", "dev", "me", "tv", "xyz",
	"online", "site", "tech", "store", "shop", "cloud", "email", "name", "pro", "asia", "mobi", "live", "life", "world", "today", "space",
	"website", "digital", "network", "solutions", "services", "agency", "company", "group", "global", "media", "news", "blog", "club",
	"design", "studio", "systems", "software", "academy", "school", "center", "health", "finance", "bank", "insurance", "vip", "work")

// trivialDigits rejects obvious placeholders: runs, repeats, sequences.
func trivialDigits(d string) bool {
	if len(d) < 6 {
		return true
	}
	same, asc, desc := 1, 1, 1
	maxSame, maxAsc, maxDesc := 1, 1, 1
	zeros := 0
	for i := 1; i < len(d); i++ {
		if d[i] == d[i-1] {
			same++
		} else {
			same = 1
		}
		if d[i] == d[i-1]+1 || (d[i-1] == '9' && d[i] == '0') {
			asc++
		} else {
			asc = 1
		}
		if d[i]+1 == d[i-1] || (d[i-1] == '0' && d[i] == '9') {
			desc++
		} else {
			desc = 1
		}
		maxSame, maxAsc, maxDesc = max(maxSame, same), max(maxAsc, asc), max(maxDesc, desc)
	}
	for i := 0; i < len(d); i++ {
		if d[i] == '0' {
			zeros++
		}
	}
	return maxSame >= 6 || maxAsc >= 6 || maxDesc >= 6 || zeros*10 >= len(d)*7
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// decimalPart reports whether str[start:end] is the fraction or the
// integer part of a decimal number (y="1424.4377811094455").
func decimalPart(str string, start, end int) bool {
	digit := func(i int) bool { return i >= 0 && i < len(str) && str[i] >= '0' && str[i] <= '9' }
	return start >= 2 && str[start-1] == '.' && digit(start-2) || end+1 < len(str) && str[end] == '.' && digit(end+1)
}

// cardGrouping reports whether a digit run with separators is grouped the
// way card numbers are written (4-4-4-4, 4-6-5 for American Express,
// 4-6-4 for Diners), with one kind of separator: "4097 1 829805 0 0" in a
// log is a list of numbers, not a card.
func cardGrouping(raw string) bool {
	sep := strings.IndexAny(raw, " -")
	if sep < 0 {
		return true
	}
	groups := strings.Split(raw, raw[sep:sep+1])
	lens := make([]int, len(groups))
	for i, g := range groups {
		if g == "" || strings.ContainsAny(g, " -") {
			return false
		}
		lens[i] = len(g)
	}
	switch {
	case slices.Equal(lens, []int{4, 6, 5}), slices.Equal(lens, []int{4, 6, 4}):
		return true
	}
	for i, n := range lens {
		if n != 4 && !(i == len(lens)-1 && n >= 1 && n <= 3) {
			return false
		}
	}
	return true
}

func cardConf(d string) float64 {
	if len(d) < 13 || len(d) > 19 || testCards[d] || trivialDigits(d[6:]) {
		return 0
	}
	iin := func(p string) bool { return strings.HasPrefix(d, p) }
	n2, _ := strconv.Atoi(d[:2])
	n4, _ := strconv.Atoi(d[:4])
	switch {
	case !luhn(d):
		return 0
	case d[0] == '4' && (len(d) == 13 || len(d) == 16 || len(d) == 19):
		return 0.85
	case (n2 >= 51 && n2 <= 55 || n4 >= 2221 && n4 <= 2720) && len(d) == 16:
		return 0.85
	case (n2 == 34 || n2 == 37) && len(d) == 15:
		return 0.85
	case (n4 >= 3528 && n4 <= 3589) && len(d) >= 16:
		return 0.85
	case (iin("6011") || iin("65") || iin("62")) && len(d) >= 16:
		return 0.8
	}
	return 0
}

func validSSN(a, g, s string) bool {
	if a == "000" || a == "666" || a[0] == '9' || g == "00" || s == "0000" {
		return false
	}
	switch a + g + s {
	case "078051120", "219099999", "123456789":
		return false
	}
	return true
}

func validIBAN(v string) bool {
	if len(v) < 15 || len(v) > 34 {
		return false
	}
	r := v[4:] + v[:4]
	var b strings.Builder
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteString(strconv.Itoa(int(c-'A') + 10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	if !ok {
		return false
	}
	return new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func valueHash(dt, v string) string {
	h := sha256.Sum256([]byte("datawarden-literal\x00" + dt + "\x00" + strings.ToLower(v)))
	return hex.EncodeToString(h[:12])
}

// MaskValue renders a value safely for reports.
func MaskValue(dt, v string) string {
	switch dt {
	case "email":
		i := strings.LastIndexByte(v, '@')
		if i <= 0 {
			return "***"
		}
		return v[:1] + strings.Repeat("*", max(3, i-1)) + v[i:]
	default:
		r := []rune(v)
		if len(r) <= 6 {
			return strings.Repeat("*", len(r))
		}
		keepHead, keepTail := 3, 2
		if dt == "credit_card" || dt == "bank_account" {
			keepHead, keepTail = 0, 4
		}
		return string(r[:keepHead]) + strings.Repeat("*", len(r)-keepHead-keepTail) + string(r[len(r)-keepTail:])
	}
}

// scanValues runs the taxonomy's value patterns (committed secrets and
// other values recognised by shape) over one line.
func (c *Classifier) scanValues(hits []LiteralHit, line string, lineNo int, minConf float64) []LiteralHit {
	for _, v := range c.values {
		if v.Confidence < minConf || !containsAny(line, v.Keywords) {
			continue
		}
		for _, m := range v.re.FindAllStringSubmatchIndex(line, -1) {
			start, end := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 {
				start, end = m[2], m[3]
			}
			val := line[start:end]
			if placeholderSecret(val) || entropy(val) < v.MinEntropy {
				continue
			}
			hits = append(hits, LiteralHit{DataType: v.dt.ID, Line: lineNo, Col: start + 1, Masked: maskSecret(val),
				Hash: valueHash(v.dt.ID, val), Conf: round2(v.Confidence), Detector: v.Name})
		}
	}
	return hits
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// placeholderSecret reports documentation and template values:
// AKIAIOSFODNN7EXAMPLE, sk_live_XXXXXXXX, ${API_KEY}, <your-token>.
func placeholderSecret(v string) bool {
	if strings.Contains(v, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") { // the jwt.io sample token
		return true
	}
	u := strings.ToUpper(v)
	for _, w := range []string{"EXAMPLE", "XXXX", "0000000", "1234567", "ABCDEFG", "YOUR", "REPLACE", "DUMMY", "PLACEHOLDER", "REDACTED", "CHANGEME", "${", "{{", "<", "*"} {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	e := 0.0
	n := float64(len(s))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// maskSecret keeps a secret's first four characters, which name its kind
// ("AKIA", "ghp_"), and nothing of the secret itself.
func maskSecret(v string) string {
	r := []rune(v)
	if len(r) <= 8 {
		return "********"
	}
	return string(r[:4]) + "********"
}
