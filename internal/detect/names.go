// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"sort"
	"strings"
)

// Match is the result of classifying an identifier, key, or field.
type Match struct {
	DataType string  `json:"data_type"`
	Conf     float64 `json:"confidence"`
	// Transform is set when the name itself says the value is already
	// protected: maskedPhone -> "masked", emailHash -> "hashed".
	Transform string `json:"transform,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// Tokens around a PII word that do not change its meaning.
var neutral = set(
	"user", "users", "customer", "client", "contact", "primary", "secondary", "alt", "alternate", "new", "old", "raw",
	"input", "value", "val", "str", "string", "text", "current", "cur", "my", "your", "owner", "member", "account",
	"person", "profile", "home", "work", "personal", "private", "billing", "shipping", "recipient", "sender", "receiver",
	"from", "to", "cc", "bcc", "reply", "param", "arg", "req", "resp", "dto", "data", "info", "list", "arr", "array",
	"the", "a", "an", "of", "plain", "clear", "cleartext", "plaintext", "full", "original", "orig", "unmasked", "real",
	"normalized", "trimmed", "formatted", "local", "entered", "typed", "confirm", "confirmation", "backup", "emergency",
	"patient", "employee", "staff", "driver", "rider", "buyer", "seller", "merchant", "applicant", "guest", "subscriber",
)

// Last-position words that make the identifier name a *thing about* PII
// rather than PII: emailValidator, phoneFormatter, emailService.
var negativeHeads = set(
	"service", "svc", "client", "validator", "validation", "verifier", "formatter", "parser", "util", "utils", "helper",
	"helpers", "provider", "manager", "repository", "repo", "dao", "controller", "handler", "adapter", "holder", "view",
	"button", "btn", "layout", "label", "hint", "field", "template", "subject", "body", "pattern", "regex", "re", "format",
	"mask", "config", "cfg", "settings", "setting", "option", "options", "opts", "enabled", "disabled", "count", "cnt",
	"len", "length", "size", "max", "min", "limit", "type", "kind", "status", "state", "error", "err", "errors",
	"exception", "message", "msg", "key", "keys", "column", "col", "attr", "attribute", "event", "events", "screen",
	"page", "fragment", "activity", "dialog", "modal", "component", "widget", "icon", "url", "link", "verified",
	"verification", "confirmed", "sent", "clicked", "entered", "changed", "submitted", "tapped", "opened", "updated",
	"failed", "success", "succeeded", "required", "visible", "visibility", "permission", "permissions", "code", "otp",
	"pin", "prefix", "suffix", "extension", "ext", "country", "domain", "host", "server", "port", "enum", "annotation",
	"token", "sender", "notification", "notifications", "campaign", "queue", "topic", "job", "worker", "task", "id",
	"ids", "mode", "flag", "flags", "style", "color", "font", "column", "index", "idx", "offset", "schema", "spec",
	"test", "tests", "mock", "stub", "fake", "factory", "builder", "listener", "callback", "cb", "fn", "func",
	"regexp", "matcher", "checker", "check", "rule", "rules", "policy", "api", "endpoint", "route", "path", "dir",
	"file", "filename", "name", "names", "class", "type", "types", "table", "label", "placeholder", "request",
	"requests", "provider", "picker", "selector", "input_type", "keyboard", "icon", "badge", "chip", "tab",
)

// First-position words that make the identifier a boolean or an action.
var negativePrefix = set(
	"is", "has", "should", "can", "did", "will", "was", "enable", "enabled", "show", "hide", "allow", "need", "needs",
	"require", "requires", "use", "uses", "validate", "verify", "check", "format", "parse", "on", "handle", "update",
	"max", "min", "num", "count", "total", "len", "no", "invalid", "valid", "missing", "empty", "default",
	"send", "resend", "get", "set", "fetch", "load", "save", "delete", "remove", "reset", "edit", "change",
	"must", "supports", "support", "with", "without", "include", "exclude", "ask", "prompt", "select",
)

// Anywhere-in-name words that disqualify.
var negativeAnywhere = set("regex", "regexp", "pattern", "placeholder", "template", "hint", "label", "validator", "formatter", "enum", "annotation")

// Words that signal a transform already happened.
var transformWords = map[string]string{
	"masked": "masked", "obfuscated": "masked", "truncated": "masked", "partial": "masked", "last4": "masked",
	"hashed": "hashed", "hash": "hashed", "digest": "hashed", "sha256": "sha256", "sha1": "sha1", "md5": "md5", "sha512": "sha512",
	"encrypted": "encrypted", "enc": "encrypted", "cipher": "encrypted", "ciphertext": "encrypted", "sealed": "encrypted",
	"redacted": "redacted", "scrubbed": "redacted", "tokenized": "tokenized", "anonymized": "anonymized", "anonymised": "anonymized",
	"pseudonymized": "pseudonymized", "pseudonymised": "pseudonymized",
}

// Substrings that must never trigger compact matching.
var compactStop = []string{"microphone", "headphone", "earphone", "smartphone", "iphone", "xylophone", "saxophone", "megaphone", "phoneme", "phonetic", "gramophone", "telephony"}

type compiledPattern struct {
	dt      *DataType
	toks    []string
	joined  string
	weak    bool
	exclude map[string]bool
}

// Classifier decides whether identifiers, keys and fields name personal
// data. It is built from a taxonomy (NewClassifier(DefaultTaxonomy()))
// and holds no global state, so tests and callers can supply their own
// data types.
type Classifier struct {
	classes  map[string]Class
	types    []DataType
	byID     map[string]*DataType
	patterns []compiledPattern
	vocab    map[string]bool
}

// NewClassifier compiles a taxonomy's data types. Classes default to the
// built-in ones; pass classes to use your own.
func NewClassifier(types []DataType, classes ...Class) *Classifier {
	if len(classes) == 0 {
		classes = DefaultClasses()
	}
	c := &Classifier{classes: map[string]Class{}, types: append([]DataType(nil), types...), byID: map[string]*DataType{}, vocab: map[string]bool{}}
	for _, cl := range classes {
		c.classes[cl.ID] = cl
	}
	for i := range c.types {
		dt := &c.types[i]
		c.byID[dt.ID] = dt
		ex := set(dt.Exclude...)
		add := func(p string, weak bool) {
			toks := strings.Fields(p)
			for _, t := range toks {
				c.vocab[t] = true
			}
			c.patterns = append(c.patterns, compiledPattern{dt: dt, toks: toks, joined: strings.Join(toks, ""), weak: weak, exclude: ex})
		}
		for _, p := range dt.Patterns {
			add(p, false)
		}
		for _, p := range dt.Weak {
			add(p, true)
		}
	}
	// Longer patterns first so "email address" beats "address".
	sort.SliceStable(c.patterns, func(i, j int) bool { return len(c.patterns[i].toks) > len(c.patterns[j].toks) })
	return c
}

// Types returns the taxonomy the classifier was built from.
func (c *Classifier) Types() []DataType { return append([]DataType(nil), c.types...) }

// Lookup returns a data type definition, or a synthetic one for custom
// types introduced by rules or pii tags.
func (c *Classifier) Lookup(id string) DataType {
	if dt, ok := c.byID[id]; ok {
		return *dt
	}
	return DataType{ID: id, Label: strings.ReplaceAll(id, "_", " "), Class: "pii", Category: "custom"}
}

// Class describes a class of data (pii, phi, pci, credential). Unknown
// ids get a synthetic class, like custom data types.
func (c *Classifier) Class(id string) Class {
	if cl, ok := c.classes[id]; ok {
		return cl
	}
	return Class{ID: id, Label: strings.ReplaceAll(id, "_", " ")}
}

// Classes returns the classes the classifier knows, sorted by id.
func (c *Classifier) Classes() []Class {
	out := make([]Class, 0, len(c.classes))
	for _, cl := range c.classes {
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Known reports whether id is part of the taxonomy.
func (c *Classifier) Known(id string) bool {
	_, ok := c.byID[id]
	return ok
}

func (c *Classifier) singular(t string) string {
	if len(t) > 4 && strings.HasSuffix(t, "es") && c.vocab[t[:len(t)-2]] {
		return t[:len(t)-2]
	}
	if len(t) > 3 && strings.HasSuffix(t, "s") && c.vocab[t[:len(t)-1]] {
		return t[:len(t)-1]
	}
	return t
}

func findSeq(toks, pat []string) int {
	for i := 0; i+len(pat) <= len(toks); i++ {
		ok := true
		for j := range pat {
			if toks[i+j] != pat[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// Ident classifies an identifier such as a variable, parameter, field,
// column, or JSON key.
func (c *Classifier) Ident(name string) (Match, bool) {
	return c.Tokens(Tokenize(name))
}

// Tokens classifies an already tokenized identifier.
func (c *Classifier) Tokens(raw []string) (Match, bool) {
	if len(raw) == 0 || len(raw) > 8 {
		return Match{}, false
	}
	toks := make([]string, len(raw))
	for i, t := range raw {
		toks[i] = c.singular(t)
	}
	xf := ""
	for _, t := range withDigitJoins(toks) {
		if x, ok := transformWords[t]; ok {
			xf = x
		}
	}
	for _, t := range toks {
		if negativeAnywhere[t] {
			return Match{}, false
		}
	}
	var best Match
	bestLen := 0
	for _, p := range c.patterns {
		idx := findSeq(toks, p.toks)
		conf := 0.0
		if idx >= 0 {
			if excluded(toks, idx, len(p.toks), p.exclude) {
				continue
			}
			if isNegativeContext(toks, idx, len(p.toks), xf != "") {
				continue
			}
			rest := len(toks) - len(p.toks)
			switch {
			case rest == 0:
				conf = 0.9
			case allNeutral(toks, idx, len(p.toks)):
				conf = 0.85
			default:
				conf = 0.72
			}
		} else if !p.weak && len(p.joined) >= 5 {
			conf = compactMatch(toks, p)
		}
		if conf == 0 {
			continue
		}
		if p.weak {
			conf -= 0.25
		}
		if conf > best.Conf || (conf == best.Conf && len(p.toks) > bestLen) {
			best = Match{DataType: p.dt.ID, Conf: conf, Pattern: strings.Join(p.toks, " ")}
			bestLen = len(p.toks)
		}
	}
	if best.DataType == "" {
		return Match{}, false
	}
	best.Transform = xf
	return best, true
}

func excluded(toks []string, idx, n int, ex map[string]bool) bool {
	if len(ex) == 0 {
		return false
	}
	for i, t := range toks {
		if i >= idx && i < idx+n {
			continue
		}
		if ex[t] {
			return true
		}
	}
	return false
}

func isNegativeContext(toks []string, idx, n int, hasTransform bool) bool {
	last := len(toks) - 1
	if last >= idx+n && negativeHeads[toks[last]] && !(hasTransform && transformWords[toks[last]] != "") {
		return true
	}
	if idx > 0 && negativePrefix[toks[0]] {
		return true
	}
	return false
}

func allNeutral(toks []string, idx, n int) bool {
	for i, t := range toks {
		if i >= idx && i < idx+n {
			continue
		}
		if !neutral[t] && transformWords[t] == "" && !isDigits(t) {
			return false
		}
	}
	return true
}

func compactMatch(toks []string, p compiledPattern) float64 {
	for _, t := range toks {
		if len(t) <= len(p.joined) || !strings.Contains(t, p.joined) {
			continue
		}
		stop := false
		for _, s := range compactStop {
			if strings.Contains(t, s) {
				stop = true
				break
			}
		}
		if stop {
			continue
		}
		for _, other := range toks {
			if p.exclude[other] {
				return 0
			}
		}
		return 0.55
	}
	return 0
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

var keyLike = regexp.MustCompile(`^[A-Za-z_\p{L}][\p{L}A-Za-z0-9_.\-]{0,47}$`)

// Key classifies a string literal used as a key ("email",
// "phone_number", "user.phone"). Free text is rejected.
func (c *Classifier) Key(s string) (Match, bool) {
	if !keyLike.MatchString(s) {
		return Match{}, false
	}
	m, ok := c.Ident(s)
	if ok {
		m.Conf -= 0.1
	}
	return m, ok
}

// Getter classifies accessor names such as getEmail, getPhoneNumber or
// Email (Go style) that take no arguments.
func (c *Classifier) Getter(name string) (Match, bool) {
	base := name
	switch {
	case len(name) > 3 && strings.HasPrefix(name, "get") && isUpper(name[3]):
		base = name[3:]
	case len(name) > 3 && strings.HasPrefix(name, "Get") && isUpper(name[3]):
		base = name[3:]
	}
	m, ok := c.Ident(base)
	if ok {
		m.Conf -= 0.05
	}
	return m, ok
}

func isUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// Entity words suggest that a bare "name" field on the type is a person name.
var personEntities = set("user", "customer", "person", "member", "employee", "patient", "account", "profile", "contact",
	"applicant", "student", "teacher", "driver", "passenger", "guest", "subscriber", "buyer", "seller", "owner",
	"cardholder", "holder", "recipient")

// Field classifies obj.field using the owner type (or the object variable
// name) as extra context.
func (c *Classifier) Field(owner, field string) (Match, bool) {
	if m, ok := c.Ident(field); ok {
		return m, true
	}
	ft := Tokenize(field)
	if len(ft) == 1 && ft[0] == "name" && owner != "" {
		ot := Tokenize(lastSegment(owner))
		for _, t := range ot {
			if personEntities[c.singular(t)] {
				return Match{DataType: "person_name", Conf: 0.6, Pattern: "entity name"}, true
			}
		}
	}
	return Match{}, false
}

func lastSegment(s string) string {
	s = strings.TrimLeft(s, "*[]&")
	if i := strings.LastIndexAny(s, "./"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ContextTypes returns the data types mentioned anywhere in a line of text,
// ignoring the negative rules. The literal detector uses it to raise
// confidence when a value sits next to its label ("cccd": "0010...").
func (c *Classifier) ContextTypes(line string) map[string]bool {
	toks := Tokenize(line)
	if len(toks) == 0 {
		return nil
	}
	for i, t := range toks {
		toks[i] = c.singular(t)
	}
	out := map[string]bool{}
	for _, p := range c.patterns {
		if p.weak && len(p.toks) == 1 && len(p.joined) < 3 {
			continue
		}
		if findSeq(toks, p.toks) >= 0 {
			out[p.dt.ID] = true
		}
	}
	return out
}

var transformFuncWords = map[string]string{
	"mask": "masked", "masked": "masked", "redact": "redacted", "redacted": "redacted", "scrub": "redacted",
	"anonymize": "anonymized", "anonymise": "anonymized", "pseudonymize": "pseudonymized", "pseudonymise": "pseudonymized",
	"hash": "hashed", "hashed": "hashed", "digest": "hashed", "sha256": "sha256", "sha512": "sha512", "sha1": "sha1", "md5": "md5",
	"hmac": "hmac", "encrypt": "encrypted", "seal": "encrypted", "obfuscate": "masked", "tokenize": "tokenized", "truncate": "masked",
	"bcrypt": "hashed", "argon2": "hashed", "scrypt": "hashed",
}

var notTransformFunc = set("map", "set", "table", "code", "tag", "tags", "bucket", "ring", "key", "keys", "mapof", "setof", "equals", "compare", "verify", "check", "valid", "is", "unmask", "decrypt")

// FuncTransform recognises sanitizer-like function names: maskPhone ->
// masked, hashEmail -> hashed, sha256Hex -> sha256.
func (c *Classifier) FuncTransform(name string) string { return TransformFromFuncName(name) }

// TransformFromFuncName is FuncTransform without a classifier (it does not
// depend on the taxonomy).
func TransformFromFuncName(name string) string {
	toks := Tokenize(name)
	for _, t := range toks {
		if notTransformFunc[t] {
			return ""
		}
	}
	for _, t := range withDigitJoins(toks) {
		if x, ok := transformFuncWords[t]; ok {
			return x
		}
	}
	return ""
}

// withDigitJoins adds "sha"+"256" style joins, since the tokenizer splits
// letters from digits.
func withDigitJoins(toks []string) []string {
	out := toks
	for i := 0; i+1 < len(toks); i++ {
		if isDigits(toks[i+1]) && !isDigits(toks[i]) {
			if out == nil || len(out) == len(toks) {
				out = append([]string{}, toks...)
			}
			out = append(out, toks[i]+toks[i+1])
		}
	}
	return out
}
