// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package ingest walks a repository, applies .datawardenignore, classifies
// files by language and computes the file set for PR scans.
package ingest

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"regexp"
	"strings"
)

// IgnoreFile is the name of the per-repository ignore file.
const IgnoreFile = ".datawardenignore"

// DefaultIgnore is applied before .datawardenignore, so a repository can
// re-include any of these with a "!" pattern.
var DefaultIgnore = []string{
	".git/", ".hg/", ".svn/", "node_modules/", "bower_components/", "vendor/", "Pods/", "Carthage/",
	"build/", "dist/", "out/", "target/", ".gradle/", ".idea/", ".vscode/", ".next/", ".nuxt/", ".expo/",
	"coverage/", ".cache/", ".terraform/", "__pycache__/", ".venv/", "venv/", ".datawarden/cache/",
	".datawarden/rules/examples/", // planted leaks for `datawarden rules test`
	"*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json", "pnpm-lock.yaml", "go.sum", "gradle.lockfile",
	"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.bmp", "*.tiff", "*.svg", "*.mp3", "*.mp4", "*.mov", "*.webm", "*.wav",
	"*.ttf", "*.otf", "*.woff", "*.woff2", "*.eot", "*.zip", "*.gz", "*.tgz", "*.bz2", "*.xz", "*.7z", "*.rar", "*.jar", "*.aar",
	"*.apk", "*.aab", "*.ipa", "*.dex", "*.so", "*.dylib", "*.dll", "*.exe", "*.class", "*.o", "*.a", "*.pdf", "*.keystore", "*.jks",
	"*.pb", "*.bin", "*.db", "*.sqlite", "*.realm", "*.onnx", "*.tflite",
}

type ignoreRule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// Matcher implements gitignore-style matching.
type Matcher struct {
	rules []ignoreRule
}

// NewMatcher compiles patterns in gitignore syntax.
func NewMatcher(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.add(p)
	}
	return m
}

// LoadMatcher returns the default patterns plus the repository's
// .datawardenignore (if any), read from the repository file system.
func LoadMatcher(fsys fs.FS) (*Matcher, error) {
	m := NewMatcher(DefaultIgnore)
	b, err := fs.ReadFile(fsys, IgnoreFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return m, nil
		}
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		m.add(sc.Text())
	}
	return m, sc.Err()
}

func (m *Matcher) add(line string) {
	line = strings.TrimRight(line, "\r")
	if !strings.HasSuffix(line, `\ `) {
		line = strings.TrimRight(line, " \t")
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	r := ignoreRule{}
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return
	}
	re, err := regexp.Compile(globRegexp(line, anchored))
	if err != nil {
		return
	}
	r.re = re
	m.rules = append(m.rules, r)
}

func globRegexp(p string, anchored bool) string {
	var b strings.Builder
	if anchored {
		b.WriteString("^")
	} else {
		b.WriteString("^(?:.*/)?")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "/**") && i+3 == len(p):
			b.WriteString("/.*")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			j := strings.IndexByte(p[i+1:], ']')
			if j < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := p[i+1 : i+1+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += j + 1
		case c == '\\' && i+1 < len(p):
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// matchOne applies rules to a single path (not its ancestors).
func (m *Matcher) matchOne(rel string, isDir bool) (ignored, decided bool) {
	for i := len(m.rules) - 1; i >= 0; i-- {
		r := m.rules[i]
		if r.dirOnly && !isDir {
			continue
		}
		if r.re.MatchString(rel) {
			return !r.negate, true
		}
	}
	return false, false
}

// Ignored reports whether the slash-separated relative path is ignored,
// taking ignored ancestor directories into account.
func (m *Matcher) Ignored(rel string, isDir bool) bool {
	rel = strings.Trim(rel, "/")
	if rel == "" || rel == "." {
		return false
	}
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		if ig, _ := m.matchOne(strings.Join(parts[:i], "/"), true); ig {
			return true
		}
	}
	ig, _ := m.matchOne(rel, isDir)
	return ig
}

// IgnoredDir is the fast path used while walking: ancestors were already
// checked by the walker.
func (m *Matcher) IgnoredDir(rel string) bool {
	ig, _ := m.matchOne(rel, true)
	return ig
}

// IgnoredFile is the fast path used while walking.
func (m *Matcher) IgnoredFile(rel string) bool {
	ig, _ := m.matchOne(rel, false)
	return ig
}
