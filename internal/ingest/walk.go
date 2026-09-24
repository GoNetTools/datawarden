// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Language identifiers used across the pipeline.
const (
	LangGo         = "go"
	LangKotlin     = "kotlin"
	LangJava       = "java"
	LangTypeScript = "typescript"
	LangProto      = "proto"
	LangSQL        = "sql"
)

// File is a repository file selected for scanning.
type File struct {
	Rel  string // slash-separated, relative to the repository root
	Lang string // "" for non-code text files
	Test bool   // test/fixture source file
	Size int64
}

// MaxFileSize bounds what is read for literal scanning.
const MaxFileSize = 2 << 20

// LangOf classifies a path by extension.
func LangOf(rel string) string {
	switch strings.ToLower(path.Ext(rel)) {
	case ".go":
		return LangGo
	case ".kt", ".kts":
		return LangKotlin
	case ".java":
		return LangJava
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts":
		if strings.HasSuffix(rel, ".d.ts") {
			return ""
		}
		return LangTypeScript
	case ".proto":
		return LangProto
	case ".sql":
		return LangSQL
	}
	return ""
}

// IsTestPath reports whether a source file is test code.
func IsTestPath(rel string) bool {
	base := path.Base(rel)
	switch {
	case strings.HasSuffix(base, "_test.go"):
		return true
	case strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasSuffix(base, "Test.kt") || strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Tests.java") || strings.HasSuffix(base, "Tests.kt"):
		return true
	}
	p := "/" + rel
	for _, d := range []string{"/src/test/", "/src/androidTest/", "/src/testDebug/", "/__tests__/", "/__mocks__/", "/testdata/", "/e2e/", "/cypress/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	return false
}

// GoIgnoredDir reports whether the go tool ignores the file's directory
// (a path element starting with "." or "_", or named "testdata").
func GoIgnoredDir(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range parts[:len(parts)-1] {
		if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "_") || p == "testdata" {
			return true
		}
	}
	return false
}

// Walk lists files in the repository file system that are not ignored.
func Walk(fsys fs.FS, m *Matcher) ([]File, error) {
	var out []File
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			return nil
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if m.IgnoredDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || m.IgnoredFile(p) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, File{Rel: p, Lang: LangOf(p), Test: IsTestPath(p), Size: info.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, err
}

// Select keeps the walked files named by paths: slash-separated, relative
// to the repository root, each a file or a directory ("." selects all).
func Select(fsys fs.FS, all []File, paths []string) []File {
	if len(paths) == 0 {
		return all
	}
	var prefixes []string
	exact := map[string]bool{}
	for _, p := range paths {
		p = path.Clean(strings.TrimPrefix(p, "./"))
		if p == "." {
			return all
		}
		if st, err := fs.Stat(fsys, p); err == nil && st.IsDir() {
			prefixes = append(prefixes, p+"/")
		} else {
			exact[p] = true
		}
	}
	var out []File
	for _, f := range all {
		if exact[f.Rel] {
			out = append(out, f)
			continue
		}
		for _, pre := range prefixes {
			if strings.HasPrefix(f.Rel, pre) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// Hasher memoizes content hashes of repository files.
type Hasher struct {
	fsys  fs.FS
	cache map[string]string
}

// NewHasher returns a Hasher reading from fsys.
func NewHasher(fsys fs.FS) *Hasher { return &Hasher{fsys: fsys, cache: map[string]string{}} }

// Hash returns the content hash of a root-relative file ("" if missing).
func (h *Hasher) Hash(rel string) string {
	if v, ok := h.cache[rel]; ok {
		return v
	}
	v := ""
	if b, err := fs.ReadFile(h.fsys, rel); err == nil {
		sum := sha256.Sum256(b)
		v = hex.EncodeToString(sum[:16])
	}
	h.cache[rel] = v
	return v
}
