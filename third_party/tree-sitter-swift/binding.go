// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

// Package tsswift is the tree-sitter Swift grammar, generated sources of
// alex-pinkus/tree-sitter-swift 0.5.0 (MIT, see LICENSE and README.md).
// That release has no Go bindings, and every newer one parses real code
// worse, so its generated parser is kept here.
package tsswift

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_swift(void);
import "C"

import "unsafe"

// Language returns the grammar, for tree_sitter.NewLanguage.
func Language() unsafe.Pointer {
	return unsafe.Pointer(C.tree_sitter_swift())
}
