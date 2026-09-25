// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"github.com/GoNetTools/datawarden/internal/frontend"
	"github.com/GoNetTools/datawarden/internal/lang"
)

// Register adds the tree-sitter frontends to a registry.
func Register(r frontend.Registrar) {
	factories := map[string]frontend.Factory{
		lang.Java:       NewJava,
		lang.Kotlin:     NewKotlin,
		lang.Python:     NewPython,
		lang.Swift:      NewSwift,
		lang.TypeScript: NewTypeScript,
	}
	for _, l := range Languages() {
		r.Register(l, factories[l])
	}
}
