// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	"github.com/GoNetTools/pii-scanner/internal/frontend"
	"github.com/GoNetTools/pii-scanner/internal/lang"
)

// Register adds the Kotlin, Java and TypeScript frontends to a registry.
func Register(r *frontend.Registry) {
	factories := map[string]frontend.Factory{
		lang.Java:       NewJava,
		lang.Kotlin:     NewKotlin,
		lang.TypeScript: NewTypeScript,
	}
	for _, l := range Languages() {
		r.Register(l, factories[l])
	}
}
