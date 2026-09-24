// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import "github.com/GoNetTools/pii-scanner/internal/frontend"

// Register adds the Kotlin, Java and TypeScript frontends to a registry.
func Register(r *frontend.Registry) {
	r.Register("kotlin", NewKotlin)
	r.Register("java", NewJava)
	r.Register("typescript", NewTypeScript)
}
