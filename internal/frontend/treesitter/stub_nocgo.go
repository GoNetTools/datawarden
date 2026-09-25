// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

// Package treesitter provides the Kotlin, Java and TypeScript frontends.
// They need cgo; in CGO_ENABLED=0 builds Register records them as
// unavailable so the Go frontend and the literal detector keep working.
package treesitter

import "github.com/GoNetTools/pii-scanner/internal/frontend"

// Register records the tree-sitter languages as unavailable.
func Register(r frontend.Registrar) {
	const why = "this pii-scanner binary was built without cgo; use a release binary or the Docker image for Kotlin/Java/TypeScript"
	for _, l := range Languages() {
		r.RegisterUnavailable(l, why)
	}
}
