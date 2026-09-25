// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package treesitter

import "github.com/GoNetTools/pii-scanner/internal/lang"

// Languages are the languages this package provides frontends for. Register
// adds them (cgo builds) or records them as unavailable (CGO_ENABLED=0).
func Languages() []string {
	return []string{lang.Java, lang.Kotlin, lang.TypeScript}
}
