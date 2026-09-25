// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/app"
)

// With cgo, the production wiring registers the tree-sitter frontends.
func TestProductionWiringHasAllFrontends(t *testing.T) {
	var out, errb bytes.Buffer
	if code := app.New(&out, &errb).Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "frontends: go, java, kotlin, typescript") {
		t.Errorf("version: %s", out.String())
	}
}
