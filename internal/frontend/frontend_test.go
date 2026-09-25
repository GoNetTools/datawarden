// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package frontend

import (
	"context"
	"strings"
	"testing"

	"github.com/GoNetTools/pii-scanner/internal/ir"
)

type stubFE struct{ o Options }

func (stubFE) Lang() string { return "go" }
func (stubFE) Lower(context.Context, []string) (*ir.Module, error) {
	return &ir.Module{}, nil
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.RegisterUnavailable("kotlin", "built without cgo")
	r.Register("go", func(o Options) Frontend { return stubFE{o} })
	fe, err := r.Frontend("go", Options{Root: "/repo"})
	if err != nil || fe.(stubFE).o.Root != "/repo" {
		t.Fatalf("go: %v", err)
	}
	if _, err := r.Frontend("kotlin", Options{}); err == nil || !strings.Contains(err.Error(), "cgo") {
		t.Errorf("unavailable: %v", err)
	}
	if _, err := r.Frontend("swift", Options{}); err == nil {
		t.Error("unregistered language returned a frontend")
	}
	r.Register("kotlin", func(o Options) Frontend { return stubFE{o} })
	if got := strings.Join(r.Languages(), ","); got != "go,kotlin" {
		t.Errorf("languages = %s", got)
	}
}
