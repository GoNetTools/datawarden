// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"

	"github.com/GoNetTools/datawarden/internal/cicomment"
	"github.com/GoNetTools/datawarden/internal/cli"
)

// On a push build there is no pull request: the adapter reports the CLI's
// sentinel, so `datawarden comment` skips posting instead of failing.
// Other errors pass through.
func TestCommenterMapsNotInReview(t *testing.T) {
	push := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "acme/app"}
	c := commenter{cicomment.Client{Getenv: func(k string) string { return push[k] }}}
	if _, err := c.Post("body"); !errors.Is(err, cli.ErrNotInReview) {
		t.Errorf("push build: err = %v, want cli.ErrNotInReview", err)
	}
	local := commenter{cicomment.Client{Getenv: func(string) string { return "" }}}
	if _, err := local.Post("body"); err == nil || errors.Is(err, cli.ErrNotInReview) {
		t.Errorf("outside CI: err = %v, want the client's own error", err)
	}
}
