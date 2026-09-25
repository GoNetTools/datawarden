// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package finding

import "testing"

func TestIsNew(t *testing.T) {
	for _, c := range []struct {
		violation, baselined, want bool
	}{{true, false, true}, {true, true, false}, {false, false, false}} {
		f := &Flow{Violation: c.violation, Baselined: c.baselined}
		l := &Literal{Violation: c.violation, Baselined: c.baselined}
		if f.IsNew() != c.want || l.IsNew() != c.want {
			t.Errorf("%+v: flow %v literal %v", c, f.IsNew(), l.IsNew())
		}
	}
}
