// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// Transfer describes a value moving from a parameter to the return value
// (or into another parameter) inside a function.
type Transfer struct {
	Xf   []string `json:"xf,omitempty"`
	Conf float64  `json:"c"`
	Path []ir.Pos `json:"p,omitempty"`
	// Field is set when only that field of the source parameter moves
	// (return this.email), not the whole value.
	Field string `json:"f,omitempty"`
	// DstField is set when the value is stored into that field of the
	// destination parameter (this.addr = email in a constructor).
	DstField string `json:"df,omitempty"`
}

// SinkHit is a sink reached from a parameter.
type SinkHit struct {
	Rule string              `json:"rule"`
	Dest finding.Destination `json:"dest"`
	Sink ir.Pos              `json:"sink"`
	Func string              `json:"func"`
	Call string              `json:"call,omitempty"`
	Lang string              `json:"lang"`
	Path []ir.Pos            `json:"p,omitempty"`
	Xf   []string            `json:"xf,omitempty"`
	Conf float64             `json:"c"`
	// Field is set when a field of the parameter reaches the sink
	// (log(this.addr)), not the parameter itself.
	Field string `json:"f,omitempty"`
	// Guards are the consent checks that must pass for the sink to run.
	Guards []string `json:"g,omitempty"`
}

// RealFact is concrete PII produced inside a function.
type RealFact struct {
	DataType string   `json:"dt"`
	Desc     string   `json:"desc"`
	Src      ir.Pos   `json:"src"`
	Path     []ir.Pos `json:"p,omitempty"`
	Xf       []string `json:"xf,omitempty"`
	Conf     float64  `json:"c"`
	// DstField is set when the value is stored into that field of the
	// parameter (ParamOut).
	DstField string `json:"df,omitempty"`
}

// Summary is the externally visible taint behaviour of a function. It is
// what callers use instead of re-analyzing the callee, and what the cache
// stores between runs.
type Summary struct {
	// ParamReturn[i]: parameter i reaches the return value.
	ParamReturn map[int][]Transfer `json:"pr,omitempty"`
	// ParamSink[i]: parameter i reaches a sink.
	ParamSink map[int][]SinkHit `json:"ps,omitempty"`
	// ParamParam[dst][src]: parameter src is stored into parameter dst.
	ParamParam map[int]map[int][]Transfer `json:"pp,omitempty"`
	// ParamOut[i]: PII produced inside the function is stored into parameter i.
	ParamOut map[int][]RealFact `json:"po,omitempty"`
	// ReturnFacts: PII produced inside the function is returned.
	ReturnFacts []RealFact `json:"rf,omitempty"`
	// ParamThrow[i]: parameter i reaches an exception the function throws.
	ParamThrow map[int][]Transfer `json:"pt,omitempty"`
	// ThrowFacts: PII produced inside the function is in an exception it
	// throws.
	ThrowFacts []RealFact `json:"tf,omitempty"`
}

const maxPerSlot = 24

func xfKey(x []string) string { return strings.Join(x, ",") }

func (s *Summary) addParamReturn(i int, t Transfer) {
	if s.ParamReturn == nil {
		s.ParamReturn = map[int][]Transfer{}
	}
	s.ParamReturn[i] = mergeTransfer(s.ParamReturn[i], t)
}

func (s *Summary) addParamParam(dst, src int, t Transfer) {
	if s.ParamParam == nil {
		s.ParamParam = map[int]map[int][]Transfer{}
	}
	if s.ParamParam[dst] == nil {
		s.ParamParam[dst] = map[int][]Transfer{}
	}
	s.ParamParam[dst][src] = mergeTransfer(s.ParamParam[dst][src], t)
}

func mergeTransfer(list []Transfer, t Transfer) []Transfer {
	for i := range list {
		if xfKey(list[i].Xf) == xfKey(t.Xf) && list[i].Field == t.Field && list[i].DstField == t.DstField {
			if compareTransfer(t, list[i]) < 0 {
				list[i] = t
			}
			return list
		}
	}
	return capped(list, t, maxPerSlot, compareTransfer)
}

func (s *Summary) addParamSink(i int, h SinkHit) {
	if s.ParamSink == nil {
		s.ParamSink = map[int][]SinkHit{}
	}
	list := s.ParamSink[i]
	for j := range list {
		if o := &list[j]; o.Rule == h.Rule && o.Sink == h.Sink && o.Field == h.Field && slices.Equal(o.Xf, h.Xf) {
			// An unguarded path outweighs a guarded one.
			if compareSinkHits(h, list[j]) < 0 {
				list[j] = h
			}
			return
		}
	}
	s.ParamSink[i] = capped(list, h, maxPerSlot*2, compareSinkHits)
}

func mergeReal(list []RealFact, f RealFact) []RealFact {
	k := f.DataType + "|" + xfKey(f.Xf) + "|" + f.DstField
	for i := range list {
		if list[i].DataType+"|"+xfKey(list[i].Xf)+"|"+list[i].DstField == k {
			if compareReal(f, list[i]) < 0 {
				list[i] = f
			}
			return list
		}
	}
	return capped(list, f, maxPerSlot, compareReal)
}

func (s *Summary) addParamOut(i int, f RealFact) {
	if s.ParamOut == nil {
		s.ParamOut = map[int][]RealFact{}
	}
	s.ParamOut[i] = mergeReal(s.ParamOut[i], f)
}

func (s *Summary) addReturnFact(f RealFact) { s.ReturnFacts = mergeReal(s.ReturnFacts, f) }

func (s *Summary) addParamThrow(i int, t Transfer) {
	if s.ParamThrow == nil {
		s.ParamThrow = map[int][]Transfer{}
	}
	s.ParamThrow[i] = mergeTransfer(s.ParamThrow[i], t)
}

func (s *Summary) addThrowFact(f RealFact) { s.ThrowFacts = mergeReal(s.ThrowFacts, f) }

// Empty reports whether the summary carries no information.
func (s *Summary) Empty() bool {
	return s == nil || (len(s.ParamReturn) == 0 && len(s.ParamSink) == 0 && len(s.ParamParam) == 0 && len(s.ParamOut) == 0 && len(s.ReturnFacts) == 0 &&
		len(s.ParamThrow) == 0 && len(s.ThrowFacts) == 0)
}

func (s *Summary) normalize() {
	for _, l := range s.ParamSink {
		sort.Slice(l, func(a, b int) bool {
			if l[a].Rule != l[b].Rule {
				return l[a].Rule < l[b].Rule
			}
			if l[a].Sink.String() != l[b].Sink.String() {
				return l[a].Sink.String() < l[b].Sink.String()
			}
			if l[a].Field != l[b].Field {
				return l[a].Field < l[b].Field
			}
			return xfKey(l[a].Guards) < xfKey(l[b].Guards)
		})
	}
	byKey := func(l []Transfer) {
		sort.Slice(l, func(a, b int) bool {
			return xfKey(l[a].Xf)+"|"+l[a].Field+"|"+l[a].DstField < xfKey(l[b].Xf)+"|"+l[b].Field+"|"+l[b].DstField
		})
	}
	for _, l := range s.ParamReturn {
		byKey(l)
	}
	for _, l := range s.ParamThrow {
		byKey(l)
	}
	sort.Slice(s.ThrowFacts, func(a, b int) bool {
		return s.ThrowFacts[a].DataType+xfKey(s.ThrowFacts[a].Xf) < s.ThrowFacts[b].DataType+xfKey(s.ThrowFacts[b].Xf)
	})
	for _, m := range s.ParamParam {
		for _, l := range m {
			byKey(l)
		}
	}
	sort.Slice(s.ReturnFacts, func(a, b int) bool {
		return s.ReturnFacts[a].DataType+xfKey(s.ReturnFacts[a].Xf) < s.ReturnFacts[b].DataType+xfKey(s.ReturnFacts[b].Xf)
	})
	for _, l := range s.ParamOut {
		sort.Slice(l, func(a, b int) bool {
			return l[a].DataType+xfKey(l[a].Xf)+"|"+l[a].DstField < l[b].DataType+xfKey(l[b].Xf)+"|"+l[b].DstField
		})
	}
}

// Digest is a stable hash of the summary.
func (s *Summary) Digest() string {
	if s == nil {
		return "nil"
	}
	s.normalize()
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
