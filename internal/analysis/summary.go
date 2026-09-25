// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
}

// RealFact is concrete PII produced inside a function.
type RealFact struct {
	DataType string   `json:"dt"`
	Desc     string   `json:"desc"`
	Src      ir.Pos   `json:"src"`
	Path     []ir.Pos `json:"p,omitempty"`
	Xf       []string `json:"xf,omitempty"`
	Conf     float64  `json:"c"`
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
		if xfKey(list[i].Xf) == xfKey(t.Xf) {
			if t.Conf > list[i].Conf {
				list[i] = t
			}
			return list
		}
	}
	if len(list) >= maxPerSlot {
		return list
	}
	return append(list, t)
}

func (s *Summary) addParamSink(i int, h SinkHit) {
	if s.ParamSink == nil {
		s.ParamSink = map[int][]SinkHit{}
	}
	list := s.ParamSink[i]
	k := h.Rule + "|" + h.Sink.String() + "|" + xfKey(h.Xf)
	for j := range list {
		if list[j].Rule+"|"+list[j].Sink.String()+"|"+xfKey(list[j].Xf) == k {
			if h.Conf > list[j].Conf {
				list[j] = h
			}
			return
		}
	}
	if len(list) < maxPerSlot*2 {
		s.ParamSink[i] = append(list, h)
	}
}

func mergeReal(list []RealFact, f RealFact) []RealFact {
	k := f.DataType + "|" + xfKey(f.Xf)
	for i := range list {
		if list[i].DataType+"|"+xfKey(list[i].Xf) == k {
			if f.Conf > list[i].Conf {
				list[i] = f
			}
			return list
		}
	}
	if len(list) >= maxPerSlot {
		return list
	}
	return append(list, f)
}

func (s *Summary) addParamOut(i int, f RealFact) {
	if s.ParamOut == nil {
		s.ParamOut = map[int][]RealFact{}
	}
	s.ParamOut[i] = mergeReal(s.ParamOut[i], f)
}

func (s *Summary) addReturnFact(f RealFact) { s.ReturnFacts = mergeReal(s.ReturnFacts, f) }

// Empty reports whether the summary carries no information.
func (s *Summary) Empty() bool {
	return s == nil || (len(s.ParamReturn) == 0 && len(s.ParamSink) == 0 && len(s.ParamParam) == 0 && len(s.ParamOut) == 0 && len(s.ReturnFacts) == 0)
}

func (s *Summary) normalize() {
	for _, l := range s.ParamSink {
		sort.Slice(l, func(a, b int) bool {
			if l[a].Rule != l[b].Rule {
				return l[a].Rule < l[b].Rule
			}
			return l[a].Sink.String() < l[b].Sink.String()
		})
	}
	sort.Slice(s.ReturnFacts, func(a, b int) bool {
		return s.ReturnFacts[a].DataType+xfKey(s.ReturnFacts[a].Xf) < s.ReturnFacts[b].DataType+xfKey(s.ReturnFacts[b].Xf)
	})
	for _, l := range s.ParamOut {
		sort.Slice(l, func(a, b int) bool { return l[a].DataType+xfKey(l[a].Xf) < l[b].DataType+xfKey(l[b].Xf) })
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
