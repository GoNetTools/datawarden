// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"cmp"
	"slices"

	"github.com/GoNetTools/datawarden/internal/finding"
	"github.com/GoNetTools/datawarden/internal/ir"
)

// The analysis keeps one fact per slot (a variable's facts by data type,
// a summary's entries by key) and caps some lists. Which of two candidates
// it keeps must not depend on the order they arrive in, which follows Go's
// randomised map iteration: otherwise two scans of the same code report
// different sources, paths or even flows. These comparisons give every
// kind of candidate a total order: higher confidence first, then the
// earliest source, the shortest path, and the rest of the fields.

func comparePos(a, b ir.Pos) int {
	return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Col, b.Col))
}

// comparePath orders shorter paths first, then position by position.
func comparePath(a, b []ir.Pos) int {
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	for i := range a {
		if c := comparePos(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

func compareStrings(a, b []string) int {
	return slices.Compare(a, b)
}

// compareFacts orders facts by preference: a negative result means a is
// kept over b.
func compareFacts(a, b *fact) int {
	return cmp.Or(
		-cmp.Compare(a.conf, b.conf),
		// A fact seeded on the variable by its own name or type stays
		// ahead of one that reached it: summaries leave seeds out, since
		// callers see the same name or type themselves.
		compareBool(a.seed, b.seed),
		comparePos(a.src, b.src),
		comparePath(a.path, b.path),
		cmp.Compare(a.desc, b.desc),
		cmp.Compare(a.dt, b.dt),
		cmp.Compare(a.param, b.param),
		cmp.Compare(a.field, b.field),
		cmp.Compare(a.stored, b.stored),
		cmp.Compare(a.at, b.at),
		compareStrings(a.xf, b.xf),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}

// betterFact reports whether f should replace old in its slot.
func betterFact(f, old *fact) bool { return compareFacts(f, old) < 0 }

func compareReal(a, b RealFact) int {
	return cmp.Or(
		-cmp.Compare(a.Conf, b.Conf),
		comparePos(a.Src, b.Src),
		comparePath(a.Path, b.Path),
		cmp.Compare(a.Desc, b.Desc),
		cmp.Compare(a.DataType, b.DataType),
		compareStrings(a.Xf, b.Xf),
		cmp.Compare(a.DstField, b.DstField),
	)
}

func compareTransfer(a, b Transfer) int {
	return cmp.Or(
		-cmp.Compare(a.Conf, b.Conf),
		comparePath(a.Path, b.Path),
		compareStrings(a.Xf, b.Xf),
		cmp.Compare(a.Field, b.Field),
		cmp.Compare(a.DstField, b.DstField),
	)
}

// compareSinkHits prefers an unguarded path, then the more confident one,
// then the rest of the fields.
func compareSinkHits(a, b SinkHit) int {
	return cmp.Or(
		compareBool(len(a.Guards) == 0, len(b.Guards) == 0),
		-cmp.Compare(a.Conf, b.Conf),
		comparePath(a.Path, b.Path),
		cmp.Compare(a.Rule, b.Rule),
		comparePos(a.Sink, b.Sink),
		cmp.Compare(a.Func, b.Func),
		cmp.Compare(a.Call, b.Call),
		cmp.Compare(a.Field, b.Field),
		compareStrings(a.Xf, b.Xf),
		compareStrings(a.Guards, b.Guards),
		cmp.Compare(a.Lang, b.Lang),
		cmp.Compare(a.Dest.Kind+"|"+a.Dest.Host+"|"+a.Dest.Vendor, b.Dest.Kind+"|"+b.Dest.Host+"|"+b.Dest.Vendor),
	)
}

// capped adds x to a list holding at most n entries, keeping the n best by
// compare: a full list drops its worst entry when x is better.
func capped[T any](list []T, x T, n int, compare func(a, b T) int) []T {
	if len(list) < n {
		return append(list, x)
	}
	worst := 0
	for i := range list {
		if compare(list[i], list[worst]) > 0 {
			worst = i
		}
	}
	if compare(x, list[worst]) < 0 {
		list[worst] = x
	}
	return list
}

// compareFlows orders two flows reported for the same data type, sink
// and transforms: an unguarded one first, then the more confident, then
// the earliest source and the shortest path.
func compareFlows(a, b *finding.Flow) int {
	return cmp.Or(
		compareBool(len(a.Guards) == 0, len(b.Guards) == 0),
		-cmp.Compare(a.Confidence, b.Confidence),
		comparePos(a.Source, b.Source),
		comparePath(a.Path, b.Path),
		cmp.Compare(a.SourceDesc, b.SourceDesc),
		compareStrings(a.Guards, b.Guards),
		cmp.Compare(a.SinkCall, b.SinkCall),
	)
}
