// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strconv"
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// Heuristics are the word lists the engine falls back on for code no
// rule describes: by table name, a list of words (Words, Has) or a map
// from a word to a value (Lookup). Implemented by *rules.Heuristics; the
// tables are named below.
type Heuristics interface {
	Words(table string) []string
	Has(table, word string) bool
	Lookup(table, key string) (string, bool)
}

// The heuristic tables the engine reads (builtin/heuristics.yaml
// documents each one).
const (
	tGetterVerbs        = "getter_verbs"
	tWholeValueFields   = "whole_value_fields"
	tWholeValueMethods  = "whole_value_methods"
	tDataFreeSuffixes   = "data_free_suffixes"
	tDataFreeCalls      = "data_free_calls"
	tPublicParts        = "public_parts"
	tRequestMethods     = "request_methods"
	tLoaderMethods      = "loader_methods"
	tSelfDescribing     = "self_describing"
	tStringers          = "stringers"
	tPlaceholders       = "placeholders"
	tHandleTypes        = "handle_types"
	tMutatorPrefixes    = "mutator_prefixes"
	tDecodeInto         = "decode_into"
	tImmediateCallbacks = "immediate_callbacks"
	tTransformChecks    = "transform_checks"
	tPiiDetectors       = "pii_detectors"
	tContainerOps       = "container_ops"
	tContainerBuilders  = "container_builders"
	tConsentWords       = "consent_words"
	tLabelStopWords     = "label_stop_words"
)

// heuristicTables lists every table the engine reads, so a test can check
// each one against the loaded heuristics.
var heuristicTables = []string{tGetterVerbs, tWholeValueFields, tWholeValueMethods, tDataFreeSuffixes, tDataFreeCalls, tPublicParts,
	tRequestMethods, tLoaderMethods, tSelfDescribing, tStringers, tPlaceholders, tHandleTypes, tMutatorPrefixes, tDecodeInto,
	tImmediateCallbacks, tTransformChecks, tPiiDetectors, tContainerOps, tContainerBuilders, tConsentWords, tLabelStopWords}

// noHeuristics is the engine's fallback when none are given: every table
// is empty.
type noHeuristics struct{}

func (noHeuristics) Words(string) []string                { return nil }
func (noHeuristics) Has(string, string) bool              { return false }
func (noHeuristics) Lookup(string, string) (string, bool) { return "", false }

// words answers the engine's questions about names from the heuristics.
// A zero words value (no heuristics) answers no.
type words struct{ h Heuristics }

func (w words) src() Heuristics {
	if w.h == nil {
		return noHeuristics{}
	}
	return w.h
}

func (w words) has(table, word string) bool             { return w.src().Has(table, word) }
func (w words) list(table string) []string              { return w.src().Words(table) }
func (w words) lookup(table, key string) (string, bool) { return w.src().Lookup(table, key) }

// isGetterName reports whether a method name reads a value: getEmail,
// optString, formValue.
func (w words) isGetterName(name string) bool {
	n := strings.ToLower(name)
	for _, v := range w.list(tGetterVerbs) {
		if strings.HasPrefix(n, v) {
			return true
		}
	}
	return false
}

// dataFreeName reports whether a variable name says it holds a status, a
// count or a flag computed from data, not the data: derivationStatus,
// rowCount.
func (w words) dataFreeName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range w.list(tDataFreeSuffixes) {
		if n == s || strings.HasSuffix(n, s) && len(n) > len(s) && (n[len(n)-len(s)-1] == '_' || name[len(name)-len(s)] >= 'A' && name[len(name)-len(s)] <= 'Z') {
			return true
		}
	}
	return false
}

// notData reports whether a literal cannot be the data its key names:
// empty, a number, a boolean or a placeholder. A hard-coded
// putString("password", "hunter2") is the secret itself.
func (w words) notData(lit string) bool {
	t := strings.ToLower(strings.TrimSpace(lit))
	if t == "" || w.has(tPlaceholders, t) {
		return true
	}
	_, err := strconv.ParseFloat(t, 64)
	return err == nil
}

// handleType reports whether t is a connection, client, router or logger
// type: the data a query or request is given does not change it.
func (w words) handleType(t string) bool {
	return t != "" && w.has(tHandleTypes, strings.TrimLeft(t, "*&"))
}

// isMutator reports whether a method on an unknown receiver plausibly
// stores its arguments into the receiver (builders, collections, bundles).
func (w words) isMutator(name string) bool {
	n := strings.ToLower(name)
	for _, p := range w.list(tMutatorPrefixes) {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// readsPart reports whether an unresolved method call on an object may
// return what the object's part (field or key) holds: a read with that
// constant key (ctx.Get("user")), a read with a key not known here, a
// method named after the part (getEmail() for email), or one rendering
// the whole object (toString()). ctx.ClientIP() does not return the user
// put under "user".
func (w words) readsPart(fn *ir.Func, defs []int, in *ir.Instr, part string) bool {
	name := strings.ToLower(in.Call.Name)
	if !w.isGetterName(name) && w.isMutator(name) {
		return true // a builder call returns its receiver
	}
	if len(in.Args) > 1 {
		k, ok := constOf(fn, defs, in.Args[1])
		return !ok || k == part || normName(k) == normName(part)
	}
	if w.has(tWholeValueMethods, name) {
		return true
	}
	p := normName(part)
	return p != "" && strings.Contains(normName(name), p)
}

// runsCallbackNow reports whether the callee runs the closure it is
// given before returning (forEach, map, apply, sort.Slice).
func (w words) runsCallbackNow(c *ir.Call) bool {
	return c != nil && w.has(tImmediateCallbacks, strings.ToLower(c.Name))
}

// runsReceiver reports whether a method call on a receiver holding
// closures runs them: not a collection operation (add, get(i),
// iterator), nor a callback runner given a closure argument.
func (w words) runsReceiver(c *ir.Call, nargs int, closureArg bool) bool {
	n := strings.ToLower(c.Name)
	switch {
	case n == "get":
		return nargs == 0
	case w.has(tContainerOps, n):
		return false
	case closureArg && w.has(tImmediateCallbacks, n):
		return false
	}
	return true
}

// consentName reports whether a name is a consent check (hasConsent,
// trackingAllowed, isOptedIn).
func (w words) consentName(name string) bool {
	n := foldName(name)
	for _, c := range w.list(tConsentWords) {
		if strings.Contains(n, c) {
			return true
		}
	}
	return false
}

// decodeInto returns the index of the argument a decoder fills
// (json.Unmarshal(b, &v): 1), if the callee is one.
func (w words) decodeInto(callee string) (int, bool) {
	v, ok := w.lookup(tDecodeInto, callee)
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(v)
	return i, err == nil
}
