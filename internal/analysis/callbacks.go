// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// immediateCallbacks are the functions and methods that run the closure
// they are given before they return, in the languages datawarden reads:
// collection operations, scope functions, sorting and locking helpers.
// Keys are lower case.
var immediateCallbacks = map[string]bool{
	// Collections (Kotlin, Java streams and Iterable, Swift, JS arrays).
	"foreach": true, "foreachindexed": true, "foreachordered": true, "map": true, "mapindexed": true, "mapnotnull": true,
	"compactmap": true, "flatmap": true, "filter": true, "filternot": true, "filterindexed": true, "reduce": true,
	"reduceright": true, "fold": true, "foldright": true, "any": true, "all": true, "none": true, "some": true,
	"every": true, "count": true, "find": true, "findindex": true, "findlast": true, "first": true, "firstornull": true,
	"last": true, "lastornull": true, "contains": true, "allsatisfy": true, "sumof": true, "maxby": true, "minby": true,
	"maxbyornull": true, "minbyornull": true, "sortedby": true, "sortedbydescending": true, "sortby": true,
	"sortwith": true, "sortedwith": true, "sorted": true, "sort": true, "groupby": true, "associate": true,
	"associateby": true, "associatewith": true, "partition": true, "oneach": true, "removeif": true,
	"removeall": true, "retainall": true, "replaceall": true, "takewhile": true, "dropwhile": true,
	"computeifabsent": true, "computeifpresent": true, "compute": true, "merge": true, "ifpresent": true,
	"ifpresentorelse": true, "anymatch": true, "allmatch": true, "nonematch": true,
	// Scope and resource functions (Kotlin), locking.
	"let": true, "run": true, "apply": true, "also": true, "with": true, "use": true, "takeif": true,
	"takeunless": true, "repeat": true, "withlock": true, "synchronized": true, "buildstring": true,
	"buildlist": true, "buildmap": true, "measuretimemillis": true,
	// Python builtins (key functions).
	"max": true, "min": true,
	// Go standard library.
	"slice": true, "slicestable": true, "sortfunc": true, "sortstablefunc": true, "indexfunc": true,
	"containsfunc": true, "deletefunc": true, "fieldsfunc": true, "trimfunc": true, "walk": true, "walkdir": true,
}

// runsCallbackNow reports whether the callee runs a closure argument
// before it returns, so the closure sees its captures as they are at the
// call and not as later code changes them.
func runsCallbackNow(c *ir.Call) bool {
	return c != nil && immediateCallbacks[strings.ToLower(c.Name)]
}
