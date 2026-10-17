// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/GoNetTools/datawarden/internal/detect"
	"github.com/GoNetTools/datawarden/internal/ir"
	"github.com/GoNetTools/datawarden/internal/rules"
)

// callCtx is one call instruction being analyzed: the state it runs in,
// how its arguments are laid out, and what each one carries.
type callCtx struct {
	st  *state
	fn  *ir.Func
	in  *ir.Instr
	c   *ir.Call
	sum *Summary
	// isNew marks a construction (OpNew); recvOff is 1 when Args[0] is
	// the receiver or the called closure.
	isNew   bool
	recvOff int
	label   string   // the callee as reports name it
	guards  []string // consent checks guarding the call
	// match finds the rules for this call: none when the call runs
	// closures held in a variable, since rules name functions.
	match func(lang, kind string, c *ir.Call) []rules.Hit
	// factsOf is what argument i carries, with the facts a key or label
	// gives it ("password" in putString("password", v)).
	factsOf func(i int) []*fact
}

// nonRecv is the number of arguments after the receiver.
func (cs *callCtx) nonRecv() int { return len(cs.in.Args) - cs.recvOff }

// call analyzes one call or construction: it reports the sinks it
// reaches, seeds what source rules say it produces, runs the closures it
// is given, applies the summaries of the code it calls, and otherwise
// propagates conservatively through code datawarden does not see into.
func (a *analyzer) call(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) bool {
	c := in.Call
	if c == nil {
		return false
	}
	cs := a.callCtx(st, fn, in, sum)
	run, first := a.flow.invoked(fn, in, func(v ir.VarID) []closure { return st.closures[v] })
	if len(run) > 0 && c.Callee == "" {
		cs.match = func(string, string, *ir.Call) []rules.Hit { return nil }
	}

	remote := a.callSinks(cs)
	sourced, keyedRead, changed := a.callSources(cs)
	if handled, ch := a.callTransform(cs); handled {
		return changed || ch
	}
	nameXf := a.opts.Names.FuncTransform(c.Name)
	invoked, ch := a.callClosures(cs, run, first, sourced)
	changed = changed || ch
	if invoked {
		return changed
	}
	applied, ch := a.callSummaries(cs, nameXf)
	changed = changed || ch
	if applied {
		return changed
	}
	return a.callUnknown(cs, remote, keyedRead, nameXf) || changed
}

// callCtx lays out the call's arguments and what they carry.
func (a *analyzer) callCtx(st *state, fn *ir.Func, in *ir.Instr, sum *Summary) *callCtx {
	c := in.Call
	cs := &callCtx{st: st, fn: fn, in: in, c: c, sum: sum, isNew: in.Op == ir.OpNew, label: calleeLabel(c), guards: st.guardsAt(fn), match: a.opts.Rules.Match}
	if (c.HasRecv || c.Indirect) && len(in.Args) > 0 {
		cs.recvOff = 1
	}
	keyed := a.keyLabels(fn, st.defs, in, cs.recvOff)
	for i, fs := range a.textLabels(fn, st.defs, in.Args, in.Pos) {
		if i >= cs.recvOff {
			if keyed == nil {
				keyed = map[int][]*fact{}
			}
			keyed[i] = append(keyed[i], fs...)
		}
	}
	cs.factsOf = func(i int) []*fact {
		fs := st.of(in.Args[i])
		// A key or label names a value that does not already say what
		// it is: putString("password", encrypt(pw)) stays encrypted.
		for _, k := range keyed[i] {
			if !slices.ContainsFunc(fs, func(f *fact) bool { return f.dt == k.dt }) {
				fs = append(fs, k)
			}
		}
		return fs
	}
	return cs
}

// callSinks reports every fact reaching a sink rule's arguments, as a
// flow or, for a parameter's data, as a summary entry. It reports
// whether a network sink matched: the result is then the remote's answer.
func (a *analyzer) callSinks(cs *callCtx) (remote bool) {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	for _, hit := range cs.match(fn.Lang, rules.KindSink, c) {
		r := hit.Rule
		if !r.ArgAllowed(func(i int) string { return argName(fn, st.defs, in, i, cs.recvOff) }) {
			continue
		}
		remote = remote || r.Category == "network"
		dest := a.dest(r, fn, in, cs.recvOff)
		for i := 0; i < len(in.Args); i++ {
			if i < cs.recvOff && !(c.HasRecv && r.Arg.Selects(-1)) || !r.Arg.Selects(i-cs.recvOff) {
				continue
			}
			if i < cs.recvOff && a.chainedSink(fn, st.defs, in.Args[i], r.ID) {
				// log.Info().Str("ip", ip).Msg("x"): the receiver is what
				// the previous call of the chain returned, and that call
				// reported what it carries.
				continue
			}
			for _, f := range cs.factsOf(i) {
				if i < cs.recvOff && f.at > 0 && a.sinkCall(fn, f.at-1, r.ID) {
					// evt.Str("ip", ip); evt.Msg(""): put on the receiver
					// by a call that already reported it.
					continue
				}
				if f.dt == "" {
					cs.sum.addParamSink(f.param, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: a.reportFunc(fn), Call: cs.label, Lang: fn.Lang,
						Path: appendPath(f.path, in.Pos), Xf: f.xf, Conf: f.conf * hit.Conf, Field: f.field, Guards: cs.guards})
					continue
				}
				a.emit(f, SinkHit{Rule: r.ID, Dest: dest, Sink: in.Pos, Func: a.reportFunc(fn), Call: cs.label, Lang: fn.Lang, Conf: hit.Conf, Guards: cs.guards}, nil)
			}
		}
	}
	return remote
}

// callSources seeds what the source rules say the call produces: into
// its result, or into the argument it fills (c.ShouldBindJSON(&v)). It
// returns the facts put on the result, which a callback the call is
// given also receives, and whether the call reads under a constant key.
func (a *analyzer) callSources(cs *callCtx) (sourced []*fact, keyedRead bool, changed bool) {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	keyedRead = a.keyedRead(fn, st.defs, in, cs.recvOff)
	for _, hit := range cs.match(fn.Lang, rules.KindSource, c) {
		if hit.Rule.DataType == requestData && keyedRead {
			// r.FormValue("page"): the key says what the value is.
			continue
		}
		f := &fact{dt: hit.Rule.DataType, param: -1, src: in.Pos, desc: "call " + cs.label, path: []ir.Pos{in.Pos}, conf: sourceConf(hit)}
		if into := hit.Rule.Arg.Indexes; len(into) > 0 {
			for _, i := range into {
				if j := cs.recvOff + i; i >= 0 && j < len(in.Args) {
					changed = st.mutate(in.Args[j], "", st.mutation(f)) || changed
				}
			}
			continue
		}
		changed = st.add(in.Dst, f) || changed
		sourced = append(sourced, f)
	}
	return sourced, keyedRead, changed
}

// callTransform handles a sanitizer: the result carries the input's data
// types with the transform recorded, and nothing else propagates.
func (a *analyzer) callTransform(cs *callCtx) (handled, changed bool) {
	hits := cs.match(cs.fn.Lang, rules.KindTransform, cs.c)
	if len(hits) == 0 {
		return false, false
	}
	x := hits[0].Rule.Transform
	for i := range cs.in.Args {
		for _, f := range cs.factsOf(i) {
			changed = cs.st.add(cs.in.Dst, derive(f, cs.in.Pos, 1, x)) || changed
		}
	}
	return true, changed
}

// callClosures runs the closures the call invokes (run, whose arguments
// start at index first) and the closures passed as arguments, which the
// callee may call back with anything else the call is given. It reports
// whether the call itself invoked a closure: its summary then stands in
// for the callee's.
func (a *analyzer) callClosures(cs *callCtx, run []closure, first int, sourced []*fact) (invoked, changed bool) {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	for _, cl := range run {
		if cl.param {
			continue
		}
		// Arguments beyond the closure's last parameter reach that
		// parameter (varargs, an implicit it standing for several).
		last := len(in.Args) - first - 1
		if cf := a.funcs[cl.fn]; cf != nil {
			last = len(cf.Params) - cf.Captures - 1
		}
		ok, ch := a.runClosure(st, fn, in, cl, in.Args[first:], func(i int) []*fact {
			var out []*fact
			for j := first + i; j < len(in.Args) && (j == first+i || i == last); j++ {
				out = append(out, cs.factsOf(j)...)
			}
			return out
		}, st.of, cs.sum)
		invoked, changed = invoked || ok, changed || ch
	}
	for i, arg := range in.Args {
		if len(run) > 0 && i < first {
			continue
		}
		cls := st.closures[arg]
		if len(cls) == 0 {
			continue
		}
		// A callee known to run the closure before it returns (forEach,
		// map, apply, sort.Slice) runs it here: its captures are read as
		// they are at the call. Any other callee may keep the closure and
		// run it at any later time (a listener, a stored handler), so its
		// captures are read with every mutation, wherever it happens. The
		// closure's parameters correspond to the call's other arguments
		// (the receiver of apply or forEach first).
		now := runsCallbackNow(c)
		inputs := append([]*fact(nil), sourced...)
		var others []ir.VarID
		for j := range in.Args {
			if j != i && !(c.Indirect && j == 0) {
				inputs = append(inputs, cs.factsOf(j)...)
				others = append(others, in.Args[j])
			}
		}
		outs := others
		if !now {
			// A kept callback (a handler, a middleware) is later given
			// arguments of the caller's choosing: what it writes into
			// its parameters does not go into this call's arguments.
			outs = nil
		}
		for _, cl := range cls {
			captured := st.all
			if now {
				captured = st.of
			}
			_, ch := a.runClosure(st, fn, in, cl, outs, func(int) []*fact { return inputs }, captured, cs.sum)
			changed = changed || ch
		}
	}
	return invoked, changed
}

// callSummaries applies the summaries of the code the call runs: the
// constructor on the new object, or the target of a call and every
// override or implementation it may dispatch to. It reports whether any
// summary applied: the call is then into analyzed code.
func (a *analyzer) callSummaries(cs *callCtx, nameXf string) (applied, changed bool) {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	if cs.isNew && c.Target != "" {
		if s := a.summaryFor(c.Target); s != nil {
			// The constructor's first parameter is the new object.
			base := append([]ir.VarID{in.Dst}, in.Args...)
			var names []string
			if c.ArgNames != nil {
				names = append([]string{""}, c.ArgNames...)
			}
			args, idx := a.arrange(c.Target, base, names)
			factsAt := func(i int) []*fact {
				switch {
				case idx[i] < 0:
					return nil
				case idx[i] == 0:
					return st.of(in.Dst)
				}
				return cs.factsOf(idx[i] - 1)
			}
			changed = a.apply(st, fn, in, s, args, factsAt, "", ir.NoVar, cs.sum) || changed
		}
	}
	if cs.isNew || c.Indirect {
		return false, changed
	}
	for _, t := range a.cha.targets(c, fn.Lang) {
		if s := a.summaryFor(t); s != nil {
			args, idx := a.arrange(t, in.Args, c.ArgNames)
			factsAt := func(i int) []*fact {
				if idx[i] < 0 {
					return nil
				}
				return cs.factsOf(idx[i])
			}
			changed = a.apply(st, fn, in, s, args, factsAt, nameXf, in.Dst, cs.sum) || changed
			applied = true
		}
	}
	return applied, changed
}

// callUnknown propagates through a call into code datawarden does not
// see into: what the api rules say the call does, else what its name
// suggests. remote marks a network call (its result is the remote's
// answer), keyedRead a read under a constant key, nameXf a transform the
// callee's name declares (maskEmail).
func (a *analyzer) callUnknown(cs *callCtx, remote, keyedRead bool, nameXf string) bool {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	skipRecv, changed := a.schemaGetter(cs)
	effect := a.apiEffect(fn.Lang, c)
	mutator := a.mutates(fn.Lang, c)
	// A keyed put (ctx.Set("user", u), map.put("email", e)) stores the
	// value under its key: reading another key, or another part of the
	// object, does not give it.
	putKey := ""
	if c.HasRecv && cs.recvOff == 1 && !cs.isNew && cs.nonRecv() == 2 && mutator {
		if k, ok := constOf(fn, st.defs, in.Args[1]); ok && k != "" && !strings.ContainsAny(k, " \t\n") {
			putKey = k
		}
	}
	// A request through an HTTP client the rules do not know
	// (HTTPClient.send_request, session.post) answers with the remote's
	// response, like a network sink's; a length, count or type check
	// is a number or a flag.
	lname := strings.ToLower(c.Name)
	remote = remote || effect == rules.EffectSends || effect == "" && (c.HasRecv || c.RecvText != "") && requestMethods[lname] && !buildsRequest(c)
	if effect == rules.EffectNone || effect == "" && dataFreeCalls[lname] {
		return changed
	}
	// A data loader (AppByTokenLoader(ctx).load(token), GraphQL's
	// DataLoader pattern) answers with the value stored under the key it
	// is given, not with the key.
	lookup := cs.recvOff == 1 && loaderMethods[lname] && strings.Contains(strings.ToLower(c.RecvText+"|"+c.RecvType+"|"+c.Callee), "loader")
	if dst, ok := decodeInto[c.Callee]; ok && dst < len(in.Args) {
		// A decoder fills the value it is given with what it reads:
		// json.NewDecoder(r.Body).Decode(&v), json.Unmarshal(b, &v).
		for i := range in.Args {
			if i == dst {
				continue
			}
			for _, f := range cs.factsOf(i) {
				changed = st.mutate(in.Args[dst], "", st.mutation(derive(f, in.Pos, 0.95))) || changed
			}
		}
	}
	for i := range in.Args {
		if skipRecv && i == 0 {
			continue
		}
		for _, f := range cs.factsOf(i) {
			if remote {
				// A network call answers with the remote's response,
				// which is not derived from what was sent: a login
				// request's reply is not the password.
				continue
			}
			if i == 0 && cs.recvOff == 1 && f.stored != "" && !readsPart(fn, st.defs, in, f.stored) {
				continue
			}
			if i == 0 && cs.recvOff == 1 && f.dt == requestData && keyedRead {
				// request.form.get("page"): the key says what it is.
				continue
			}
			if lookup && i >= cs.recvOff {
				continue
			}
			changed = st.add(in.Dst, derive(f, in.Pos, 0.95, nameXf)) || changed
			if putKey != "" && i == 2 {
				changed = st.mutate(in.Args[0], putKey, st.mutation(derive(f, in.Pos, 0.9))) || changed
				continue
			}
			if putKey != "" && i == 1 {
				continue
			}
			if i >= cs.recvOff && c.HasRecv && cs.recvOff == 1 && !cs.isNew && mutator {
				changed = a.mutateReceiver(cs, f) || changed
			}
		}
	}
	if r, ok := st.fluent[in.Dst]; ok && r == in.Args[0] && !remote {
		// A builder or scope function returns its receiver: the result
		// is the same object, with the mutations made to it here and
		// later (User().apply { email = x }).
		changed = a.alias(st, in, in.Dst, r) || changed
	}
	return a.nameSources(cs, skipRecv) || changed
}

// schemaGetter answers a getter on a value whose type the schema knows
// (profile.getBio()) from the schema, instead of smearing every field
// of the object onto the result. It reports whether the receiver's facts
// must therefore not propagate to the result.
func (a *analyzer) schemaGetter(cs *callCtx) (skipRecv, changed bool) {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	if !c.HasRecv || cs.recvOff != 1 || cs.nonRecv() != 0 {
		return false, false
	}
	skipRecv = publicParts[strings.ToLower(c.Name)]
	if in.Args[0] < 0 {
		return skipRecv, false
	}
	owner := fn.Vars[in.Args[0]].Type
	if owner == "" || !a.opts.Schema.KnownType(owner) {
		return skipRecv, false
	}
	field, ok := getterField(c.Name)
	if !ok {
		return skipRecv, false
	}
	if h, fs := a.opts.Schema.Field(owner, field); fs == detect.FieldPII {
		f := &fact{dt: h.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("%s.%s() (%s)", shortType(owner), c.Name, h.Via), path: []ir.Pos{in.Pos}, conf: h.Conf}
		changed = st.add(in.Dst, f)
	}
	return true, changed
}

// mutateReceiver puts a fact a builder call is given on its receiver,
// and on the object that receiver came from when it is itself a builder
// call's result (sb.append(a).append(email)).
func (a *analyzer) mutateReceiver(cs *callCtx, f *fact) bool {
	st, fn, in := cs.st, cs.fn, cs.in
	changed := false
	r := in.Args[0]
	for depth := 0; r >= 0 && depth < 8; depth++ {
		if handleType(fn.Vars[r].Type) {
			// A connection or client is not changed by the data a query
			// or request is given: db.Where(q, email) does not put the
			// email into db.
			break
		}
		changed = st.mutate(r, "", st.mutation(derive(f, in.Pos, 0.9))) || changed
		next, ok := st.fluent[r]
		if !ok {
			break
		}
		r = next
	}
	return changed
}

// nameSources seeds what the call's name says it returns: a getter named
// for a data type (getEmail()), or a read under a constant key that names
// one (slog.String("email", v), getString("phone")).
func (a *analyzer) nameSources(cs *callCtx, skipRecv bool) bool {
	st, fn, in, c := cs.st, cs.fn, cs.in, cs.c
	if in.Dst < 0 {
		return false
	}
	changed := false
	if cs.nonRecv() == 0 && !skipRecv {
		if m, ok := a.opts.Names.Getter(c.Name); ok {
			f := &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("getter %s()", c.Name), path: []ir.Pos{in.Pos}, conf: m.Conf}
			if m.Transform != "" {
				f.xf = []string{m.Transform}
			}
			changed = st.add(in.Dst, f) || changed
		}
	}
	if cs.nonRecv() >= 1 && isGetterName(c.Name) {
		if key, ok := constOf(fn, st.defs, in.Args[cs.recvOff]); ok {
			// A value passed after the key (slog.String("address", v))
			// may say it is something else.
			if m, ok := a.opts.Names.Key(key); ok && (cs.recvOff+1 >= len(in.Args) || !a.keyContradicted(fn, st.defs, in.Args[cs.recvOff+1], m.DataType)) {
				changed = st.add(in.Dst, &fact{dt: m.DataType, param: -1, src: in.Pos, desc: fmt.Sprintf("%s(%q)", c.Name, key), path: []ir.Pos{in.Pos}, conf: m.Conf}) || changed
			}
		}
	}
	return changed
}
