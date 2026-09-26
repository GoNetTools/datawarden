// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package ir defines the language-neutral intermediate representation that
// every frontend lowers source code into. The analysis, detectors and
// reports only ever see this IR, never a language AST. docs/IR.md is its
// specification; Verify checks a function against it.
//
// A function is a control-flow graph of basic blocks over SSA variables:
//
//   - Instructions are three-address: each reads variables (Args) and
//     defines at most one (Dst). Every variable has at most one definition
//     unless it is a Cell (a location written by weak updates). Where
//     control flow joins, an OpPhi merges the versions arriving from each
//     predecessor block; definitions dominate their uses.
//   - Blocks list their instructions contiguously in Func.Instrs, in the
//     order they run, and end with a terminator (Term): a jump to their
//     successors, a two-way branch on a condition variable, a return or a
//     throw. Exc lists the handler blocks an exception raised in the block
//     goes to; an instruction that may throw inside a try ends its block.
//   - Closures are functions of their own. OpClosure creates one, binding
//     the enclosing function's variables to the closure's capture
//     parameters.
//   - Module.Classes is the class table: supertypes and methods, from
//     which the analysis resolves dynamically dispatched calls.
//
// Together with the def-use edges of its variables this forms a small
// code property graph: control flow (Blocks), data flow (SSA def-use) and
// control dependence (Branch conditions, via Dominators).
package ir

import (
	"fmt"
	"slices"
	"sort"
)

// Version is the version of the IR described in docs/IR.md. It changes
// whenever the meaning of the IR changes, so that anything derived from
// it (cached summaries) is recomputed.
const Version = 2

// Pos is a source position. File is slash-separated and relative to the
// repository root; Line and Col are 1-based.
type Pos struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Col  int    `json:"col,omitempty"`
}

// IsValid reports whether the position points somewhere.
func (p Pos) IsValid() bool { return p.File != "" && p.Line > 0 }

func (p Pos) String() string {
	if p.Col > 0 {
		return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Col)
	}
	return fmt.Sprintf("%s:%d", p.File, p.Line)
}

// VarID indexes Func.Vars.
type VarID int32

// NoVar is used where an instruction has no destination.
const NoVar VarID = -1

// Var is a value inside a function: a parameter, a local, or a temporary.
type Var struct {
	// Name is the source-level identifier ("phoneNumber"). Empty for
	// temporaries. Source detectors classify variables by this name.
	Name string `json:"name,omitempty"`
	// Type is the best-effort declared type, qualified when the frontend
	// can resolve it ("example.com/app/model.User", "com.acme.User").
	Type string `json:"type,omitempty"`
	// Const holds the value of a string/number literal.
	Const *string `json:"const,omitempty"`
	// Param is the index into Func.Params, or -1.
	Param int `json:"param"`
	// Cell marks a variable that is a location rather than a value: it
	// may be defined several times (an array written by index, a Go
	// variable written through a pointer, a captured variable a closure
	// assigns), and each definition is a weak update that adds to what it
	// holds instead of replacing it.
	Cell bool `json:"cell,omitempty"`
	Pos  Pos  `json:"pos"`
}

// IsConst reports whether the variable is a literal.
func (v *Var) IsConst() bool { return v.Const != nil }

// Op is an instruction opcode.
type Op uint8

const (
	// OpAssign: Dst = Args... A copy, or a merge of references to the
	// arguments (a container built from them, a cast): Dst aliases them.
	OpAssign Op = iota
	// OpLoad: Dst = Args[0].Field. Field may also be a constant map key.
	OpLoad
	// OpStore: Args[0].Field = Args[1].
	OpStore
	// OpCall: Dst = Call(Args...). When Call.HasRecv, Args[0] is the
	// receiver; when Call.Indirect, Args[0] is the function value called.
	OpCall
	// OpReturn: return Args... Ends its block.
	OpReturn
	// OpPhi: Dst = φ(Args...): Args[i] is the value arriving from the
	// predecessor block From[i]. Phis come first in their block.
	OpPhi
	// OpCompute: Dst = Operator(Args...): a new value computed from the
	// arguments' current state (string building, arithmetic). Later
	// mutations of an argument do not reach it. A Logical operator
	// (comparison, negation, && and ||) yields a boolean that carries no
	// data of its arguments.
	OpCompute
	// OpNew: Dst = new Call.Callee(Args...). Call.Target is the
	// constructor when it is code under analysis; its first parameter is
	// the new object.
	OpNew
	// OpThrow: throw Args[0]. Ends its block; the exception goes to the
	// block's Exc handlers, or leaves the function when it has none.
	OpThrow
	// OpCatch: Dst = the exception being handled. It starts a handler
	// block, after the phis; the exception comes from the instructions
	// ending the blocks whose Exc edges lead here.
	OpCatch
	// OpClosure: Dst = a closure of function Func, binding Args to its
	// capture parameters (the last Func.Captures parameters) in order.
	OpClosure
	// OpYield: a generator produces Args[0] to its caller and goes on.
	OpYield
)

var opNames = [...]string{"assign", "load", "store", "call", "return", "phi", "compute", "new", "throw", "catch", "closure", "yield"}

func (o Op) String() string {
	if int(o) < len(opNames) {
		return opNames[o]
	}
	return "op?"
}

// defines reports whether the op defines Dst.
func (o Op) defines() bool {
	switch o {
	case OpStore, OpReturn, OpThrow, OpYield:
		return false
	}
	return true
}

// Instr is a single IR instruction.
type Instr struct {
	Op   Op      `json:"op"`
	Dst  VarID   `json:"dst"`
	Args []VarID `json:"args,omitempty"`
	// Field is the field/property name (or constant key) for OpLoad/OpStore.
	Field string `json:"field,omitempty"`
	// Owner is the declared type of the object for OpLoad/OpStore, if known.
	Owner string `json:"owner,omitempty"`
	// Call describes the callee of an OpCall and the class of an OpNew.
	Call *Call `json:"call,omitempty"`
	Pos  Pos   `json:"pos"`
	// Block is the index of the basic block (Func.Blocks) holding the
	// instruction.
	Block int32 `json:"block,omitempty"`
	// From gives, for OpPhi, the predecessor block each argument comes from.
	From []int32 `json:"from,omitempty"`
	// Operator is the source operator of an OpCompute ("+", "!", "==",
	// "format"), when known.
	Operator string `json:"operator,omitempty"`
	// Func is the ID of the closure function an OpClosure creates.
	Func string `json:"func,omitempty"`
}

// Logical reports whether an OpCompute operator yields a boolean that
// carries no data of its operands: a comparison, a negation or a boolean
// connective.
func Logical(op string) bool {
	switch op {
	case "!", "&&", "||", "==", "!=", "===", "!==", "<", "<=", ">", ">=", "cmp", "is", "in", "instanceof":
		return true
	}
	return false
}

// Term is how a basic block ends.
type Term uint8

const (
	// TermJump continues at any of Succs; with none, the function ends
	// (falls off its end).
	TermJump Term = iota
	// TermIf branches on Cond: to Succs[0] when it is true, Succs[1]
	// when false.
	TermIf
	// TermReturn: the block ends with an OpReturn.
	TermReturn
	// TermThrow: the block ends with an OpThrow.
	TermThrow
)

var termNames = [...]string{"jump", "if", "return", "throw"}

func (t Term) String() string {
	if int(t) < len(termNames) {
		return termNames[t]
	}
	return "term?"
}

// Block is a basic block of the control-flow graph.
type Block struct {
	// Succs are the blocks control passes to at the end of this one.
	Succs []int32 `json:"succs,omitempty"`
	// Exc are the handler blocks an exception raised in this block goes
	// to: the block ends with an OpThrow, or with a call that may throw.
	Exc  []int32 `json:"exc,omitempty"`
	Term Term    `json:"term,omitempty"`
	// Cond is the condition of a TermIf.
	Cond VarID `json:"cond,omitempty"`
}

// Call describes the callee of an OpCall or the class of an OpNew.
type Call struct {
	// Callee is the resolved, qualified callee name, e.g.
	// "io.sentry.Sentry.setUser", "log.Printf",
	// "github.com/getsentry/sentry-go.Scope.SetUser", "@sentry/browser.setUser".
	// For OpNew it is the class. Empty when the frontend could not resolve it.
	Callee string `json:"callee,omitempty"`
	// Name is the simple function/method name ("setUser").
	Name string `json:"name"`
	// RecvType is the (possibly unqualified) receiver type when known. A
	// call with a receiver type is dynamically dispatched: the analysis
	// looks up overrides and implementations in Module.Classes.
	RecvType string `json:"recv_type,omitempty"`
	// RecvText is the receiver expression as written ("logger", "this.analytics").
	RecvText string `json:"recv_text,omitempty"`
	// HasRecv reports that Instr.Args[0] is the receiver.
	HasRecv bool `json:"has_recv,omitempty"`
	// Indirect reports that Instr.Args[0] is the function value called (a
	// closure held in a variable), and the remaining arguments its
	// arguments.
	Indirect bool `json:"indirect,omitempty"`
	// Target is the ID of a function in the program when the call resolves
	// to code under analysis: the statically bound method, or for OpNew
	// the constructor.
	Target string `json:"target,omitempty"`
	// ArgNames gives, per argument, the parameter name of a keyword or
	// named argument (Python f(to=x), Kotlin f(to = x)); "" for a
	// positional one. Nil when every argument is positional.
	ArgNames []string `json:"arg_names,omitempty"`
}

// Func is a lowered function, method, closure or synthetic initializer.
type Func struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Lang   string  `json:"lang"`
	File   string  `json:"file"`
	Pos    Pos     `json:"pos"`
	Params []VarID `json:"params"` // receiver first for methods
	// Captures is the number of trailing Params that are variables a
	// closure captures from its enclosing function (Parent); OpClosure
	// binds them.
	Captures int     `json:"captures,omitempty"`
	Parent   string  `json:"parent,omitempty"`
	Vars     []Var   `json:"vars"`
	Instrs   []Instr `json:"instrs"`
	// Blocks is the control-flow graph; block 0 is the entry. Empty when
	// the frontend provides no control flow.
	Blocks []Block `json:"blocks,omitempty"`

	cur int32 // block that Emit appends to
}

// NewVar appends a variable and returns its ID. Callers must set v.Param to
// -1 for non-parameters; the helpers below do so.
func (f *Func) NewVar(v Var) VarID {
	f.Vars = append(f.Vars, v)
	return VarID(len(f.Vars) - 1)
}

// Temp creates an unnamed temporary.
func (f *Func) Temp(pos Pos) VarID {
	return f.NewVar(Var{Param: -1, Pos: pos})
}

// Named creates a named local.
func (f *Func) Named(name, typ string, pos Pos) VarID {
	return f.NewVar(Var{Name: name, Type: typ, Param: -1, Pos: pos})
}

// ConstVar creates a literal.
func (f *Func) ConstVar(val string, pos Pos) VarID {
	v := val
	return f.NewVar(Var{Const: &v, Param: -1, Pos: pos})
}

// AddParam creates a parameter variable and registers it in Params.
func (f *Func) AddParam(name, typ string, pos Pos) VarID {
	id := f.NewVar(Var{Name: name, Type: typ, Param: len(f.Params), Pos: pos})
	f.Params = append(f.Params, id)
	return id
}

// AddCapture adds a capture parameter: a variable of the enclosing
// function that an OpClosure binds.
func (f *Func) AddCapture(name, typ string, pos Pos) VarID {
	f.Captures++
	return f.AddParam(name, typ, pos)
}

// Emit appends an instruction to the current block.
func (f *Func) Emit(in Instr) {
	in.Block = f.cur
	f.Instrs = append(f.Instrs, in)
}

// NewBlock adds a basic block with edges from the given blocks and makes it
// the current block.
func (f *Func) NewBlock(preds ...int32) int32 {
	b := int32(len(f.Blocks))
	f.Blocks = append(f.Blocks, Block{})
	for _, p := range preds {
		f.Edge(p, b)
	}
	f.cur = b
	return b
}

// Edge adds a control-flow edge.
func (f *Func) Edge(from, to int32) {
	if !f.valid(from) || !f.valid(to) || slices.Contains(f.Blocks[from].Succs, to) {
		return
	}
	f.Blocks[from].Succs = append(f.Blocks[from].Succs, to)
}

// ExcEdge adds an exceptional edge: an exception raised at the end of
// block from is handled by block to.
func (f *Func) ExcEdge(from, to int32) {
	if !f.valid(from) || !f.valid(to) || slices.Contains(f.Blocks[from].Exc, to) {
		return
	}
	f.Blocks[from].Exc = append(f.Blocks[from].Exc, to)
}

// Branch ends block b with a two-way branch on cond.
func (f *Func) Branch(b int32, cond VarID, ifTrue, ifFalse int32) {
	if !f.valid(b) {
		return
	}
	f.Blocks[b].Term, f.Blocks[b].Cond = TermIf, cond
	f.Blocks[b].Succs = []int32{ifTrue, ifFalse}
}

func (f *Func) valid(b int32) bool { return b >= 0 && int(b) < len(f.Blocks) }

// CurBlock is the block that Emit appends to.
func (f *Func) CurBlock() int32 { return f.cur }

// SetBlock makes b the block that Emit appends to.
func (f *Func) SetBlock(b int32) { f.cur = b }

// Assign emits Dst = Args...
func (f *Func) Assign(dst VarID, pos Pos, args ...VarID) {
	args = compact(args)
	if dst == NoVar || len(args) == 0 {
		return
	}
	f.Emit(Instr{Op: OpAssign, Dst: dst, Args: args, Pos: pos})
}

// Compute emits Dst = operator(Args...) as a new value built from the
// arguments' current state: "items=" + items, a + b.
func (f *Func) Compute(dst VarID, pos Pos, operator string, args ...VarID) {
	args = compact(args)
	if dst == NoVar || len(args) == 0 {
		return
	}
	f.Emit(Instr{Op: OpCompute, Dst: dst, Args: args, Pos: pos, Operator: operator})
}

// Phi emits Dst = φ(Args...) with Args[i] arriving from block from[i].
func (f *Func) Phi(dst VarID, pos Pos, args []VarID, from []int32) {
	if dst == NoVar || len(args) == 0 || len(args) != len(from) {
		return
	}
	f.Emit(Instr{Op: OpPhi, Dst: dst, Args: args, From: from, Pos: pos})
}

// Return ends the current block with return Args...
func (f *Func) Return(pos Pos, args ...VarID) {
	f.Emit(Instr{Op: OpReturn, Dst: NoVar, Args: compact(args), Pos: pos})
	if f.valid(f.cur) {
		f.Blocks[f.cur].Term = TermReturn
	}
}

// Throw ends the current block with throw v.
func (f *Func) Throw(pos Pos, v VarID) {
	f.Emit(Instr{Op: OpThrow, Dst: NoVar, Args: compact([]VarID{v}), Pos: pos})
	if f.valid(f.cur) {
		f.Blocks[f.cur].Term = TermThrow
	}
}

func compact(in []VarID) []VarID {
	out := in[:0:0]
	for _, v := range in {
		if v != NoVar {
			out = append(out, v)
		}
	}
	return out
}

// Preds returns the predecessors of every block, over normal and
// exceptional edges.
func (f *Func) Preds() [][]int32 {
	out := make([][]int32, len(f.Blocks))
	for b := range f.Blocks {
		for _, s := range append(append([]int32(nil), f.Blocks[b].Succs...), f.Blocks[b].Exc...) {
			if f.valid(s) && !slices.Contains(out[s], int32(b)) {
				out[s] = append(out[s], int32(b))
			}
		}
	}
	return out
}

// Dominators returns the immediate dominator of every block over normal
// and exceptional edges: -1 for the entry and for unreachable blocks.
// (Cooper, Harvey and Kennedy, "A Simple, Fast Dominance Algorithm".)
func (f *Func) Dominators() []int32 {
	n := len(f.Blocks)
	idom := make([]int32, n)
	for i := range idom {
		idom[i] = -1
	}
	if n == 0 {
		return idom
	}
	// Reverse postorder from the entry.
	order := make([]int32, 0, n)
	rpo := make([]int, n)
	seen := make([]bool, n)
	type frame struct {
		b    int32
		next int
	}
	stack := []frame{{0, 0}}
	seen[0] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		succs := append(append([]int32(nil), f.Blocks[top.b].Succs...), f.Blocks[top.b].Exc...)
		if top.next < len(succs) {
			s := succs[top.next]
			top.next++
			if f.valid(s) && !seen[s] {
				seen[s] = true
				stack = append(stack, frame{s, 0})
			}
			continue
		}
		order = append(order, top.b)
		stack = stack[:len(stack)-1]
	}
	slices.Reverse(order)
	for i, b := range order {
		rpo[b] = i
	}
	preds := f.Preds()
	idom[0] = 0
	intersect := func(a, b int32) int32 {
		for a != b {
			for rpo[a] > rpo[b] {
				a = idom[a]
			}
			for rpo[b] > rpo[a] {
				b = idom[b]
			}
		}
		return a
	}
	for changed := true; changed; {
		changed = false
		for _, b := range order[1:] {
			nd := int32(-1)
			for _, p := range preds[b] {
				if !seen[p] || idom[p] < 0 {
					continue
				}
				if nd < 0 {
					nd = p
				} else {
					nd = intersect(p, nd)
				}
			}
			if nd >= 0 && idom[b] != nd {
				idom[b] = nd
				changed = true
			}
		}
	}
	idom[0] = -1
	return idom
}

// Dominates reports whether block a dominates block b, given idom from
// Dominators.
func Dominates(idom []int32, a, b int32) bool {
	for depth := 0; b >= 0 && depth <= len(idom); depth++ {
		if a == b {
			return true
		}
		if int(b) >= len(idom) {
			return false
		}
		b = idom[b]
	}
	return false
}

// Field is a field of a struct, class, proto message or SQL table.
type Field struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	// Tags carries schema hints: struct tags ("json", "gorm", "db", "pii"),
	// annotations ("@Column", "@SerializedName", "@JsonProperty", "@PII") and
	// column names from migrations ("column").
	Tags map[string]string `json:"tags,omitempty"`
	Pos  Pos               `json:"pos"`
}

// TypeDecl is a record-like declaration used for schema hints.
type TypeDecl struct {
	Name string `json:"name"` // qualified when possible
	// Kind is "struct", "class", "entity", "proto", "table".
	Kind        string   `json:"kind"`
	Lang        string   `json:"lang"`
	Annotations []string `json:"annotations,omitempty"`
	// External marks types from dependencies: their field hints are used,
	// but merely holding such a value is not treated as holding PII.
	External bool    `json:"external,omitempty"`
	Fields   []Field `json:"fields"`
	Pos      Pos     `json:"pos"`
}

// Class is an entry of the class table: a class, interface, protocol or
// named type with methods, its direct supertypes (superclasses,
// implemented interfaces and protocols; for Go, the interfaces of the
// program the type implements) and its methods.
type Class struct {
	Name string `json:"name"` // qualified when possible
	Lang string `json:"lang"`
	// File declares the class; the cache keeps the class table per file.
	File    string            `json:"file,omitempty"`
	Supers  []string          `json:"supers,omitempty"`
	Methods map[string]string `json:"methods,omitempty"` // method name -> Func ID
}

// Module is the output of a frontend.
type Module struct {
	Lang     string      `json:"lang"`
	Funcs    []*Func     `json:"funcs"`
	Types    []*TypeDecl `json:"types"`
	Classes  []*Class    `json:"classes,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
}

// Merge appends another module into m.
func (m *Module) Merge(o *Module) {
	if o == nil {
		return
	}
	m.Funcs = append(m.Funcs, o.Funcs...)
	m.Types = append(m.Types, o.Types...)
	m.Classes = append(m.Classes, o.Classes...)
	m.Warnings = append(m.Warnings, o.Warnings...)
}

// SortStable orders functions, types and classes deterministically.
func (m *Module) SortStable() {
	sort.SliceStable(m.Funcs, func(i, j int) bool {
		return m.Funcs[i].ID < m.Funcs[j].ID
	})
	sort.SliceStable(m.Types, func(i, j int) bool {
		return m.Types[i].Name < m.Types[j].Name
	})
	sort.SliceStable(m.Classes, func(i, j int) bool {
		return m.Classes[i].Name < m.Classes[j].Name
	})
}
