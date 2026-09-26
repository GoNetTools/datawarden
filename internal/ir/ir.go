// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package ir defines the small, language-neutral intermediate representation
// that every frontend lowers source code into. The analysis, detectors and
// reports only ever see this IR, never a language AST.
//
// The IR is deliberately tiny: functions own a flat list of variables and a
// flat list of instructions. Together with the control-flow graph and the
// def-use edges of its variables it forms a small code property graph:
//
//   - Data flow: frontends give each assignment to a local its own variable
//     and merge the versions where control flow joins (SSA form, with phis
//     lowered to assign), so a value that is overwritten does not reach
//     reads after the overwrite.
//   - Control flow: Blocks lists the basic blocks and their successors, and
//     every instruction names its block. Within a block, instructions run
//     in slice order. The analysis uses it to order mutations of objects
//     (field stores, list.add) against the sinks that read them.
//
// A function without Blocks has no control-flow information; the analysis
// then treats every mutation as visible everywhere in the function.
package ir

import (
	"fmt"
	"slices"
	"sort"
)

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
	Pos   Pos `json:"pos"`
}

// IsConst reports whether the variable is a literal.
func (v *Var) IsConst() bool { return v.Const != nil }

// Op is an instruction opcode.
type Op uint8

const (
	// OpAssign: Dst = f(Args...). Copies, phis, concatenation, arithmetic,
	// conversions and container construction all lower to this.
	OpAssign Op = iota
	// OpLoad: Dst = Args[0].Field. Field may also be a constant map key.
	OpLoad
	// OpStore: Args[0].Field = Args[1].
	OpStore
	// OpCall: Dst = Call(Args...). When Call.HasRecv, Args[0] is the receiver.
	OpCall
	// OpReturn: return Args... With Throw set, the function instead throws
	// Args[0] out to its caller.
	OpReturn
)

func (o Op) String() string {
	switch o {
	case OpAssign:
		return "assign"
	case OpLoad:
		return "load"
	case OpStore:
		return "store"
	case OpCall:
		return "call"
	case OpReturn:
		return "return"
	}
	return "op?"
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
	Call  *Call  `json:"call,omitempty"`
	Pos   Pos    `json:"pos"`
	// Block is the index of the basic block (Func.Blocks) holding the
	// instruction.
	Block int32 `json:"block,omitempty"`
	// Throw marks an OpReturn that throws its argument (an exception that
	// leaves the function) instead of returning it.
	Throw bool `json:"throw,omitempty"`
	// Snapshot marks an assign that computes a new value from the current
	// state of its arguments (string building, arithmetic) rather than
	// copying or merging references to them: later mutations of an
	// argument do not reach the result.
	Snapshot bool `json:"snapshot,omitempty"`
}

// Block is a basic block of the control-flow graph.
type Block struct {
	// Succs are the blocks control may pass to at the end of this one.
	Succs []int32 `json:"succs,omitempty"`
	// Floating marks code with no fixed place in the function's order: the
	// body of a lambda or closure, which may run when it is created, later
	// or never. It is ordered neither before nor after anything else.
	Floating bool `json:"floating,omitempty"`
}

// Call describes the callee of an OpCall.
type Call struct {
	// Callee is the resolved, qualified callee name, e.g.
	// "io.sentry.Sentry.setUser", "log.Printf",
	// "github.com/getsentry/sentry-go.Scope.SetUser", "@sentry/browser.setUser".
	// Empty when the frontend could not resolve it.
	Callee string `json:"callee,omitempty"`
	// Name is the simple function/method name ("setUser").
	Name string `json:"name"`
	// RecvType is the (possibly unqualified) receiver type when known.
	RecvType string `json:"recv_type,omitempty"`
	// RecvText is the receiver expression as written ("logger", "this.analytics").
	RecvText string `json:"recv_text,omitempty"`
	// HasRecv reports that Instr.Args[0] is the receiver.
	HasRecv bool `json:"has_recv,omitempty"`
	// Target is the ID of a function in the program when the call resolves to
	// code under analysis.
	Target string `json:"target,omitempty"`
	// Construct marks object construction (new Foo(...), Foo(...), &T{...}).
	Construct bool `json:"construct,omitempty"`
	// Ctor is the ID of the constructor a Construct call runs, when it is
	// code under analysis. Its first parameter is the new object (Dst).
	Ctor string `json:"ctor,omitempty"`
	// ArgNames gives, per argument, the parameter name of a keyword or
	// named argument (Python f(to=x), Kotlin f(to = x)); "" for a
	// positional one. Nil when every argument is positional.
	ArgNames []string `json:"arg_names,omitempty"`
	// Targets are further functions a dynamically dispatched call may run:
	// the overrides and implementations of Target in the program (class
	// hierarchy analysis). Target may be empty for an interface method.
	Targets []string `json:"targets,omitempty"`
	// Catch are the variables that receive what the callee throws: the
	// enclosing handler's caught exception, or the function's own escaping
	// exception when the call is not inside a try.
	Catch []VarID `json:"catch,omitempty"`
	// Callbacks are the input variables of lambda arguments: values the
	// callee hands to a callback (collection elements, a location fix, an
	// HTTP response) flow into these.
	Callbacks []VarID `json:"callbacks,omitempty"`
}

// Func is a lowered function, method, or synthetic initializer.
type Func struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Lang   string  `json:"lang"`
	File   string  `json:"file"`
	Pos    Pos     `json:"pos"`
	Params []VarID `json:"params"` // receiver first for methods
	Vars   []Var   `json:"vars"`
	Instrs []Instr `json:"instrs"`
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

// Emit appends an instruction to the current block.
func (f *Func) Emit(in Instr) {
	in.Block = f.cur
	f.Instrs = append(f.Instrs, in)
}

// NewBlock adds a basic block with edges from the given blocks and makes it
// the current block.
func (f *Func) NewBlock(floating bool, preds ...int32) int32 {
	b := int32(len(f.Blocks))
	f.Blocks = append(f.Blocks, Block{Floating: floating})
	for _, p := range preds {
		f.Edge(p, b)
	}
	f.cur = b
	return b
}

// Edge adds a control-flow edge.
func (f *Func) Edge(from, to int32) {
	if int(from) >= len(f.Blocks) || int(to) >= len(f.Blocks) || slices.Contains(f.Blocks[from].Succs, to) {
		return
	}
	f.Blocks[from].Succs = append(f.Blocks[from].Succs, to)
}

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

// Compute emits Dst = f(Args...) as a snapshot of the arguments' current
// state: "items=" + items, a + b.
func (f *Func) Compute(dst VarID, pos Pos, args ...VarID) {
	args = compact(args)
	if dst == NoVar || len(args) == 0 {
		return
	}
	f.Emit(Instr{Op: OpAssign, Dst: dst, Args: args, Pos: pos, Snapshot: true})
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

// Module is the output of a frontend.
type Module struct {
	Lang     string      `json:"lang"`
	Funcs    []*Func     `json:"funcs"`
	Types    []*TypeDecl `json:"types"`
	Warnings []string    `json:"warnings,omitempty"`
}

// Merge appends another module into m.
func (m *Module) Merge(o *Module) {
	if o == nil {
		return
	}
	m.Funcs = append(m.Funcs, o.Funcs...)
	m.Types = append(m.Types, o.Types...)
	m.Warnings = append(m.Warnings, o.Warnings...)
}

// SortStable orders functions and types deterministically.
func (m *Module) SortStable() {
	sort.SliceStable(m.Funcs, func(i, j int) bool {
		return m.Funcs[i].ID < m.Funcs[j].ID
	})
	sort.SliceStable(m.Types, func(i, j int) bool {
		return m.Types[i].Name < m.Types[j].Name
	})
}
