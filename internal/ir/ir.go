// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Package ir defines the small, language-neutral intermediate representation
// that every frontend lowers source code into. The analysis, detectors and
// reports only ever see this IR, never a language AST.
//
// The IR is deliberately tiny: functions own a flat list of variables and a
// flat list of instructions. The analysis is flow-insensitive within a
// function, so instruction order and control flow are not modelled.
package ir

import (
	"fmt"
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
	// Name is the source-level identifier ("soDienThoai"). Empty for
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
	// OpReturn: return Args...
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

// Emit appends an instruction.
func (f *Func) Emit(in Instr) { f.Instrs = append(f.Instrs, in) }

// Assign emits Dst = Args...
func (f *Func) Assign(dst VarID, pos Pos, args ...VarID) {
	args = compact(args)
	if dst == NoVar || len(args) == 0 {
		return
	}
	f.Emit(Instr{Op: OpAssign, Dst: dst, Args: args, Pos: pos})
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
	sort.SliceStable(m.Funcs, func(i, j int) bool { return m.Funcs[i].ID < m.Funcs[j].ID })
	sort.SliceStable(m.Types, func(i, j int) bool { return m.Types[i].Name < m.Types[j].Name })
}
