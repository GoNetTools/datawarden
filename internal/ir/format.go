// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// Format renders a function as text, one block after another:
//
//	func app.save(email, this) captures 1
//	b0:
//	  v2 = call log.info(v0)
//	  if v3 -> b1, b2
func Format(f *Func) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "func %s(", f.ID)
	for i, p := range f.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(varName(f, p))
	}
	sb.WriteString(")")
	if f.Captures > 0 {
		fmt.Fprintf(&sb, " captures %d", f.Captures)
	}
	sb.WriteString("\n")
	if len(f.Blocks) == 0 {
		for i := range f.Instrs {
			sb.WriteString("  " + FormatInstr(f, &f.Instrs[i]) + "\n")
		}
		return sb.String()
	}
	byBlock := make([][]int, len(f.Blocks))
	for i := range f.Instrs {
		if b := f.Instrs[i].Block; b >= 0 && int(b) < len(byBlock) {
			byBlock[b] = append(byBlock[b], i)
		}
	}
	for b := range f.Blocks {
		writeBlock(&sb, f, int32(b))
		for _, i := range byBlock[b] {
			sb.WriteString("  " + FormatInstr(f, &f.Instrs[i]) + "\n")
		}
		writeTerm(&sb, f, int32(b))
	}
	return sb.String()
}

func writeBlock(sb *strings.Builder, f *Func, b int32) {
	fmt.Fprintf(sb, "b%d:", b)
	if int(b) < len(f.Blocks) && len(f.Blocks[b].Exc) > 0 {
		fmt.Fprintf(sb, " exc %s", blockList(f.Blocks[b].Exc))
	}
	sb.WriteString("\n")
}

func writeTerm(sb *strings.Builder, f *Func, b int32) {
	if int(b) >= len(f.Blocks) {
		return
	}
	blk := &f.Blocks[b]
	switch blk.Term {
	case TermIf:
		fmt.Fprintf(sb, "  if %s -> %s\n", varName(f, blk.Cond), blockList(blk.Succs))
	case TermJump:
		if len(blk.Succs) > 0 {
			fmt.Fprintf(sb, "  jump %s\n", blockList(blk.Succs))
		}
	}
}

func blockList(bs []int32) string {
	parts := make([]string, len(bs))
	for i, b := range bs {
		parts[i] = "b" + strconv.Itoa(int(b))
	}
	return strings.Join(parts, ", ")
}

func varName(f *Func, v VarID) string {
	if v < 0 || int(v) >= len(f.Vars) {
		return "_"
	}
	x := &f.Vars[v]
	if x.Const != nil {
		return strconv.Quote(*x.Const)
	}
	s := "v" + strconv.Itoa(int(v))
	if x.Name != "" {
		s += ":" + x.Name
	}
	return s
}

// FormatInstr renders one instruction.
func FormatInstr(f *Func, in *Instr) string {
	args := make([]string, len(in.Args))
	for i, a := range in.Args {
		args[i] = varName(f, a)
		if in.Op == OpPhi && i < len(in.From) {
			args[i] = fmt.Sprintf("b%d: %s", in.From[i], args[i])
		}
	}
	list := strings.Join(args, ", ")
	dst := ""
	if in.Dst != NoVar {
		dst = varName(f, in.Dst) + " = "
	}
	switch in.Op {
	case OpLoad:
		return fmt.Sprintf("%s%s.%s", dst, list, in.Field)
	case OpStore:
		if len(args) == 2 {
			return fmt.Sprintf("%s.%s = %s", args[0], in.Field, args[1])
		}
	case OpCall, OpNew:
		name := ""
		if in.Call != nil && in.Call.Indirect {
			return fmt.Sprintf("%scall indirect (%s)", dst, list)
		}
		if in.Call != nil {
			name = in.Call.Callee
			if name == "" {
				name = in.Call.Name
			}
			if in.Call.Target != "" && in.Call.Target != name {
				name += " [" + in.Call.Target + "]"
			}
		}
		return fmt.Sprintf("%s%s %s(%s)", dst, in.Op, name, list)
	case OpCompute:
		return fmt.Sprintf("%scompute %q(%s)", dst, in.Operator, list)
	case OpClosure:
		return fmt.Sprintf("%sclosure %s(%s)", dst, in.Func, list)
	}
	return fmt.Sprintf("%s%s %s", dst, in.Op, list)
}
