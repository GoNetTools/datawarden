// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/GoNetTools/datawarden/internal/ir"
)

// sinkTo logs arg with the language's own logger.
func sinkTo(f *ir.Func, arg ir.VarID, line int) {
	c := &ir.Call{Callee: "console.log", Name: "log", RecvText: "console"}
	if f.Lang == "go" {
		c = &ir.Call{Callee: "log.Println", Name: "Println"}
	}
	f.Emit(ir.Instr{Op: ir.OpCall, Dst: f.Temp(pos(line)), Args: []ir.VarID{arg}, Call: c, Pos: pos(line)})
}

// Request data (req.body) is reported when it is logged whole, and not when
// a part of it is read under a constant name: the name says what it is.
func TestRequestDataReadWholeOrByKey(t *testing.T) {
	f := newFunc("web.handler")
	f.Lang = "typescript"
	req := f.AddParam("req", "", pos(1))
	body := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpLoad, Dst: body, Args: []ir.VarID{req}, Field: "body", Pos: pos(2)})
	sinkTo(f, body, 3)
	page := f.Temp(pos(4))
	f.Emit(ir.Instr{Op: ir.OpLoad, Dst: page, Args: []ir.VarID{body}, Field: "page", Pos: pos(4)})
	sinkTo(f, page, 5)
	got := call(f, 6, &ir.Call{Name: "get", HasRecv: true}, body, f.ConstVar("page", pos(6)))
	sinkTo(f, got, 7)
	key := f.AddParam("key", "", pos(1))
	dyn := call(f, 8, &ir.Call{Name: "get", HasRecv: true}, body, key)
	sinkTo(f, dyn, 9)

	res := analyze(t, nil, f)
	for _, line := range []int{3, 9} {
		if fl := flowAt(res, line); fl == nil || fl.DataType != requestData {
			t.Errorf("line %d: request data read whole (or under a computed key) not reported: %+v", line, fl)
		}
	}
	for _, line := range []int{5, 7} {
		if fl := flowAt(res, line); fl != nil {
			t.Errorf("line %d: a part read under a constant name reported as request data: %+v", line, fl)
		}
	}
}

// @RequestBody marks a parameter as request data; an annotation given a
// key (@RequestParam("page")) does not.
func TestAnnotatedRequestParameters(t *testing.T) {
	f := newFunc("app.Ctl.create")
	f.Lang = "java"
	body := f.AddParam("body", "Map", pos(1))
	f.Vars[body].Annotations = []string{"RequestBody"}
	page := f.AddParam("page", "String", pos(1))
	f.Vars[page].Annotations = []string{"RequestParam:page"}
	logTo(f, body, 2)
	logTo(f, page, 3)

	res := analyze(t, nil, f)
	if fl := flowAt(res, 2); fl == nil || fl.DataType != requestData {
		t.Errorf("@RequestBody parameter not reported: %+v", fl)
	}
	if fl := flowAt(res, 3); fl != nil {
		t.Errorf("@RequestParam(\"page\") reported: %+v", fl)
	}
}

// c.ShouldBindJSON(&req) fills req with the request body, and a decoder
// fills the value it is given with what it reads.
func TestBindAndDecodeFillTheirArgument(t *testing.T) {
	f := newFunc("app.handle")
	f.Lang = "go"
	c := f.AddParam("c", "github.com/gin-gonic/gin.Context", pos(1))
	bound := f.Temp(pos(2))
	f.Emit(ir.Instr{Op: ir.OpNew, Dst: bound, Call: &ir.Call{Callee: "app.Signup", Name: "Signup"}, Pos: pos(2)})
	call(f, 3, &ir.Call{Callee: "github.com/gin-gonic/gin.Context.ShouldBindJSON", Name: "ShouldBindJSON", HasRecv: true}, c, bound)
	sinkTo(f, bound, 4)

	r := f.AddParam("r", "net/http.Request", pos(1))
	rb := f.Temp(pos(5))
	f.Emit(ir.Instr{Op: ir.OpLoad, Dst: rb, Args: []ir.VarID{r}, Field: "Body", Owner: "net/http.Request", Pos: pos(5)})
	dec := call(f, 6, &ir.Call{Callee: "encoding/json.NewDecoder", Name: "NewDecoder"}, rb)
	decoded := f.Temp(pos(7))
	f.Emit(ir.Instr{Op: ir.OpNew, Dst: decoded, Call: &ir.Call{Callee: "app.Signup", Name: "Signup"}, Pos: pos(7)})
	call(f, 8, &ir.Call{Callee: "encoding/json.Decoder.Decode", Name: "Decode", HasRecv: true}, dec, decoded)
	sinkTo(f, decoded, 9)

	res := analyze(t, nil, f)
	for _, line := range []int{4, 9} {
		if fl := flowAt(res, line); fl == nil || fl.DataType != requestData {
			t.Errorf("line %d: the filled value is not reported as request data: %+v", line, fl)
		}
	}
}
