# The datawarden IR

This is the specification of the intermediate representation that every
frontend produces and the taint engine consumes (`internal/ir`). It is
version **2** (`ir.Version`). `ir.Verify` checks a function against the
rules marked **must** below; every frontend's output is verified in the
tests (`TestLoweredIRVerifies`, and each tree-sitter frontend test).

The design follows the IRs used by production analysers: three-address
instructions over SSA variables in a control-flow graph of basic blocks,
as in WALA's SSA IR, Soot's Shimple and `golang.org/x/tools/go/ssa`,
from which the Go frontend lowers. It is smaller than those because it
only needs to follow values, not to run code.

## Module

A frontend returns an `ir.Module`:

| Field | Meaning |
|---|---|
| `Funcs` | Every function, method, closure and synthetic initializer. |
| `Types` | Record-like declarations (structs, classes, entities, protobuf messages, SQL tables) with their fields and tags. The engine gets schema hints from them. |
| `Classes` | The class table: each class, interface, protocol or named type with its direct supertypes and its methods (name → function ID). For Go, the supertypes of a type are the interfaces of the module, or that its code calls methods on, that the type or a pointer to it implements. `File` is the declaring file, by which the cache stores the table for PR scans. |
| `Warnings` | What the frontend could not read. |

## Functions

A `Func` has an `ID` (qualified the way rules are written, see
[ARCHITECTURE.md](ARCHITECTURE.md#the-ir-internalir)), its `Vars`, its
`Params`, its `Instrs` and its `Blocks`.

- `Params` lists parameter variables in order, the receiver first for
  methods. Each parameter variable's `Param` is its index; every other
  variable's is -1.
- A **closure** (lambda, anonymous function, local function, method of an
  anonymous class) is a function of its own. Its ID is its enclosing
  function's ID followed by `$1`, `$2`, …; `Parent` is the enclosing
  function's ID. The last `Captures` parameters are its **capture
  parameters**: variables of the enclosing function that the closure reads
  or writes, in the order its `OpClosure` binds them. `this` is captured
  whenever the enclosing function has one.
- A function **must** have `Captures` ≤ `len(Params)`.

## Variables

A `Var` has a source-level `Name` (empty for temporaries), a best-effort
`Type`, a `Const` value for literals, and a `Pos`.

**SSA.** Every variable other than a cell **must** have at most one
definition (an instruction whose `Dst` it is). A parameter or a constant
**must** have none. Each assignment to a local in the source therefore
makes a new variable with the same name.

**Cells.** A variable with `Cell` set is a location rather than a value:
it may be defined any number of times, and each definition is a *weak
update* that adds to what the cell holds. Frontends use cells for an
array written by index, a Go variable written through a pointer
(`Alloc`, `Store`), a channel sent to, and a captured variable that a
closure assigns (the closure's capture parameter is the cell).

## Instructions

An instruction reads `Args` and defines at most `Dst` (`NoVar` when it
defines nothing). Every argument **must** be a variable of the function.

| Op | Meaning | Shape (**must**) |
|---|---|---|
| `assign` | `Dst = Args…`: a copy, or a merge of references (a container built from its elements, a cast, `a ?? b`). `Dst` aliases the arguments: later mutations of them are visible through it. | ≥ 1 argument, a destination |
| `compute` | `Dst = Operator(Args…)`: a new value computed from the arguments' current state (string concatenation or interpolation, arithmetic, a conversion). If `Operator` is logical (`!`, `&&`, `\|\|`, a comparison; `ir.Logical`), the result is a boolean that carries no data of its operands. | ≥ 1 argument, a destination |
| `phi` | `Dst = φ(Args…)`: `Args[i]` is the value arriving from predecessor block `From[i]`. A path on which the variable is not bound has no argument. | `len(From) == len(Args)`, each `From[i]` a predecessor, phis first in their block |
| `load` | `Dst = Args[0].Field`. `Field` may be a constant map key; `Owner` is the declared type of the object when known. | 1 argument, a destination |
| `store` | `Args[0].Field = Args[1]` | 2 arguments, no destination |
| `call` | `Dst = Call(Args…)` (`Dst` may be `NoVar`). With `Call.HasRecv`, `Args[0]` is the receiver; with `Call.Indirect`, `Args[0]` is the function value called (a closure held in a variable) and the rest are its arguments. | a `Call`; `Args[0]` present with a receiver or an indirect call; `ArgNames`, when set, as long as `Args` |
| `new` | `Dst = new Call.Callee(Args…)`. `Call.Target` is the constructor when it is code under analysis; its first parameter is the new object. | a `Call`, a destination |
| `closure` | `Dst` = a closure of function `Func`, binding `Args` to its capture parameters in order. A function of the module used as a value (a Go func literal that captures nothing, a named function passed as a callback) is a closure with no captures. | `Func` set, a destination |
| `return` | Return `Args…` to the caller. | last in its block, which is `TermReturn` |
| `throw` | Throw `Args[0]`. The exception goes to the block's `Exc` handlers, or leaves the function when there are none. | 1 argument, last in its block, which is `TermThrow` |
| `catch` | `Dst` = the exception being handled. | first after the phis of a block that is entered by an exceptional edge |
| `yield` | A generator produces `Args[0]` to its caller and goes on. | 1 argument |

### Calls

`Call` describes the callee:

- `Callee`: the resolved, qualified name, which rules match; for `new`,
  the class. `Name` is the simple name.
- `Target`: the function under analysis the call statically binds to (or,
  for `new`, the constructor).
- `RecvType`: the declared type of the receiver. A call with a receiver
  type is **dynamically dispatched**: besides `Target`, it may run the
  method of the same name in any subtype of `RecvType` in the class
  table. The engine resolves this (class hierarchy analysis); frontends
  do not.
- `ArgNames`: per argument, the parameter name of a keyword or named
  argument (`f(to=x)`), or "".

## Blocks

`Blocks` is the control-flow graph; block 0 is the entry. A function
without blocks has no control-flow information (the engine then treats
every mutation as visible everywhere); every frontend emits blocks.

- The instructions of a block **must** be contiguous in `Instrs`, in the
  order they run.
- `Succs` are the successors on normal control flow. `Exc` are the
  handler blocks an exception raised in the block goes to. Inside a
  `try`, every instruction that may throw (a call, a `new`, a `throw`)
  ends its block, so a handler is entered with the state at that point;
  an empty block before the body stands for exceptions the runtime
  raises anywhere in it.
- `Term` is how the block ends:

| Term | Meaning (**must**) |
|---|---|
| `jump` | Continue at any of `Succs`; with none, the function ends. |
| `if` | Branch on `Cond`: `Succs[0]` when it is true, `Succs[1]` when false. Exactly two successors, `Cond` a variable whose definition dominates the block. |
| `return` | The block ends with a `return`; no successors. |
| `throw` | The block ends with a `throw`; no successors. |

**Dominance.** A definition **must** dominate each use: an instruction's
arguments are defined earlier in its block or in a block that dominates
it, and a phi's argument from block `P` is defined in a block that
dominates `P`. Dominance is computed over normal and exceptional edges
(`Func.Dominators`); unreachable blocks are not checked.

## What the engine reads from it

- **Data flow**: the def-use edges of SSA variables, with phis and
  assigns as aliases and computes as snapshots.
- **Order of mutations**: a fact put on an object by a store, a mutating
  call or a callee is seen only by instructions that the mutating one can
  run before, over normal and exceptional edges (`analysis/order.go`).
- **Control dependence**: a sink in a block dominated by the "consent
  given" successor of a branch on a consent check (`hasConsent()`,
  `user.optedIn`, `!consents.hasConsent()` with the successors swapped)
  is reported with that check as a guard (`analysis/guard.go`).
- **Closures**: `closure` values flow, over the whole program, through
  assigns and phis, into and out of fields (by owner type and field
  name) and collections, into the parameters of the functions they are
  passed to and out of the functions that return them
  (`analysis/closures.go`). A call runs the closures held in the variable
  it calls (an indirect call), in the receiver of a method call that
  resolves to no code under analysis (`h.accept(v)`, but not
  `handlers.add(h)`), or in the field of the receiver that the method is
  named after (`this.onSend(v)`). A closure that reached a function
  through one of its parameters is not run there: the caller passing it
  runs it with the call's other arguments, at the call when the callee
  runs callbacks before returning (`forEach`, `map`, …), at any later
  time otherwise. Captures are bound only in the function that created
  the closure; a closure that leaves it (stored in a field, returned) is
  run there, reading its captures with every mutation made to them.
- **Exceptions**: a `catch` receives the value of each `throw`, and what
  each call throws, in the blocks whose exceptional edges lead to it.
- **Dispatch**: the class table (`Module.Classes`).

## Text form

`ir.Format` prints a function for debugging:

```
func app.save(v0:email, v1:consents)
b0:
  v2 = call hasConsent(v1:consents)
  v3 = compute "!"(v2)
  if v3 -> b1, b2
b1:
  return
b2:
  v4 = call android.util.Log.d("TAG", v0:email)
```

## Changes

- **2**: `phi`, `compute`, `new`, `throw`, `catch`, `closure` and `yield`
  replace the `Snapshot` and `Throw` flags and `Call.Construct`, `Ctor`,
  `Catch` and `Callbacks`; closures are separate functions with capture
  parameters instead of floating blocks; blocks have terminators and
  exceptional edges; `Var.Cell`; `Module.Classes` replaces
  `Call.Targets`.
- **1**: assign, load, store, call, return over SSA variables, with
  blocks and successors.
