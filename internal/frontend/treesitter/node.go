// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package treesitter

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Node is a syntax tree node: the tree-sitter binding's node with the
// accessors the frontends use. A nil *Node is a missing child. Nodes are
// fresh values on every access, so compare them with Equal, not ==. They
// are valid until the tree they belong to is closed (program.close).
type Node sitter.Node

// Point is a position in a file: 0-based row and byte column.
type Point struct{ Row, Column uint }

func wrap(n *sitter.Node) *Node { return (*Node)(n) }

func (n *Node) ts() *sitter.Node { return (*sitter.Node)(n) }

// Type is the node's kind, as named in the grammar.
func (n *Node) Type() string { return n.ts().Kind() }

func (n *Node) IsNamed() bool   { return n.ts().IsNamed() }
func (n *Node) IsError() bool   { return n.ts().IsError() }
func (n *Node) IsMissing() bool { return n.ts().IsMissing() }
func (n *Node) HasError() bool  { return n.ts().HasError() }

func (n *Node) ChildCount() int        { return int(n.ts().ChildCount()) }
func (n *Node) Child(i int) *Node      { return wrap(n.ts().Child(uint(i))) }
func (n *Node) NamedChildCount() int   { return int(n.ts().NamedChildCount()) }
func (n *Node) NamedChild(i int) *Node { return wrap(n.ts().NamedChild(uint(i))) }
func (n *Node) Parent() *Node          { return wrap(n.ts().Parent()) }

func (n *Node) ChildByFieldName(name string) *Node {
	return wrap(n.ts().ChildByFieldName(name))
}

// FieldNameForChild is the field name of the i-th child, or "".
func (n *Node) FieldNameForChild(i int) string {
	return n.ts().FieldNameForChild(uint32(i))
}

func (n *Node) StartByte() uint { return n.ts().StartByte() }

func (n *Node) StartPoint() Point {
	p := n.ts().StartPosition()
	return Point{Row: p.Row, Column: p.Column}
}

// Content is the node's source text.
func (n *Node) Content(src []byte) string { return n.ts().Utf8Text(src) }

// Equal reports whether n and o are the same node of the same tree.
func (n *Node) Equal(o *Node) bool {
	if n == nil || o == nil {
		return n == o
	}
	return n.ts().Equals(*o.ts())
}
