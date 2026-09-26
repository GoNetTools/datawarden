// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

// Package flowgraph draws the call graph behind a scan's flows: where
// personal data is read (sources), the functions it goes through
// (Flow.Calls), the functions that call them (Flow.CalledBy), and the
// sinks it reaches. It renders the graph as an SVG image (laid out here,
// no external tools), as Graphviz DOT, or as a Mermaid flowchart.
package flowgraph

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/GoNetTools/datawarden/internal/finding"
)

// Formats are the formats Render writes.
var Formats = []string{"svg", "dot", "mermaid"}

// Kind is what a node stands for.
type Kind string

// Node kinds.
const (
	Source   Kind = "source"
	Function Kind = "function"
	Caller   Kind = "caller"
	Sink     Kind = "sink"
)

// Node is a source, a function or a sink.
type Node struct {
	ID    string
	Kind  Kind
	Label string
	// Detail is a second line: the location, or the destination.
	Detail string
	// Dest is the destination kind of a sink (log, third_party, ...).
	Dest string
	// Severity is the highest severity of the flows through the node.
	Severity string
}

// Edge carries data from one node to the next, or (Calls) marks a call
// by a function that does not pass the data itself.
type Edge struct {
	From, To  string
	DataTypes []string
	// Calls marks a caller edge from Flow.CalledBy.
	Calls bool
}

// Graph is the merged graph of a set of flows.
type Graph struct {
	Nodes []*Node
	Edges []*Edge
	Flows int
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// Build merges the flows into one graph: a function reached by several
// flows is one node, and an edge lists every data type it carries.
func Build(flows []*finding.Flow) *Graph {
	g := &Graph{Flows: len(flows)}
	nodes := map[string]*Node{}
	edges := map[string]*Edge{}
	node := func(id string, kind Kind, label, detail, sev string) *Node {
		n := nodes[id]
		if n == nil {
			n = &Node{ID: id, Kind: kind, Label: label, Detail: detail}
			nodes[id] = n
			g.Nodes = append(g.Nodes, n)
		}
		if n.Kind == Caller && kind == Function {
			n.Kind = Function // a caller that also passes data
		}
		if severityRank[sev] > severityRank[n.Severity] {
			n.Severity = sev
		}
		return n
	}
	edge := func(from, to, dt string, calls bool) {
		if from == to {
			return
		}
		k := from + "\x00" + to
		e := edges[k]
		if e == nil {
			e = &Edge{From: from, To: to, Calls: calls}
			edges[k] = e
			g.Edges = append(g.Edges, e)
		}
		if !calls {
			e.Calls = false
			if !slices.Contains(e.DataTypes, dt) {
				e.DataTypes = append(e.DataTypes, dt)
				sort.Strings(e.DataTypes)
			}
		}
	}
	for _, f := range flows {
		steps := f.Calls
		if len(steps) == 0 {
			steps = []finding.CallStep{{Function: f.Function, Pos: f.Sink}}
		}
		// One source node per thing read (field Customer.email), wherever
		// it is read.
		what := f.SourceDesc
		if what == "" {
			what = short(f.Source.String())
		}
		src := node("src:"+f.DataType+":"+what, Source, f.DataType, what, f.Severity)
		prev := src.ID
		for _, s := range steps {
			n := node("fn:"+s.Function, Function, shortFunc(s.Function), "", f.Severity)
			if n.Detail == "" {
				n.Detail = short(s.Pos.File)
			}
			edge(prev, n.ID, f.DataType, false)
			prev = n.ID
		}
		sinkID := fmt.Sprintf("sink:%s:%s", f.SinkRule, f.Sink)
		sink := node(sinkID, Sink, sinkLabel(f), short(f.Sink.String()), f.Severity)
		sink.Dest = f.Dest.Kind
		edge(prev, sink.ID, f.DataType, false)
		entry := "fn:" + steps[0].Function
		for _, c := range f.CalledBy {
			n := node("fn:"+c, Caller, shortFunc(c), "", "")
			edge(n.ID, entry, "", true)
		}
	}
	return g
}

func sinkLabel(f *finding.Flow) string {
	call := f.SinkCall
	if call == "" {
		call = f.SinkRule
	}
	dest := f.Dest.Vendor
	if dest == "" {
		dest = f.Dest.Host
	}
	if dest == "" {
		dest = f.Dest.Kind
	}
	return shortFunc(call) + " → " + dest
}

// shortFunc keeps the last two segments of a qualified name
// (com.example.app.Repo.save → Repo.save).
func shortFunc(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '/' || r == ':' })
	if len(parts) <= 2 {
		return s
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// short keeps the file name and line of a location.
func short(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// Renderer renders flow graphs (the CLI's FlowGrapher).
type Renderer struct{}

// Render builds the graph of flows and writes it in format.
func (Renderer) Render(w io.Writer, format string, flows []*finding.Flow) error {
	g := Build(flows)
	switch format {
	case "svg":
		return SVG(w, g)
	case "dot":
		return DOT(w, g)
	case "mermaid":
		return Mermaid(w, g)
	}
	return fmt.Errorf("unknown graph format %q (%s)", format, strings.Join(Formats, ", "))
}

// destColors color sinks by destination kind.
var destColors = map[string]string{
	"third_party": "#d64545", "log": "#d9822b", "storage": "#8e5cc7", "network": "#2f8f9d",
	"ipc": "#c2489b", "first_party": "#5c8a3a",
}

func sinkColor(dest string) string {
	if c, ok := destColors[dest]; ok {
		return c
	}
	return "#777777"
}

// DOT writes the graph for Graphviz (dot -Tpng graph.dot -o graph.png).
func DOT(w io.Writer, g *Graph) error {
	var b strings.Builder
	b.WriteString("digraph datawarden {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=11];\n  edge [fontname=\"Helvetica\", fontsize=9];\n")
	for _, n := range g.Nodes {
		fill, font := "#f2f2f2", "#222222"
		switch n.Kind {
		case Source:
			fill, font = "#2f6fce", "#ffffff"
		case Sink:
			fill, font = sinkColor(n.Dest), "#ffffff"
		case Caller:
			fill = "#fafafa"
		}
		fmt.Fprintf(&b, "  %q [label=%q, fillcolor=%q, fontcolor=%q", n.ID, n.Label+"\n"+n.Detail, fill, font)
		if n.Kind == Caller {
			b.WriteString(", style=\"rounded,dashed\"")
		}
		b.WriteString("];\n")
	}
	for _, e := range g.Edges {
		if e.Calls {
			fmt.Fprintf(&b, "  %q -> %q [style=dashed, color=\"#999999\", label=\"calls\"];\n", e.From, e.To)
			continue
		}
		fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", e.From, e.To, strings.Join(e.DataTypes, ", "))
	}
	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// Mermaid writes the graph as a Mermaid flowchart (GitHub renders it in
// Markdown).
func Mermaid(w io.Writer, g *Graph) error {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	ids := map[string]string{}
	for i, n := range g.Nodes {
		id := fmt.Sprintf("n%d", i)
		ids[n.ID] = id
		label := strings.NewReplacer(`"`, "'").Replace(n.Label + "<br/><small>" + n.Detail + "</small>")
		switch n.Kind {
		case Source:
			fmt.Fprintf(&b, "  %s([\"%s\"])\n", id, label)
		case Sink:
			fmt.Fprintf(&b, "  %s[[\"%s\"]]\n", id, label)
		default:
			fmt.Fprintf(&b, "  %s[\"%s\"]\n", id, label)
		}
	}
	for _, e := range g.Edges {
		if e.Calls {
			fmt.Fprintf(&b, "  %s -.->|calls| %s\n", ids[e.From], ids[e.To])
			continue
		}
		fmt.Fprintf(&b, "  %s -->|%s| %s\n", ids[e.From], strings.Join(e.DataTypes, ", "), ids[e.To])
	}
	for _, n := range g.Nodes {
		switch n.Kind {
		case Source:
			fmt.Fprintf(&b, "  style %s fill:#2f6fce,color:#fff,stroke:#2f6fce\n", ids[n.ID])
		case Sink:
			c := sinkColor(n.Dest)
			fmt.Fprintf(&b, "  style %s fill:%s,color:#fff,stroke:%s\n", ids[n.ID], c, c)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
