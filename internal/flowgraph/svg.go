// Copyright 2026 The datawarden Authors
// SPDX-License-Identifier: Apache-2.0

package flowgraph

import (
	"fmt"
	"html"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// Layout of the SVG: a layered drawing, left to right. Each node gets the
// layer of the longest path reaching it (cycles are broken first), nodes
// in a layer are ordered to keep edges short (barycenter sweeps), and
// edges are drawn as curves labelled with the data types they carry.

const (
	nodeH    = 44
	rowGap   = 18
	colGap   = 90
	margin   = 24
	headerH  = 64
	labelPx  = 7.4 // approximate width of a 12px bold character
	detailPx = 6.0 // of a 10px character
)

type placed struct {
	*Node
	layer, order int
	x, y, w      float64
}

// SVG writes the graph as a standalone SVG image.
func SVG(w io.Writer, g *Graph) error {
	ps, height, width := layout(g)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" font-family="-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif">`+"\n", width, height, width, height)
	b.WriteString(`<style>
  .bg { fill: #ffffff; }
  .title { fill: #1f2328; font-size: 16px; font-weight: 600; }
  .sub, .detail, .elabel { fill: #59636e; }
  .sub { font-size: 12px; }
  .detail { font-size: 10px; }
  .label { font-size: 12px; font-weight: 600; fill: #1f2328; }
  .fn rect { fill: #f6f8fa; stroke: #d0d7de; }
  .caller rect { fill: #ffffff; stroke: #d0d7de; stroke-dasharray: 4 3; }
  .source rect { fill: #2f6fce; stroke: #2f6fce; }
  .source .label, .source .detail, .sink .label, .sink .detail { fill: #ffffff; }
  .edge { fill: none; stroke: #8c959f; stroke-width: 1.4; }
  .edge.calls { stroke-dasharray: 5 4; stroke: #afb8c1; }
  .elabel { font-size: 10px; }
  .elabg { fill: #ffffff; opacity: 0.85; }
  .arrow { fill: #8c959f; }
  @media (prefers-color-scheme: dark) {
    .bg { fill: #0d1117; }
    .title, .label { fill: #e6edf3; }
    .sub, .detail, .elabel { fill: #9198a1; }
    .fn rect { fill: #161b22; stroke: #3d444d; }
    .caller rect { fill: #0d1117; stroke: #3d444d; }
    .edge { stroke: #6e7681; }
    .edge.calls { stroke: #484f58; }
    .elabg { fill: #0d1117; }
    .arrow { fill: #6e7681; }
  }
</style>
<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrow" d="M 0 0 L 10 5 L 0 10 z"/></marker></defs>
`)
	fmt.Fprintf(&b, `<rect class="bg" width="%.0f" height="%.0f"/>`+"\n", width, height)
	sinks := 0
	for _, p := range ps {
		if p.Kind == Sink {
			sinks++
		}
	}
	fmt.Fprintf(&b, `<text class="title" x="%d" y="%d">Personal data flows</text>`+"\n", margin, margin+8)
	fmt.Fprintf(&b, `<text class="sub" x="%d" y="%d">%d flow(s) · %d sink(s) · sources → functions → sinks · dashed: callers</text>`+"\n", margin, margin+28, g.Flows, sinks)
	// Legend: the destination kinds present.
	var kinds []string
	for _, p := range ps {
		if p.Kind == Sink && !slices.Contains(kinds, p.Dest) {
			kinds = append(kinds, p.Dest)
		}
	}
	sort.Strings(kinds)
	lx := width - margin
	for i := len(kinds) - 1; i >= 0; i-- {
		label := strings.ReplaceAll(kinds[i], "_", " ")
		lw := float64(utf8.RuneCountInString(label))*detailPx + 22
		lx -= lw
		fmt.Fprintf(&b, `<rect x="%.1f" y="%d" width="10" height="10" rx="2" style="fill:%s"/><text class="sub" x="%.1f" y="%d">%s</text>`+"\n", lx, margin+19, sinkColor(kinds[i]), lx+14, margin+28, html.EscapeString(label))
		lx -= 8
	}

	byID := map[string]*placed{}
	for _, p := range ps {
		byID[p.ID] = p
	}
	// Edges below the nodes.
	for _, e := range g.Edges {
		from, to := byID[e.From], byID[e.To]
		if from == nil || to == nil {
			continue
		}
		x1, y1 := from.x+from.w, from.y+nodeH/2
		x2, y2 := to.x, to.y+nodeH/2
		var d string
		if to.layer > from.layer {
			dx := (x2 - x1) / 2
			d = fmt.Sprintf("M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f", x1, y1, x1+dx, y1, x2-dx, y2, x2-2, y2)
		} else {
			// Back to an earlier layer: loop below the nodes.
			low := max(from.y, to.y) + nodeH + rowGap
			d = fmt.Sprintf("M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f", from.x+from.w/2, from.y+nodeH, from.x+from.w/2, low+30, to.x+to.w/2, low+30, to.x+to.w/2, to.y+nodeH+2)
		}
		class := "edge"
		if e.Calls {
			class += " calls"
		}
		fmt.Fprintf(&b, `<path class="%s" d="%s" marker-end="url(#arrow)"/>`+"\n", class, d)
		if label := strings.Join(e.DataTypes, ", "); label != "" && to.layer > from.layer {
			mx, my := (x1+x2)/2, (y1+y2)/2
			lw := float64(utf8.RuneCountInString(label))*detailPx + 8
			fmt.Fprintf(&b, `<rect class="elabg" x="%.1f" y="%.1f" width="%.1f" height="14" rx="3"/>`, mx-lw/2, my-10, lw)
			fmt.Fprintf(&b, `<text class="elabel" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`+"\n", mx, my+1, html.EscapeString(label))
		}
	}
	for _, p := range ps {
		class := "fn"
		style := ""
		switch p.Kind {
		case Source:
			class = "source"
		case Sink:
			class = "sink"
			c := sinkColor(p.Dest)
			style = fmt.Sprintf(` style="fill:%s;stroke:%s"`, c, c)
		case Caller:
			class = "caller"
		}
		fmt.Fprintf(&b, `<g class="%s"><title>%s</title>`, class, html.EscapeString(p.ID))
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%d" rx="8"%s/>`, p.x, p.y, p.w, nodeH, style)
		fmt.Fprintf(&b, `<text class="label" x="%.1f" y="%.1f">%s</text>`, p.x+10, p.y+18, html.EscapeString(p.Label))
		fmt.Fprintf(&b, `<text class="detail" x="%.1f" y="%.1f">%s</text></g>`+"\n", p.x+10, p.y+33, html.EscapeString(p.Detail))
	}
	if len(ps) == 0 {
		fmt.Fprintf(&b, `<text class="sub" x="%d" y="%d">No flows to draw.</text>`+"\n", margin, headerH+margin)
	}
	b.WriteString("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func nodeWidth(n *Node) float64 {
	w := max(float64(utf8.RuneCountInString(n.Label))*labelPx, float64(utf8.RuneCountInString(n.Detail))*detailPx)
	return min(w+20, 420)
}

// layout places the nodes and returns them with the image's size.
func layout(g *Graph) ([]*placed, float64, float64) {
	idx := map[string]int{}
	ps := make([]*placed, len(g.Nodes))
	for i, n := range g.Nodes {
		idx[n.ID] = i
		ps[i] = &placed{Node: n, w: nodeWidth(n)}
	}
	succ := make([][]int, len(ps))
	pred := make([][]int, len(ps))
	for _, e := range g.Edges {
		a, b := idx[e.From], idx[e.To]
		succ[a] = append(succ[a], b)
	}
	// Break cycles: an edge to a node on the DFS stack is a back edge and
	// does not count for layering.
	state := make([]int, len(ps)) // 0 new, 1 on stack, 2 done
	forward := make([][]int, len(ps))
	var dfs func(int)
	dfs = func(v int) {
		state[v] = 1
		for _, s := range succ[v] {
			switch state[s] {
			case 0:
				forward[v] = append(forward[v], s)
				dfs(s)
			case 2:
				forward[v] = append(forward[v], s)
			}
		}
		state[v] = 2
	}
	order := make([]int, len(ps))
	for i := range order {
		order[i] = i
	}
	// Roots first: sources and callers, then everything else.
	sort.SliceStable(order, func(i, j int) bool { return rootRank(ps[order[i]].Kind) < rootRank(ps[order[j]].Kind) })
	for _, v := range order {
		if state[v] == 0 {
			dfs(v)
		}
	}
	for v, ss := range forward {
		for _, s := range ss {
			pred[s] = append(pred[s], v)
		}
	}
	// Longest-path layers over the forward edges (a DAG).
	indeg := make([]int, len(ps))
	for _, ss := range forward {
		for _, s := range ss {
			indeg[s]++
		}
	}
	var queue []int
	for _, v := range order {
		if indeg[v] == 0 {
			queue = append(queue, v)
		}
	}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		for _, s := range forward[v] {
			ps[s].layer = max(ps[s].layer, ps[v].layer+1)
			if indeg[s]--; indeg[s] == 0 {
				queue = append(queue, s)
			}
		}
	}
	// A sink sits one layer after its last function, a caller one layer
	// before the function it calls.
	for v, p := range ps {
		if p.Kind == Caller && len(forward[v]) > 0 {
			low := ps[forward[v][0]].layer
			for _, s := range forward[v] {
				low = min(low, ps[s].layer)
			}
			p.layer = max(0, low-1)
		}
	}
	nLayers := 0
	for _, p := range ps {
		if p.Kind != Sink {
			nLayers = max(nLayers, p.layer+1)
		}
	}
	// Every sink in the last column, grouped by destination.
	for _, p := range ps {
		if p.Kind == Sink {
			p.layer = nLayers
		}
	}
	nLayers++
	sort.SliceStable(order, func(i, j int) bool {
		a, b := ps[order[i]], ps[order[j]]
		return a.Kind == Sink && b.Kind == Sink && a.Dest < b.Dest
	})
	layers := make([][]int, nLayers)
	for _, v := range order {
		layers[ps[v].layer] = append(layers[ps[v].layer], v)
	}
	// Barycenter sweeps: order each layer by the mean position of its
	// neighbours in the previous (then next) layer.
	pos := func() {
		for _, l := range layers {
			for i, v := range l {
				ps[v].order = i
			}
		}
	}
	pos()
	for sweep := 0; sweep < 4; sweep++ {
		for li := range layers {
			l := li
			nb := pred
			if sweep%2 == 1 {
				l = len(layers) - 1 - li
				nb = forward
			}
			key := map[int]float64{}
			for _, v := range layers[l] {
				sum, n := 0.0, 0
				for _, u := range nb[v] {
					sum += float64(ps[u].order)
					n++
				}
				if n > 0 {
					key[v] = sum / float64(n)
				} else {
					key[v] = float64(ps[v].order)
				}
			}
			sort.SliceStable(layers[l], func(i, j int) bool { return key[layers[l][i]] < key[layers[l][j]] })
			for i, v := range layers[l] {
				ps[v].order = i
			}
		}
	}
	// Coordinates: columns as wide as their widest node, each column
	// centred on the tallest.
	colW := make([]float64, nLayers)
	tallest := 0
	for li, l := range layers {
		for _, v := range l {
			colW[li] = max(colW[li], ps[v].w)
		}
		tallest = max(tallest, len(l))
	}
	totalH := float64(tallest)*(nodeH+rowGap) - rowGap
	x := float64(margin)
	for li, l := range layers {
		colH := float64(len(l))*(nodeH+rowGap) - rowGap
		y := float64(headerH+margin) + (totalH-colH)/2
		for _, v := range l {
			ps[v].x = x + (colW[li]-ps[v].w)/2
			if li == nLayers-1 {
				ps[v].x = x // sinks line up on the left
			}
			ps[v].y = y
			y += nodeH + rowGap
		}
		x += colW[li] + colGap
	}
	width := max(x-colGap+margin, 720)
	height := float64(headerH+2*margin) + max(totalH, 0) + 60 // room for loops below
	return ps, height, width
}

func rootRank(k Kind) int {
	switch k {
	case Source:
		return 0
	case Caller:
		return 1
	case Function:
		return 2
	}
	return 3
}
