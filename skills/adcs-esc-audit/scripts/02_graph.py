#!/usr/bin/env python3
"""Generic attack-path graph generator.

Uses working/results.json graph nodes/edges derived from the current dataset only.
No client-specific tokens or hard-coded paths are embedded.
"""
from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import textwrap

WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
R = json.load(open(os.path.join(WK, "results.json"), encoding="utf-8"))
os.makedirs(OUT, exist_ok=True)

try:
    import cairosvg  # type: ignore
except Exception:  # pragma: no cover
    cairosvg = None

W = 2000
BG = "#0f1115"
DIV = "#2a2f3a"
INK = "#e8edf4"
SUB = "#9aa6b6"
COL = {
    "Critical": "#d85a5a",
    "High": "#e08a57",
    "Medium": "#e0b020",
    "Low": "#59b981",
    "Clean": "#3f8f5b",
    "Mitigated": "#2a9d8f",
    "Not evaluated": "#6b7482",
    "Not Evaluated": "#6b7482",
}
NODE_FILL = {
    "Principal/Object": "#4f9fe0",
    "ESC finding": "#ab8fd6",
    "Impact/target": "#e0b020",
}
RED = "#e0524e"
GOLD = "#e0b020"
GREY = "#7c879a"
LANES = ["Principal/Object", "ESC finding", "Impact/target"]
NW, NH = 260, 72
ROW_PITCH = 98
GRAPH_TOP = 170
LEGEND_H = 178


def esc(s):
    return html.escape(str(s), quote=True)


def trunc(s, n=30):
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def node_label_lines(value):
    label = str(value or "node")
    if len(label) <= 29:
        return [label]
    if " " not in label:
        if "_" in label:
            prefix, digest = label.split("_", 1)
            return [trunc(prefix + "_", 15), trunc(digest, 23)]
        return [trunc(label, 27)]
    wrapped = textwrap.wrap(label, width=27, break_long_words=False, break_on_hyphens=False)
    if len(wrapped) <= 2:
        return wrapped
    return [wrapped[0], trunc(" ".join(wrapped[1:]), 28)]


graph = R.get("graph") or {"nodes": [], "edges": []}
nodes_in = graph.get("nodes", [])
edges_in = graph.get("edges", [])
lane_nodes = {lane: [] for lane in LANES}
for node in nodes_in:
    lane = node.get("kind", "Principal/Object")
    if lane not in lane_nodes:
        lane = "Principal/Object"
    lane_nodes[lane].append(node)
for lane in LANES:
    lane_nodes[lane] = lane_nodes[lane][:14]

max_lane_count = max([len(lane_nodes[lane]) for lane in LANES] + [1])
if nodes_in:
    graph_height = (max_lane_count - 1) * ROW_PITCH + NH
    graph_bottom = GRAPH_TOP + graph_height + 34
else:
    graph_bottom = 650
legend_y = graph_bottom + 34
H = legend_y + LEGEND_H + 48

svg = []
svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Segoe UI, Arial, sans-serif">')
svg.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
svg.append("<defs>")
for marker_name, marker_color in [
    ("critical", COL["Critical"]),
    ("high", COL["High"]),
    ("medium", COL["Medium"]),
    ("low", COL["Low"]),
    ("mitigated", COL["Mitigated"]),
    ("default", GREY),
]:
    svg.append(
        f'<marker id="arrow-{marker_name}" markerWidth="11" markerHeight="11" '
        f'refX="9" refY="3.2" orient="auto"><path d="M0,0 L9,3.2 L0,6.4 z" '
        f'fill="{marker_color}"/></marker>'
    )
svg.append("</defs>")
svg.append('<style>.nd{cursor:pointer}.nd:hover rect{stroke:#fff;stroke-width:3}</style>')
svg.append(f'<text x="46" y="58" fill="{INK}" font-size="34" font-weight="700">CertifEye - AD CS Attack-Path Graph</text>')
svg.append(f'<text x="48" y="90" fill="{SUB}" font-size="18">generated from the current scrubbed dataset · no client-specific paths are hard-coded</text>')

positions = {}

if not nodes_in:
    svg.append(f'<rect x="180" y="250" width="1640" height="280" rx="18" fill="#141821" stroke="{DIV}"/>')
    svg.append(f'<text x="1000" y="375" fill="{INK}" font-size="30" text-anchor="middle" font-weight="700">No open attack-path findings were generated</text>')
    svg.append(f'<text x="1000" y="425" fill="{SUB}" font-size="19" text-anchor="middle">Review the coverage matrix for clean, mitigated, and not-evaluated ESC areas.</text>')
else:
    # Arrange nodes by kind into three lanes: source -> ESC -> impact.
    x_for = {"Principal/Object": 80, "ESC finding": 870, "Impact/target": 1660}
    max_graph_height = (max_lane_count - 1) * ROW_PITCH + NH
    for lane in LANES:
        items = lane_nodes.get(lane, [])
        count = max(1, len(items))
        lane_height = (count - 1) * ROW_PITCH + NH
        start_y = GRAPH_TOP + max(0, (max_graph_height - lane_height) // 2)
        svg.append(f'<text x="{x_for[lane]+NW/2}" y="135" fill="{SUB}" font-size="17" font-weight="700" letter-spacing="1.5" text-anchor="middle">{esc(lane.upper())}</text>')
        for i, n in enumerate(items):
            x = x_for[lane]
            y = start_y + i * ROW_PITCH
            positions[n["id"]] = (x + NW / 2, y + NH / 2, x, y)
            fill = NODE_FILL.get(lane, "#4f9fe0")
            sev = n.get("severity") or ""
            stroke = COL.get(sev, "#1b1e25")
            label = str(n.get("label", "node"))
            lines = node_label_lines(label)
            fs = 15 if len(lines) == 1 and len(lines[0]) <= 20 else 13.5
            tip = f"{n.get('kind','Node')}\n{n.get('label','')}\nSeverity: {sev or 'n/a'}"
            svg.append(f'<g class="nd"><title>{esc(tip)}</title>')
            svg.append(f'<rect class="node-box" x="{x}" y="{y}" rx="11" ry="11" width="{NW}" height="{NH}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
            if len(lines) == 1:
                svg.append(f'<text x="{x+NW/2}" y="{y+NH/2+5}" fill="#10131a" font-size="{fs}" font-weight="700" text-anchor="middle">{esc(lines[0])}</text>')
            else:
                svg.append(f'<text x="{x+NW/2}" y="{y+NH/2-7}" fill="#10131a" font-size="{fs}" font-weight="700" text-anchor="middle">')
                svg.append(f'<tspan x="{x+NW/2}" dy="0">{esc(lines[0])}</tspan>')
                svg.append(f'<tspan x="{x+NW/2}" dy="18">{esc(lines[1])}</tspan></text>')
            if sev:
                svg.append(f'<text x="{x+NW/2}" y="{y+NH+20}" fill="{COL.get(sev, SUB)}" font-size="13.5" font-weight="700" text-anchor="middle">{esc(sev)}</text>')
            svg.append('</g>')

    def draw_edge(e):
        s = e.get("source")
        t = e.get("target")
        if s not in positions or t not in positions:
            return
        x1, y1, _, _ = positions[s]
        x2, y2, _, _ = positions[t]
        sx = x1 + NW / 2 if x2 > x1 else x1 - NW / 2
        ex = x2 - NW / 2 if x2 > x1 else x2 + NW / 2
        severity = str(e.get("severity") or "")
        color = COL.get(severity, GREY)
        marker_key = severity.lower() if severity.lower() in {"critical", "high", "medium", "low", "mitigated"} else "default"
        c1 = sx + (ex - sx) * 0.36
        c2 = sx + (ex - sx) * 0.64
        edge_label = str(e.get("label") or "")
        tip = f"{edge_label or 'evidence relationship'}\nSeverity: {severity or 'n/a'}"
        svg.append(f'<g class="edge"><title>{esc(tip)}</title>')
        svg.append(f'<path d="M {sx:.0f} {y1:.0f} C {c1:.0f} {y1:.0f}, {c2:.0f} {y2:.0f}, {ex:.0f} {y2:.0f}" fill="none" stroke="{color}" stroke-width="2.2" stroke-opacity="0.9" marker-end="url(#arrow-{marker_key})"/>')
        # Severity and "can enable" are already conveyed by node captions, colors,
        # arrow direction, and tooltips. Repeating them on every dense edge causes
        # label collisions without adding evidence.
        if edge_label and edge_label not in set(COL) | {"can enable"}:
            lx = sx + (ex - sx) * 0.45
            ly = y1 + (y2 - y1) * 0.45 - 9
            svg.append(f'<text x="{lx:.0f}" y="{ly:.0f}" fill="{color}" stroke="{BG}" stroke-width="6" paint-order="stroke" font-size="13.5" font-weight="700" text-anchor="middle">{esc(trunc(edge_label, 28))}</text>')
        svg.append("</g>")

    for e in edges_in[:28]:
        draw_edge(e)

# Legend occupies a reserved band below the graph body and can never cover nodes.
lx, ly, legend_w = 80, legend_y, W - 160
svg.append('<g id="graph-legend">')
svg.append(f'<rect id="legend-panel" x="{lx}" y="{ly}" rx="12" width="{legend_w}" height="{LEGEND_H}" fill="#141821" stroke="{DIV}"/>')
svg.append(f'<text x="{lx+24}" y="{ly+34}" fill="{INK}" font-size="19" font-weight="700">Legend</text>')
severities = ["Critical", "High", "Medium", "Low", "Mitigated", "Not evaluated"]
slot = (legend_w - 48) / len(severities)
for i, sev in enumerate(severities):
    x = lx + 24 + i * slot
    y = ly + 70
    svg.append(f'<rect x="{x:.0f}" y="{y-15}" width="26" height="18" rx="4" fill="{COL[sev]}"/>')
    svg.append(f'<text x="{x+36:.0f}" y="{y}" fill="{INK}" font-size="14.5">{esc(sev)}</text>')
node_y = ly + 119
for i, (kind, fill) in enumerate(NODE_FILL.items()):
    x = lx + 24 + i * 300
    svg.append(f'<rect x="{x}" y="{node_y-15}" width="26" height="18" rx="4" fill="{fill}"/>')
    svg.append(f'<text x="{x+36}" y="{node_y}" fill="{INK}" font-size="14.5">{esc(kind)}</text>')
svg.append(f'<text x="{lx+950}" y="{node_y}" fill="{SUB}" font-size="14">Arrows connect evidence → finding → impact and inherit finding severity.</text>')
svg.append(f'<text x="{lx+950}" y="{node_y+31}" fill="{SUB}" font-size="14">Only the highest-priority current-run findings are shown; hover nodes for full labels.</text>')
svg.append('</g>')
svg.append('</svg>')
svg_text = "\n".join(svg)

svg_path = os.path.join(OUT, "ADCS_Attack_Path_Graph.svg")
png_path = os.path.join(OUT, "ADCS_Attack_Path_Graph.png")
open(svg_path, "w", encoding="utf-8").write(svg_text)
if cairosvg:
    cairosvg.svg2png(bytestring=svg_text.encode("utf-8"), write_to=png_path, output_width=W)
    print("Wrote ADCS_Attack_Path_Graph.svg + .png")
else:
    # ImageMagick is an optional local fallback. SVG remains authoritative and
    # an unavailable rasterizer never creates or advertises an empty PNG.
    magick = shutil.which("magick")
    rendered = False
    if magick:
        proc = subprocess.run(
            [magick, svg_path, "-strip", png_path],
            capture_output=True,
            text=True,
        )
        rendered = proc.returncode == 0 and os.path.exists(png_path) and os.path.getsize(png_path) > 0
    if rendered:
        print("Wrote ADCS_Attack_Path_Graph.svg + .png (ImageMagick fallback)")
    else:
        if os.path.exists(png_path):
            os.remove(png_path)
        print("Wrote ADCS_Attack_Path_Graph.svg; PNG unavailable (install CairoSVG or ImageMagick).")
