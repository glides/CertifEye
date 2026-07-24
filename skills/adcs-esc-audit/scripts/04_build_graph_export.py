#!/usr/bin/env python3
"""Build generic graph export JSON + Cypher from the current findings graph."""
from __future__ import annotations

import json
import hashlib
import os

WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
R = json.load(open(os.path.join(WK, "results.json"), encoding="utf-8"))
os.makedirs(OUT, exist_ok=True)

graph = R.get("graph") or {"nodes": [], "edges": []}

nodes = []
for n in graph.get("nodes", []):
    kinds = ["Base"]
    kind = n.get("kind", "Node")
    if "Principal" in kind:
        kinds.append("User")
    elif "ESC" in kind:
        kinds.append("Finding")
    else:
        kinds.append("Object")
    nodes.append({
        "id": n.get("id"),
        "kinds": kinds,
        "label": n.get("label"),
        "props": {"kind": kind, "severity": n.get("severity", "")},
    })

edges = []
for i, e in enumerate(graph.get("edges", []), 1):
    edges.append({
        "id": f"e{i:03d}",
        "source": e.get("source"),
        "target": e.get("target"),
        "type": "ADCS_ESC_EDGE",
        "kind": "ABUSABLE" if e.get("esc") else "STRUCTURAL",
        "props": {"label": e.get("label", ""), "primitive": e.get("label", ""), "esc": e.get("esc", ""), "severity": e.get("severity", "")},
    })

json_path = os.path.join(OUT, "ADCS_Attack_Path_BloodHound.json")
with open(json_path, "w", encoding="utf-8") as f:
    payload = {
        "meta": {"schemaVersion": "adcs-graph/v1", "source": "current scrubbed AD CS findings"},
        "graph": {"nodes": nodes, "edges": edges},
        # Keep top-level aliases for older consumers while the versioned graph
        # envelope becomes the canonical contract.
        "nodes": nodes,
        "edges": edges,
    }
    json.dump(payload, f, indent=2, ensure_ascii=False)


def cypher_escape(s):
    return str(s or "").replace("\\", "\\\\").replace("'", "\\'")

lines = ["// Generic AD CS ESC graph generated from current audit findings", "CREATE"]
parts = []
for n in nodes:
    var = "n" + hashlib.sha256(str(n["id"]).encode("utf-8")).hexdigest()[:12]
    n["var"] = var
    labels = ":".join(n["kinds"])
    parts.append(f"({var}:{labels} {{id:'{cypher_escape(n['id'])}', label:'{cypher_escape(n['label'])}', kind:'{cypher_escape(n['props']['kind'])}', severity:'{cypher_escape(n['props']['severity'])}'}})")
var_by_id = {n["id"]: n["var"] for n in nodes}
for ed in edges:
    if ed["source"] in var_by_id and ed["target"] in var_by_id:
        parts.append(f"({var_by_id[ed['source']]})-[:ADCS_ESC_EDGE {{label:'{cypher_escape(ed['props']['label'])}', esc:'{cypher_escape(ed['props']['esc'])}', severity:'{cypher_escape(ed['props']['severity'])}'}}]->({var_by_id[ed['target']]})")
if parts:
    lines.append(",\n".join(parts) + ";")
else:
    lines.append("// No graph findings were generated for this dataset.")
open(os.path.join(OUT, "ADCS_Attack_Path.cypher"), "w", encoding="utf-8").write("\n".join(lines))
print("Wrote ADCS_Attack_Path_BloodHound.json + ADCS_Attack_Path.cypher")
