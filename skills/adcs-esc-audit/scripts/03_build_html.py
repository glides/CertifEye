#!/usr/bin/env python3
"""Generic interactive attack-path HTML report."""
from __future__ import annotations

import html
import json
import os

WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
LOCAL_ONLY = os.environ.get("ADCS_AUDIT_LOCAL_ONLY", "").strip() == "1"
R = json.load(open(os.path.join(WK, "results.json"), encoding="utf-8"))
os.makedirs(OUT, exist_ok=True)

svg_path = os.path.join(OUT, "ADCS_Attack_Path_Graph.svg")
svg = open(svg_path, encoding="utf-8").read() if os.path.exists(svg_path) else ""

def e(s):
    return html.escape(str(s or ""))

SEVC = {"Critical": "#b00020", "High": "#d9534f", "Medium": "#d99a00", "Low": "#3f8f5b", "Clean": "#3f8f5b", "Mitigated": "#2a9d8f", "Not evaluated": "#6b7482", "Not Evaluated": "#6b7482"}
ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

def pill(t, c=None):
    c = c or SEVC.get(t, "#555")
    return f'<span class="pill" style="background:{c}">{e(t)}</span>'

m = R.get("meta", {})
sev = R.get("sev_counts", {})
findings = sorted(R.get("findings", []), key=lambda f: (-ORDER.get(f.get("Severity"), 0), f.get("FindingID", "")))

PATH_TITLES = {
    "ESC1": "Requester-supplied identity path",
    "ESC2": "Broad-purpose certificate path",
    "ESC3": "Enrollment-agent / on-behalf-of path",
    "ESC4": "Template-control path",
    "ESC5": "PKI control-plane path",
    "ESC6": "CA SAN-attribute path",
    "ESC7": "CA administration path",
    "ESC8": "Web-enrollment relay prerequisite",
    "ESC9/10": "Weak certificate-mapping path",
    "ESC11": "Unencrypted RPC enrollment path",
}

kpis = [
    ("Critical", sev.get("Critical", 0), SEVC["Critical"]),
    ("High", sev.get("High", 0), SEVC["High"]),
    ("Medium", sev.get("Medium", 0), SEVC["Medium"]),
    ("Total findings", len(findings), "#15365c"),
    ("ESC1 templates", len(R.get("esc1_templates", [])), "#15365c"),
    ("Input files", sum(len(v) for v in m.get("input_files", {}).values()), "#15365c"),
]
kpi_html = "".join(f'<div class="kpi"><div class="kn" style="color:{c}">{v}</div><div class="kl">{e(l)}</div></div>' for l, v, c in kpis)

cov_rows = "".join(f'<tr><td><b>{e(esc)}</b></td><td>{pill(st)}</td><td>{e(note)}</td></tr>' for esc, st, note in R.get("coverage", []))

fr = ""
for f in findings:
    fr += (
        f'<tr><td>{e(f.get("FindingID"))}</td><td>{pill(f.get("Severity"))}</td>'
        f'<td>{e(f.get("Confidence"))}</td><td>{e(f.get("Category"))}</td>'
        f'<td>{e(f.get("Object") or f.get("Principal"))}</td>'
        f'<td>{e(f.get("Evidence"))}</td></tr>'
    )
if not fr:
    fr = '<tr><td colspan="6">No findings were generated from the supplied data.</td></tr>'

primary = []
seen_esc = set()
for finding in findings:
    esc_type = finding.get("ESCType", "")
    if finding.get("Severity") not in {"Critical", "High"} or esc_type in seen_esc:
        continue
    seen_esc.add(esc_type)
    primary.append(finding)
    if len(primary) == 4:
        break

path_cards = ""
for finding in primary:
    source = finding.get("Principal") or finding.get("Object") or "Current-run evidence"
    target = finding.get("Target") or finding.get("Object") or "PKI security posture"
    severity = finding.get("Severity", "High")
    path_cards += f"""
    <article class="pathcard" style="--path-color:{SEVC.get(severity, '#d9534f')}">
      <h3>{e(PATH_TITLES.get(finding.get("ESCType"), "Evidence-backed attack-path prerequisite"))} ({e(finding.get("ESCType"))})</h3>
      <div class="pathflow">
        <span class="pathnode">{e(source)}</span>
        <span class="patharrow">evidence supports →</span>
        <span class="pathnode findingref">{e(finding.get("FindingID"))}</span>
        <span class="patharrow">can affect →</span>
        <span class="pathnode">{e(target)}</span>
      </div>
      <p>{e(finding.get("WhyThisMatters") or finding.get("Evidence"))}</p>
    </article>"""
if not path_cards:
    path_cards = '<p class="sub">No Critical or High evidence-backed paths were generated. Review coverage before treating the environment as clean.</p>'

top = findings[:6]
todo = []
top_by_esc = {}
for finding in top:
    top_by_esc.setdefault(finding.get("ESCType", "Other"), []).append(finding)
for esc_type, grouped in top_by_esc.items():
    refs = ", ".join(f.get("FindingID", "") for f in grouped)
    validation = next((f.get("RecommendedValidation") for f in grouped if f.get("RecommendedValidation")), "Validate the current-run evidence with the PKI owner.")
    todo.append(f'Validate {esc_type} findings ({len(grouped)}; {refs}): {validation}')
    remediation = next((f.get("RecommendedRemediation") for f in grouped if f.get("Severity") in {"Critical", "High"} and f.get("RecommendedRemediation")), None)
    if remediation:
        todo.append(f'Remediate {esc_type} findings ({len(grouped)}; {refs}): {remediation}')
if not todo:
    todo = ["Review the coverage matrix for any Not evaluated areas and collect missing exports if needed."]
todo_html = "".join(f'<li>{e(t)}</li>' for t in todo[:10])

clean = [f"{esc} — {note}" for esc, st, note in R.get("coverage", []) if st in {"Clean", "Mitigated"}]
not_eval = [f"{esc} — {note}" for esc, st, note in R.get("coverage", []) if st in {"Not evaluated", "Not Evaluated"}]
clean_html = "".join(f'<li>{e(c)}</li>' for c in clean) or "<li>No clean/mitigated areas were computed from the supplied data.</li>"
not_eval_html = "".join(f'<li>{e(c)}</li>' for c in not_eval) or "<li>All supported ESC areas had at least one relevant input source.</li>"

input_items = []
for role, files in m.get("input_files", {}).items():
    input_items.append(f"{role}: {', '.join(files)}")
input_html = "".join(f'<li>{e(x)}</li>' for x in input_items) or "<li>No recognized CSV inputs were loaded.</li>"

HTML = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>CertifEye - AD CS ESC Attack-Path Report</title>
<style>
body{{margin:0;background:#0f1115;color:#e8edf4;font-family:'Segoe UI',Arial,sans-serif;line-height:1.5}}
.wrap{{max-width:1600px;margin:0 auto;padding:32px}}
h1{{font-size:30px;margin:0 0 4px}} h2{{color:#7fb6e6;border-bottom:2px solid #2a9d8f;padding-bottom:6px;margin-top:38px}}
.sub{{color:#9aa6b6;margin:0 0 18px}}
.strip{{display:flex;flex-wrap:wrap;gap:18px;background:#141821;border:1px solid #2a2f3a;border-radius:10px;padding:14px 18px;font-size:13.5px}}
.strip b{{color:#fff}}
.kpis{{display:flex;flex-wrap:wrap;gap:16px;margin:20px 0}}
.kpi{{background:#141821;border:1px solid #2a2f3a;border-radius:10px;padding:16px 22px;min-width:145px;text-align:center}}
.kn{{font-size:34px;font-weight:700}} .kl{{color:#9aa6b6;font-size:13px;margin-top:4px}}
.caveat{{background:#2a2310;border-left:5px solid #d99a00;border-radius:6px;padding:14px 18px;margin:18px 0;color:#f0e2c0}}
table{{width:100%;border-collapse:collapse;margin:14px 0;font-size:13px}}
th{{background:#1b2330;color:#cfe0f2;text-align:left;padding:9px 11px;border:1px solid #2a2f3a}}
td{{padding:9px 11px;border:1px solid #222833;vertical-align:top}}
tr:nth-child(even) td{{background:#141821}}
.findings{{table-layout:fixed}}
.findings th,.findings td{{overflow-wrap:anywhere;word-break:break-word}}
.findings td:nth-child(1){{font-family:Consolas,'Cascadia Mono',monospace;font-size:12px}}
.findings td:nth-child(2),.findings td:nth-child(3){{white-space:nowrap}}
.pathcards{{display:grid;gap:14px;margin:14px 0 22px}}
.pathcard{{background:#141821;border:1px solid #2a2f3a;border-radius:10px;padding:14px 16px;border-left:4px solid var(--path-color)}}
.pathcard h3{{font-size:15px;margin:0 0 10px;color:#f3f6fa}}
.pathcard p{{color:#b7c8dc;font-size:13px;margin:9px 0 0}}
.pathflow{{display:flex;align-items:center;flex-wrap:wrap;gap:7px}}
.pathnode{{display:inline-block;background:#1b2330;border:1px solid #3a4658;border-radius:6px;padding:4px 8px;font-size:12.5px;font-weight:600;overflow-wrap:anywhere;max-width:34ch}}
.pathnode.findingref{{color:#fff;border-color:var(--path-color)}}
.patharrow{{color:#ff8a86;font-size:12px;font-weight:700}}
.verified{{background:#10251d;border:1px solid #235b43;border-left:5px solid #59b981;border-radius:8px;padding:12px 18px;color:#baf5cf}}
.verified li::marker{{color:#74d69a}}
.graphcontrols{{display:flex;gap:8px;align-items:center;margin:0 0 10px}}
.graphcontrols button{{background:#1b2330;color:#dce8f5;border:1px solid #3a4658;border-radius:6px;padding:7px 12px;cursor:pointer;font-weight:600}}
.graphcontrols button:hover,.graphcontrols button:focus{{border-color:#7fb6e6;outline:none}}
.graphcontrols .hint{{color:#9aa6b6;font-size:12.5px;margin-left:6px}}
.graphbox{{background:#0f1115;border:1px solid #2a2f3a;border-radius:10px;padding:8px;overflow:auto;scrollbar-color:#445064 #141821}}
.graphbox svg{{display:block;width:1800px;max-width:none;height:auto}}
.graphbox.fit svg{{width:100%;max-width:100%;height:auto}}
ul,ol{{padding-left:22px}} li{{margin:6px 0}}
.pill{{color:#fff;padding:2px 10px;border-radius:11px;font-size:12px;font-weight:700;white-space:nowrap}}
.foot{{margin-top:40px;color:#7c879a;font-size:12.5px;border-top:1px solid #2a2f3a;padding-top:16px}}
</style></head><body><div class="wrap">
<h1>CertifEye - AD CS ESC Attack-Path Report</h1>
<p class="sub">Defensive review of {"local-only, non-tokenized AD CS exports — DO NOT UPLOAD" if LOCAL_ONLY else "scrubbed AD CS exports"} · generated for {e(m.get('generated_for', 'Current audit dataset'))} · {e(m.get('generated_on', ''))}</p>

<div class="strip">
<span><b>{m.get('cert_rows', 0):,}</b> certificate rows</span>
<span><b>{m.get('templates', 0)}</b> templates</span>
<span><b>{m.get('pki_aces', 0)}</b> PKI ACEs</span>
<span><b>{m.get('cas', 0)}</b> CA security row(s)</span>
<span><b>{m.get('dcs', 0)}</b> DC row(s)</span>
<span><b>{m.get('web_endpoints', 0)}</b> web endpoint row(s)</span>
<span><b>{m.get('hv_tokens', 0)}</b> high-value token(s)</span>
</div>

<div class="kpis">{kpi_html}</div>

<div class="caveat"><b>Read first:</b> Issued-certificate evidence proves a certificate was <i>issued</i> — not that it was used to authenticate. Confirmation requires DC/Kerberos certificate-authentication logs. Posture findings describe conditions that can enable abuse, not proof that abuse occurred.</div>

<h2>ESC coverage matrix</h2>
<table><tr><th>ESC</th><th>Status</th><th>Evidence</th></tr>{cov_rows}</table>

<h2>Attack-path graph</h2>
<p class="sub">The graph is built from the current findings only. Hover nodes for details.</p>
<div class="graphcontrols">
<button type="button" onclick="setGraphFit(false)">Readable size</button>
<button type="button" onclick="setGraphFit(true)">Fit width</button>
<span class="hint">Readable size preserves label clarity and may scroll horizontally on a smaller screen.</span>
</div>
<div id="attackGraph" class="graphbox">{svg}</div>

<h2>Primary attack paths</h2>
<p class="sub">A concise view of the highest-priority current-run relationships. These cards describe evidence-backed prerequisites, not proof of successful abuse.</p>
<div class="pathcards">{path_cards}</div>

<h2 id="findings">Findings</h2>
<table class="findings">
<colgroup><col style="width:10%"><col style="width:9%"><col style="width:7%"><col style="width:15%"><col style="width:23%"><col style="width:36%"></colgroup>
<tr><th>Finding</th><th>Severity</th><th>Conf.</th><th>Category</th><th>Object / principal</th><th>Evidence</th></tr>{fr}</table>

<h2>What to do first</h2>
<ol>{todo_html}</ol>

<h2>Controls verified clean / mitigated</h2>
<div class="verified"><ul>{clean_html}</ul></div>

<h2>Not evaluated / missing input</h2>
<ul>{not_eval_html}</ul>

<h2>Recognized input files</h2>
<ul>{input_html}</ul>

<div class="foot">Companion files: <b>ADCS_Attack_Path_Graph.svg</b>, <b>ADCS_ESC_Findings.csv</b>, graph JSON, and <b>ADCS_Attack_Path.cypher</b>. PDF and PNG are included only when their optional renderers are available. {"LOCAL-ONLY: values may be identifiable; do not upload or share this report." if LOCAL_ONLY else "Scrubbed tokens throughout - no real identities are shown."}</div>
</div>
<script>
function setGraphFit(fit) {{
  const graph = document.getElementById('attackGraph');
  if (graph) graph.classList.toggle('fit', Boolean(fit));
}}
</script>
</body></html>"""

open(os.path.join(OUT, "ADCS_Attack_Path_Report.html"), "w", encoding="utf-8").write(HTML)
print("Wrote ADCS_Attack_Path_Report.html", len(HTML), "bytes")
