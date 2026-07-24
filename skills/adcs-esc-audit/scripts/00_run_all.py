#!/usr/bin/env python3
"""CertifEye AD CS Audit - single-call pipeline wrapper.

Runs the full deterministic pipeline (01 analyze -> 06 QA montage) in order and prints
ONE compact digest at the end. The digest carries everything the model needs to write the
chat summary, so on a clean run the model reads only:
    (1) this wrapper's stdout, and
    (2) the single QA montage image.
It never needs to reopen working/results.json or read the standalone graph PNG.

Run order / fatality:
    01_analyze            -> findings + results.json + findings CSV   (fatal on fail)
    02_graph              -> attack-path SVG + rasterized PNG          (fatal on fail)
    03_build_html         -> interactive attack-path HTML report       (fatal on fail)
    04_build_graph_export -> BloodHound JSON + Neo4j Cypher            (fatal on fail)
    05_build_pdf          -> three-part branded PDF                     (fatal on fail)
    06_qa_montage         -> ONE low-DPI montage PNG for visual QA      (warn on fail)

Usage:
    python 00_run_all.py            # full pipeline + digest
    python 00_run_all.py --skip-qa  # build deliverables, skip the montage step

Use explicit --input-dir, --output-dir, and --working-dir paths. Individual
scripts retain environment-variable fallbacks for compatible hosted execution.
"""
import argparse, hashlib, importlib.util, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
MONTAGE = os.path.join(WK, "qa_montage.png")
LOCAL_ONLY = os.environ.get("ADCS_AUDIT_LOCAL_ONLY", "").strip() == "1"

STAGES = [
    ("01_analyze.py",            "analyze",      True),
    ("02_graph.py",              "graph",        True),
    ("03_build_html.py",         "html report",  True),
    ("04_build_graph_export.py", "graph export", True),
    ("05_build_pdf.py",          "pdf",          True),
    ("06_qa_montage.py",         "qa montage",   False),
]


def run_stage(script, label, fatal, idx, total):
    """Run one stage; echo its last stdout line as the status. Return True on success."""
    proc = subprocess.run([sys.executable, os.path.join(HERE, script)],
                          capture_output=True, text=True)
    tag = f"[{idx}/{total}] {label:<13}"
    if proc.returncode == 0:
        last = next((ln for ln in reversed(proc.stdout.splitlines()) if ln.strip()), "ok")
        print(f"{tag} OK   {last.strip()}")
        return True
    # failure
    print(f"{tag} {'FAIL' if fatal else 'WARN'} (exit {proc.returncode})")
    err = (proc.stderr or proc.stdout).strip().splitlines()
    for ln in err[-8:]:
        print("      " + ln)
    if fatal:
        print(f"\nPipeline stopped at '{label}'. Fix the cause and re-run; "
              f"earlier stages already wrote their outputs to {OUT}.")
        sys.exit(1)
    print(f"      (non-fatal) deliverables are complete; QA montage was not produced.")
    return False


def trunc(s, n=46):
    s = s or ""
    return s if len(s) <= n else s[:n - 3] + "..."


def digest():
    rp = os.path.join(WK, "results.json")
    if not os.path.exists(rp):
        print("  (no results.json - analyze stage did not complete)")
        return
    R = json.load(open(rp))
    m, dq, sg = R["meta"], R["dq"], R["signals"]
    ims = dq.get("ims", {})
    disp = dq.get("disposition", {})
    join = dq.get("join", {})

    line = "-" * 78
    print("\n" + line)
    print(" DIGEST  (write the chat summary from this - do NOT reopen results.json)")
    print(line)


    print(f"SCOPE: {m['cert_rows']} cert rows "
          f"({disp.get('Issued',0)} issued / {disp.get('Revoked',0)} revoked) "
          f"| {m['templates']} templates | {m['pki_aces']} PKI ACEs "
          f"| {m['dcs']} DCs | {m['web_endpoints']} web endpoint(s) "
          f"| {m['hv_tokens']} HV tokens")
    print(f"IDENTITY: mapping cols {'present' if dq.get('idcols_present') else 'ABSENT'} "
          f"| IMS SameIdentity {ims.get('SameIdentity',0)}, "
          f"DifferentMapped {ims.get('DifferentMappedIdentity',0)}, "
          f"DifferentOrUnmapped {ims.get('DifferentOrUnmappedIdentity',0)}, "
          f"NoSANUPN {ims.get('NoSANUPN',0)} "
          f"| join {join.get('Joined',0)} Joined, {join.get('Unmatched',0)} Unmatched")
    print(f"SAN: HV {dq.get('san_hv',0)}, unmapped {dq.get('san_unmapped',0)}")
    print(f"SIGNALS: ESC6 san-attr {sg.get('esc6_san_attr',0)} "
          f"| ESC3 EKU {sg.get('esc3_eku',0)} / OBO {sg.get('esc3_obo',0)} "
          f"| ESC2 {sg.get('esc2',0)} "
          f"| SID missing {sg.get('sid_missing',0)} "
          f"| SID mismatch real {sg.get('sid_mismatch_real',0)} / "
          f"benign {sg.get('sid_mismatch_benign',0)}")

    sev = R.get("sev_counts", {})
    cat = R.get("cat_counts", {})
    print("SEVERITY: " + ", ".join(f"{k} {sev[k]}" for k in ("Critical", "High", "Medium", "Low") if k in sev))
    print("CATEGORY: " + ", ".join(f"{k} ({v})" for k, v in cat.items()))

    print("\nFINDINGS:")
    for f in R.get("findings", []):
        who = f.get("Principal") or f.get("Object") or ""
        print(f" {f['FindingID']} [{f['Severity']}/{f['Confidence']}] "
              f"{f['ESCType']:<8} {trunc(who)}")
        print(f"      evidence: {f.get('Evidence','')}")
        rv = f.get("RecommendedValidation")
        if rv:
            print(f"      validate: {rv}")

    print("\nCOVERAGE MATRIX:")
    for esc, status, note in R.get("coverage", []):
        print(f" {esc:<8} {status:<10} {note}")

    print("\nDELIVERABLES (output/):")
    _delivs = sorted(os.listdir(OUT)) if os.path.isdir(OUT) else []
    for fn in _delivs:
        print(f"  {fn}")
    print(f"DELIVERY GATE: {len(_delivs)} file(s) verified present in {OUT} - "
          f"trust this list as the existence check; do NOT run a separate "
          f"working-directory-relative Glob to re-verify.")
    print(f"\nQA MONTAGE: {MONTAGE if os.path.exists(MONTAGE) else '(not produced)'}")
    print("NEXT: read the montage ONCE for visual QA. If clean, write the chat summary "
          "from this digest. Do NOT reopen results.json or read the standalone graph PNG "
          "unless the montage shows a defect in that region.")
    print(line)


def write_safe_manifest():
    """Write a deterministic, scrub-safe delivery manifest after all available stages."""
    if LOCAL_ONLY:
        print("[package] Local-only mode: safe upload manifest intentionally not generated.")
        return
    rp = os.path.join(WK, "results.json")
    if not os.path.exists(rp) or not os.path.isdir(OUT):
        return
    result = json.load(open(rp, encoding="utf-8"))
    files = sorted(
        name for name in os.listdir(OUT)
        if os.path.isfile(os.path.join(OUT, name))
        and "DO_NOT_UPLOAD" not in name
        and "token_map" not in name.lower()
        and name != "adcs_upload_manifest.json"
    )
    manifest = {
        "schemaVersion": "adcs-upload-manifest/v1",
        "analysisSchemaVersion": result.get("meta", {}).get("schema_version", "unknown"),
        "assessmentDate": result.get("meta", {}).get("generated_on", "Not supplied"),
        "reviewRequired": True,
        "files": files,
        "artifacts": [
            {
                "file": name,
                "bytes": os.path.getsize(os.path.join(OUT, name)),
                "sha256": hashlib.sha256(open(os.path.join(OUT, name), "rb").read()).hexdigest(),
            }
            for name in files
        ],
        "inputRows": result.get("meta", {}).get("cert_rows", 0),
        "findingCount": len(result.get("findings", [])),
        "inputRoleRows": {
            "certificates": result.get("meta", {}).get("cert_rows", 0),
            "templates": result.get("meta", {}).get("templates", 0),
            "pkiAces": result.get("meta", {}).get("pki_aces", 0),
            "certificateAuthorities": result.get("meta", {}).get("cas", 0),
            "domainControllers": result.get("meta", {}).get("dcs", 0),
            "webEndpoints": result.get("meta", {}).get("web_endpoints", 0),
            "highValueTokens": result.get("meta", {}).get("hv_tokens", 0),
        },
        "coverage": [{"esc": esc, "status": status} for esc, status, _note in result.get("coverage", [])],
    }
    with open(os.path.join(OUT, "adcs_upload_manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Run the reusable AD CS analysis/report pipeline.")
    parser.add_argument("--input-dir", help="Folder containing scrubbed AD CS CSV files")
    parser.add_argument("--output-dir", help="Folder for reports and exports")
    parser.add_argument("--working-dir", help="Folder for results.json and QA intermediates")
    parser.add_argument("--skip-qa", action="store_true", help="Skip PDF montage QA")
    args = parser.parse_args()
    if args.input_dir:
        os.environ["ADCS_AUDIT_INPUT"] = os.path.abspath(args.input_dir)
    if args.output_dir:
        os.environ["ADCS_AUDIT_OUTPUT"] = os.path.abspath(args.output_dir)
    if args.working_dir:
        os.environ["ADCS_AUDIT_WORKING"] = os.path.abspath(args.working_dir)
    global WK, OUT, MONTAGE, LOCAL_ONLY
    WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
    OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
    MONTAGE = os.path.join(WK, "qa_montage.png")
    LOCAL_ONLY = os.environ.get("ADCS_AUDIT_LOCAL_ONLY", "").strip() == "1"
    skip_qa = args.skip_qa
    pdf_available = importlib.util.find_spec("reportlab") is not None
    stages = [s for s in STAGES if not (skip_qa and s[0] == "06_qa_montage.py")]
    if not pdf_available:
        stages = [s for s in stages if s[0] != "05_build_pdf.py"]
        print("[renderer] PDF skipped: ReportLab is not installed; all non-PDF deliverables remain required.")
    total = len(stages)
    mode = "LOCAL-ONLY / NOT TOKENIZED" if LOCAL_ONLY else "tokenized safe-package"
    print(f"CertifEye AD CS Audit - running full pipeline ({mode})")
    print("=" * 78)
    for i, (script, label, fatal) in enumerate(stages, 1):
        run_stage(script, label, fatal, i, total)
    write_safe_manifest()
    digest()


if __name__ == "__main__":
    main()
