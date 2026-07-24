# adcs-esc-audit — reusable build scripts

These are the **hardened, reusable** analysis/render scripts for the audit. They are dataset-generic: findings, graph content, coverage, and report narrative are derived from the current CSV inputs, not from client-specific findings or prior-run tokens/counts. Reusing them
across runs (instead of re-deriving the logic in-context each time) keeps a re-run lean.
They already contain the render fixes that make the first visual-QA pass pass cleanly
(graph node-label auto-sizing; PDF severity-pill widths + cell padding), so a normal run
needs **no rebuild round-trip**.

## Standard workspace layout

The scripts accept explicit paths through the wrapper or these environment variables:

- Inputs: `ADCS_AUDIT_INPUT` (scrubbed CSV exports)
- Output: `ADCS_AUDIT_OUTPUT` (deliverables the user sees)
- Scratch: `ADCS_AUDIT_WORKING` (`results.json`, QA images)

Environment-variable defaults remain for compatible hosted runs, but reusable
callers should always pass explicit input, output, and working paths.

## Default path — one call
**`00_run_all.py`** runs the whole pipeline (`01`→`06`) in order and prints ONE compact digest (scope,
counts, every finding with evidence + recommended validation, the ESC coverage matrix, the deliverable list,
and the montage path). A clean run is then just: **`python 00_run_all.py`** → read `working/qa_montage.png`
once → write the chat summary from the digest. No need to reopen `results.json` or read the standalone graph
PNG. The wrapper stops at the first fatal stage and reports which one; `--skip-qa` omits the montage step.
Use the individual numbered scripts below only to re-render one artifact after a fix.

Example:

```text
python 00_run_all.py --input-dir C:\\audit\\Scrubbed --output-dir C:\\audit\\Output --working-dir C:\\audit\\Working
```

## Run order (what the wrapper runs)
1. `01_analyze.py` — deterministic detection pass over all supplied CSVs. Writes
   `working/results.json` (all counts, findings, coverage matrix) + `output/ADCS_ESC_Findings.csv`.
2. `02_graph.py` — attack-path graph: interactive SVG + rasterized PNG (PNG = SVG via cairosvg, so PDF == HTML graph).
3. `03_build_html.py` — interactive attack-path HTML report (embeds the SVG, hover tooltips).
4. `04_build_graph_export.py` — BloodHound CE JSON + Neo4j Cypher (same node/edge model).
5. `05_build_pdf.py` — three-part branded PDF (exec summary · ELI5 remediation · technical), embeds the rasterized graph.
6. `06_qa_montage.py` — renders the PDF to ONE stitched, low-DPI PNG for the visual-QA pass.

## Efficient QA (do this)
`00_run_all.py` already runs the montage step and prints its path. Read that **single** montage image
(`working/qa_montage.png`) back once and fix any clipping/overflow — instead of reading each page
individually. Re-render only if a defect is found. (Run `06_qa_montage.py` directly only if you rebuilt the
PDF on its own.) This is the montage-QA step referenced in SKILL.md ("Efficient re-runs").

> The scripts assume the data columns documented in SKILL.md. If a new export changes a
> column name/shape, adjust the relevant pass — do not fabricate values for missing columns.
