import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "synthetic-samples"
SCRIPTS = ROOT / "skills" / "adcs-esc-audit" / "scripts"
EXPECTATIONS = json.loads((SCENARIOS / "scenario_expectations.json").read_text(encoding="utf-8"))
REQUIRED = {
    "ADCS_ESC_Findings.csv",
    "ADCS_Attack_Path_Graph.svg",
    "ADCS_Attack_Path_Report.html",
    "ADCS_Attack_Path_BloodHound.json",
    "ADCS_Attack_Path.cypher",
    "ADCS_ESC_Audit_Report.pdf",
    "adcs_upload_manifest.json",
}


def run_script(script: str, input_dir: Path, output_dir: Path, working_dir: Path):
    env = os.environ.copy()
    env.update({
        "ADCS_AUDIT_INPUT": str(input_dir),
        "ADCS_AUDIT_OUTPUT": str(output_dir),
        "ADCS_AUDIT_WORKING": str(working_dir),
    })
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / script)],
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode:
        raise AssertionError(proc.stderr + proc.stdout)
    return json.loads((working_dir / "results.json").read_text(encoding="utf-8"))


class CertifEyeSyntheticScenarioTests(unittest.TestCase):
    def test_packages_are_large_safe_unique_and_span_two_years(self):
        requester_sets = {}
        for scenario, expected in EXPECTATIONS["scenarios"].items():
            source = SCENARIOS / scenario / "Scrubbed"
            manifest = json.loads((source / "adcs_upload_manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["synthetic"])
            first = date.fromisoformat(manifest["evidenceWindow"]["first"])
            last = date.fromisoformat(manifest["evidenceWindow"]["last"])
            self.assertGreaterEqual((last - first).days, expected["minimumEvidenceDays"])
            file_rows = {entry["role"]: entry["rows"] for entry in manifest["files"]}
            self.assertEqual(file_rows, expected["minimumRows"])
            for entry in manifest["files"]:
                path = source / entry["file"]
                self.assertGreater(path.stat().st_size, 0)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
            cert_path = source / "exported_certs_normalized_scrubbed.csv"
            with cert_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertGreaterEqual(len(rows), 15000)
            dates = [date.fromisoformat(row["SubmittedWhen"][:10]) for row in rows]
            self.assertGreaterEqual((max(dates) - min(dates)).days, expected["minimumEvidenceDays"])
            requester_sets[scenario] = {row["RequesterIdentityToken"] for row in rows if row["RequesterIdentityToken"]}
            joined = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in source.glob("*.csv"))
            for forbidden in ("CANARY_SECRET", "example.com", "DC=", "CN=", "\\\\"):
                self.assertNotIn(forbidden, joined)
        names = sorted(requester_sets)
        for index, left in enumerate(names):
            for right in names[index + 1:]:
                self.assertTrue(requester_sets[left].isdisjoint(requester_sets[right]))

    def test_expected_findings_and_coverage_vary_by_scenario(self):
        signatures = {}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for scenario, expected in EXPECTATIONS["scenarios"].items():
                result = run_script(
                    "01_analyze.py",
                    SCENARIOS / scenario / "Scrubbed",
                    root / scenario / "output",
                    root / scenario / "working",
                )
                types = {finding["ESCType"] for finding in result["findings"]}
                self.assertTrue(set(expected["expectedEscTypes"]) <= types)
                self.assertTrue(set(expected["expectedAbsentEscTypes"]).isdisjoint(types))
                coverage = {esc: status for esc, status, _note in result["coverage"]}
                self.assertEqual(expected["expectedCoverage"], coverage)
                self.assertEqual(
                    [f["FindingID"] for f in result["findings"]],
                    [
                        f"F{index:02d}-"
                        + "".join(ch if ch.isalnum() else "-" for ch in f["ESCType"]).strip("-").upper()
                        for index, f in enumerate(result["findings"], 1)
                    ],
                )
                self.assertTrue(all(f["FindingKey"].startswith("CF-") for f in result["findings"]))
                signatures[scenario] = (tuple(sorted(types)), tuple(sorted(coverage.items())), len(result["findings"]))
        self.assertEqual(len(set(signatures.values())), 3)

    def test_schema_discovery_and_results_ignore_names_and_row_order(self):
        scenario = "mixed-enterprise"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = run_script(
                "01_analyze.py",
                SCENARIOS / scenario / "Scrubbed",
                root / "original-output",
                root / "original-working",
            )
            renamed = root / "renamed"
            renamed.mkdir()
            for index, source in enumerate(sorted((SCENARIOS / scenario / "Scrubbed").glob("*.csv"))):
                with source.open(newline="", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    rows = list(reader)
                    columns = list(reader.fieldnames or [])
                with (renamed / f"evidence-{index:02d}.csv").open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=columns)
                    writer.writeheader()
                    writer.writerows(reversed(rows))
            changed = run_script(
                "01_analyze.py",
                renamed,
                root / "changed-output",
                root / "changed-working",
            )
            for result in (original, changed):
                result["meta"].pop("input_files", None)
            self.assertEqual(original, changed)

    def test_full_pipeline_generates_nonempty_manifested_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for scenario in EXPECTATIONS["scenarios"]:
                output = root / scenario / "output"
                working = root / scenario / "working"
                proc = subprocess.run(
                    [
                        sys.executable, str(SCRIPTS / "00_run_all.py"),
                        "--input-dir", str(SCENARIOS / scenario / "Scrubbed"),
                        "--output-dir", str(output),
                        "--working-dir", str(working),
                        "--skip-qa",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
                generated = {path.name for path in output.iterdir() if path.is_file()}
                self.assertTrue(REQUIRED <= generated)
                self.assertFalse(any(path.stat().st_size == 0 for path in output.iterdir() if path.is_file()))
                svg_root = ET.parse(output / "ADCS_Attack_Path_Graph.svg").getroot()
                view_box = [float(value) for value in svg_root.attrib["viewBox"].split()]
                self.assertEqual(view_box[:2], [0.0, 0.0])
                canvas_width, canvas_height = view_box[2], view_box[3]
                elements = list(svg_root.iter())
                legend = next(element for element in elements if element.attrib.get("id") == "legend-panel")
                legend_y = float(legend.attrib["y"])
                legend_bottom = legend_y + float(legend.attrib["height"])
                self.assertLessEqual(legend_bottom + 40, canvas_height)
                node_rects = [element for element in elements if element.attrib.get("class") == "node-box"]
                if node_rects:
                    node_caption_bottom = max(
                        float(element.attrib["y"]) + float(element.attrib["height"]) + 24
                        for element in node_rects
                    )
                    self.assertGreater(
                        legend_y,
                        node_caption_bottom,
                        f"Legend overlaps graph nodes for {scenario}",
                    )
                for element in node_rects + [legend]:
                    self.assertLessEqual(
                        float(element.attrib["x"]) + float(element.attrib["width"]),
                        canvas_width,
                    )
                html_report = (output / "ADCS_Attack_Path_Report.html").read_text(encoding="utf-8")
                self.assertIn("Readable size", html_report)
                self.assertIn("Fit width", html_report)
                self.assertIn("classList.toggle('fit'", html_report)
                self.assertIn('class="findings"', html_report)
                self.assertIn("table-layout:fixed", html_report)
                self.assertIn('id="findings"', html_report)
                self.assertIn("Primary attack paths", html_report)
                self.assertIn("pathcards", html_report)
                self.assertIn('class="verified"', html_report)
                self.assertNotIn("CF-", html_report)
                self.assertLess(
                    html_report.index('id="attackGraph"'),
                    html_report.index("<h2>Primary attack paths</h2>"),
                )
                self.assertFalse(any("CF-" in element.text for element in elements if element.text))
                committed = SCENARIOS / scenario / "output"
                committed_files = {path.name for path in committed.iterdir() if path.is_file()}
                optional_graph = "ADCS_Attack_Path_Graph.png"
                self.assertEqual(generated - {optional_graph}, committed_files - {optional_graph})
                renderer_state_matches = (optional_graph in generated) == (optional_graph in committed_files)
                for name in sorted(generated & committed_files):
                    if not renderer_state_matches and name in {
                        optional_graph,
                        "ADCS_ESC_Audit_Report.pdf",
                        "adcs_upload_manifest.json",
                    }:
                        continue
                    self.assertEqual(
                        (output / name).read_bytes(),
                        (committed / name).read_bytes(),
                        f"Committed golden artifact is stale: {scenario}/{name}",
                    )
                manifest = json.loads((output / "adcs_upload_manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["assessmentDate"], EXPECTATIONS["scenarios"][scenario]["assessmentDate"])
                listed = {entry["file"] for entry in manifest["artifacts"]}
                self.assertEqual(set(manifest["files"]), listed)
                for entry in manifest["artifacts"]:
                    path = output / entry["file"]
                    self.assertEqual(entry["bytes"], path.stat().st_size)
                    self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
