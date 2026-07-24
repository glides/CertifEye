import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADCS_SCRIPTS = ROOT / "skills" / "adcs-esc-audit" / "scripts"
ADCS_FIXTURES = ROOT / "tests" / "fixtures" / "scrubbed"
AD_SECURITY_ROOT = ROOT.parent / "ADmission Control"


class StaticContractTests(unittest.TestCase):
    def test_schema_and_skill_references_exist(self):
        self.assertTrue((ROOT / "docs" / "schema-contract.md").exists())
        self.assertTrue((ROOT / "skills" / "adcs-esc-audit" / "SKILL.md").exists())
        self.assertTrue((ROOT / "skills" / "adcs-esc-audit" / "agents" / "openai.yaml").exists())
        self.assertTrue((ROOT / "docs" / "Novice-User-Guide.md").exists())
        self.assertTrue((ROOT / "synthetic-samples" / "scenario_expectations.json").exists())
        self.assertTrue((ADCS_SCRIPTS / "00_run_all.py").exists())
        self.assertTrue((AD_SECURITY_ROOT / "skills" / "ad-security-posture" / "SKILL.md").exists())

    def test_synthetic_fixture_contains_all_adcs_roles(self):
        names = {p.name for p in ADCS_FIXTURES.glob("*.csv")}
        self.assertTrue(any("cert" in n for n in names))
        self.assertIn("adcs_template_inventory_scrubbed.csv", names)
        self.assertIn("adcs_ca_security_scrubbed.csv", names)
        self.assertIn("adcs_dc_enforcement_scrubbed.csv", names)
        self.assertIn("adcs_web_enrollment_scrubbed.csv", names)

    def test_graph_exports_use_stable_ids(self):
        text = (ADCS_SCRIPTS / "04_build_graph_export.py").read_text(encoding="utf-8")
        analyzer = (ADCS_SCRIPTS / "01_analyze.py").read_text(encoding="utf-8")
        self.assertIn("sha256", text)
        self.assertNotIn("hash(n[\"id\"])", text)
        self.assertIn('"CF-" + hashlib.sha256', analyzer)
        self.assertNotIn("datetime.now", analyzer)

    def test_no_private_artifacts_in_synthetic_fixture(self):
        forbidden = ("token_map", "salt", "raw_do_not_upload", "private")
        for path in ADCS_FIXTURES.rglob("*"):
            if path.is_file():
                self.assertFalse(any(term in path.name.lower() for term in forbidden), path)


if __name__ == "__main__":
    unittest.main()
