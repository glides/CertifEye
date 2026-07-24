import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "adcs-esc-audit" / "scripts"
EXPECTED = json.loads((ROOT / "tests" / "fixtures" / "release_matrix_expected.json").read_text(encoding="utf-8"))


def write_csv(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def build_matrix(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    templates = [
        {"TemplateName":"TPL_ESC1","TemplateOID":"1.2.3.1","Published":"True","SubjectOrSANSuppliedByRequester":"True","AuthCapableOrAnyPurpose":"True","ManagerApprovalRequired":"False","AuthorizedSignaturesRequired":"False","EnrollAllowPrincipals":"BROAD_AUTHENTICATED_USERS","BroadEnrollPrincipals":"BROAD_AUTHENTICATED_USERS","ESC1Candidate_AnyEnroll":"True","ESC1Candidate_BroadEnroll":"True","ESC4Candidate":"False","DangerousControlNonDefaultPrincipals":"","EKU_OIDs":"1.3.6.1.5.5.7.3.2","NoSecurityExtension":"True"},
        {"TemplateName":"TPL_ESC4","TemplateOID":"1.2.3.4","Published":"True","SubjectOrSANSuppliedByRequester":"False","AuthCapableOrAnyPurpose":"True","ManagerApprovalRequired":"False","AuthorizedSignaturesRequired":"False","EnrollAllowPrincipals":"GROUP_RESTRICTED","BroadEnrollPrincipals":"","ESC1Candidate_AnyEnroll":"False","ESC1Candidate_BroadEnroll":"False","ESC4Candidate":"True","DangerousControlNonDefaultPrincipals":"PRINCIPAL_TEMPLATE_CONTROL","EKU_OIDs":"1.3.6.1.5.5.7.3.2","NoSecurityExtension":"False"},
    ]
    write_csv(root / "adcs_template_inventory_scrubbed.csv", list(templates[0]), templates)
    cert_columns = ["RequestID","CertificateTemplate","ParseStatus","RequesterName","RequesterIdentityToken","RequesterMappedToAD","SAN_UPN","SAN_UPN_IdentityToken","SAN_UPN_MappedToAD","RequesterSanUPNSameIdentity","IdentityMappingStatus","SubmittedWhen","CertDisposition","EKU_OIDs","AuthCapableOrAnyPurpose","RequestAttributes","RequestAttributesHasSAN","HasAnyPurposeOrNoEKU","IsEnrollmentAgentCert","OnBehalfOfCallerMismatch","CallerName","HasSidSecurityExtension","SidExtensionMatchesRequester","SidMismatchLikelyBenign","NoSecurityExtension"]
    certs = [
        {"RequestID":"REQ_ESC1","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_REQ","RequesterIdentityToken":"PRINCIPAL_REQ","RequesterMappedToAD":"True","SAN_UPN":"HV_PRINCIPAL_A","SAN_UPN_IdentityToken":"HV_PRINCIPAL_A","SAN_UPN_MappedToAD":"True","RequesterSanUPNSameIdentity":"False","IdentityMappingStatus":"DifferentMappedIdentity","SubmittedWhen":"2026-01-01T00:00:00Z","CertDisposition":"Issued","EKU_OIDs":"1.3.6.1.5.5.7.3.2","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"True"},
        {"RequestID":"REQ_ESC2","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_ESC2","CertDisposition":"Issued","EKU_OIDs":"2.5.29.37.0","HasAnyPurposeOrNoEKU":"True","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"True"},
        {"RequestID":"REQ_ESC3","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_TARGET","CallerName":"PRINCIPAL_AGENT","CertDisposition":"Issued","EKU_OIDs":"1.3.6.1.4.1.311.20.2.1","IsEnrollmentAgentCert":"True","OnBehalfOfCallerMismatch":"True","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"True"},
        {"RequestID":"REQ_ESC6","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_ESC6","CertDisposition":"Issued","RequestAttributes":"SAN:UPN=HV_PRINCIPAL_A","RequestAttributesHasSAN":"True","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"True"},
        {"RequestID":"REQ_ESC910","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_ESC910","CertDisposition":"Issued","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"False","NoSecurityExtension":"True"},
        {"RequestID":"REQ_BENIGN","CertificateTemplate":"TPL_ESC1","ParseStatus":"OK","RequesterName":"PRINCIPAL_BENIGN","CertDisposition":"Issued","AuthCapableOrAnyPurpose":"True","HasSidSecurityExtension":"True","SidExtensionMatchesRequester":"False","SidMismatchLikelyBenign":"True"},
    ]
    write_csv(root / "exported_certs_normalized_scrubbed.csv", cert_columns, certs)
    acl_columns = ["PkiObjectType","Principal","Rights","ESC5Candidate","IsCAHostAccount","IsEnrollRight","RightCategory"]
    write_csv(root / "adcs_pki_acl_scrubbed.csv", acl_columns, [
        {"PkiObjectType":"Enrollment Services","Principal":"PRINCIPAL_PKI_CONTROL","Rights":"WriteDacl","ESC5Candidate":"True","IsCAHostAccount":"False","IsEnrollRight":"False","RightCategory":"Control"},
        {"PkiObjectType":"Certificate Templates","Principal":"PRINCIPAL_ENROLL_ONLY","Rights":"Enroll","ESC5Candidate":"True","IsCAHostAccount":"False","IsEnrollRight":"True","RightCategory":"Enroll"},
        {"PkiObjectType":"Enrollment Services","Principal":"COMPUTER_CA_HOST","Rights":"GenericAll","ESC5Candidate":"True","IsCAHostAccount":"True","IsEnrollRight":"False","RightCategory":"Control"},
    ])
    write_csv(root / "adcs_ca_security_scrubbed.csv", ["CA_CommonName","ManageCAPrincipals","ManageCertificatesPrincipals","EditF_AttributeSubjectAltName2","ESC6_CAConfigFlag","IF_EnforceEncryptICertRequest","ESC7Candidate","ESC11Candidate"], [{"CA_CommonName":"CA_TOKEN","ManageCAPrincipals":"PRINCIPAL_CA_OPERATOR","ManageCertificatesPrincipals":"PRINCIPAL_CERT_OFFICER","EditF_AttributeSubjectAltName2":"True","ESC6_CAConfigFlag":"True","IF_EnforceEncryptICertRequest":"False","ESC7Candidate":"True","ESC11Candidate":"True"}])
    write_csv(root / "adcs_dc_enforcement_scrubbed.csv", ["DC_DnsHostName","StrongCertificateBindingEnforcement","EnforcementLevel","FullEnforcement","ReadStatus","ReadMethod","ReadDetail"], [{"DC_DnsHostName":"COMPUTER_DC","StrongCertificateBindingEnforcement":"1","EnforcementLevel":"Compatibility","FullEnforcement":"False","ReadStatus":"Live","ReadMethod":"RemoteRegistry","ReadDetail":"Live"}])
    write_csv(root / "adcs_web_enrollment_scrubbed.csv", ["EndpointHostName","EndpointKind","Scheme","IsHttp","AuthFromMetadata","Probed","Reachable","NtlmOffered","EpaTokenChecking","ESC8Confirmed","ESC8NeedsEpaCheck","ESC8Mitigated","Esc8RiskFromMetadata"], [
        {"EndpointHostName":"COMPUTER_HTTP","EndpointKind":"certsrv","Scheme":"http","IsHttp":"True","AuthFromMetadata":"Windows","Probed":"True","Reachable":"True","NtlmOffered":"True","EpaTokenChecking":"Unknown","ESC8Confirmed":"True","ESC8NeedsEpaCheck":"False","ESC8Mitigated":"False","Esc8RiskFromMetadata":"True"},
        {"EndpointHostName":"COMPUTER_HTTPS_REQUIRED","EndpointKind":"certsrv","Scheme":"https","IsHttp":"False","Probed":"True","Reachable":"True","NtlmOffered":"True","EpaTokenChecking":"Require","ESC8Confirmed":"False","ESC8NeedsEpaCheck":"False","ESC8Mitigated":"True","Esc8RiskFromMetadata":"False"},
        {"EndpointHostName":"COMPUTER_HTTPS_UNKNOWN","EndpointKind":"certsrv","Scheme":"https","IsHttp":"False","Probed":"True","Reachable":"True","NtlmOffered":"True","EpaTokenChecking":"Unknown","ESC8Confirmed":"False","ESC8NeedsEpaCheck":"True","ESC8Mitigated":"False","Esc8RiskFromMetadata":"False"},
        {"EndpointHostName":"COMPUTER_UNPROBED","EndpointKind":"certsrv","Scheme":"https","IsHttp":"False","Probed":"False","Reachable":"False","NtlmOffered":"","EpaTokenChecking":"Unknown","ESC8Confirmed":"False","ESC8NeedsEpaCheck":"True","ESC8Mitigated":"False","Esc8RiskFromMetadata":"False"},
    ])
    write_csv(root / "high_value_targets_scrubbed.csv", ["Token","HighValueReason","ObjectClass"], [{"Token":"HV_PRINCIPAL_A","HighValueReason":"Synthetic high value","ObjectClass":"user"}])


class CertifEyeReleasePipelineTests(unittest.TestCase):
    def run_pipeline(self, input_dir, output_dir, working_dir, local_only=False):
        env = os.environ.copy()
        if local_only:
            env["ADCS_AUDIT_LOCAL_ONLY"] = "1"
        result = subprocess.run([sys.executable, str(SCRIPTS / "00_run_all.py"), "--input-dir", str(input_dir), "--output-dir", str(output_dir), "--working-dir", str(working_dir), "--skip-qa"], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return json.loads((working_dir / "results.json").read_text(encoding="utf-8"))

    def test_release_matrix_covers_all_esc_types_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "input"; build_matrix(source)
            result = self.run_pipeline(source, root / "output", root / "working")
            types = {row["ESCType"] for row in result["findings"]}
            self.assertTrue(set(EXPECTED["expectedEscTypes"]) <= types)
            esc5 = [row for row in result["findings"] if row["ESCType"] == "ESC5"]
            evidence = " ".join(row["Evidence"] for row in esc5)
            for token in EXPECTED["expectedAbsentEsc5Principals"]:
                self.assertNotIn(token, evidence)
            coverage = {esc: status for esc, status, _note in result["coverage"]}
            self.assertNotEqual(coverage["ESC5"], "Not Evaluated")
            self.assertNotEqual(coverage["ESC9/10"], "Clean")

    def test_pipeline_artifacts_are_deterministic_and_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "input"; build_matrix(source)
            outputs = []
            for name in ("one", "two"):
                output, working = root / name / "output", root / name / "working"
                self.run_pipeline(source, output, working)
                for artifact in EXPECTED["requiredArtifacts"]:
                    self.assertTrue((output / artifact).exists(), artifact)
                outputs.append({path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()} | {Path("working/results.json"): (working / "results.json").read_bytes()})
                safe_manifest = json.loads((output / "adcs_upload_manifest.json").read_text(encoding="utf-8"))
                self.assertTrue(safe_manifest["reviewRequired"])
                rendered = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in output.glob("*.html"))
                self.assertNotIn("Raw_DO_NOT_UPLOAD", rendered)
                self.assertNotIn("/mnt/workspace", rendered)
            self.assertEqual(outputs[0], outputs[1])

    def test_local_only_mode_never_emits_a_safe_upload_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "raw-local-only"; build_matrix(source)
            output, working = root / "private-output", root / "private-working"
            self.run_pipeline(source, output, working, local_only=True)
            self.assertFalse((output / "adcs_upload_manifest.json").exists())
            html = (output / "ADCS_Attack_Path_Report.html").read_text(encoding="utf-8")
            self.assertIn("LOCAL-ONLY", html)
            pdf = (output / "ADCS_ESC_Audit_Report.pdf").read_bytes()
            self.assertGreater(len(pdf), 0)


if __name__ == "__main__":
    unittest.main()
