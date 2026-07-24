#!/usr/bin/env python3
"""AD CS ESC Audit — generic deterministic detection pass.

Reads whatever scrubbed AD CS CSV exports are present in the explicit input directory, detects file
roles by schema/name, computes findings from the supplied data only, and writes:
  - /mnt/workspace/working/results.json
  - /mnt/workspace/output/ADCS_ESC_Findings.csv

The script intentionally avoids client-specific names, tokens, counts, dates, or conclusions.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

IN = os.environ.get("ADCS_AUDIT_INPUT", "/mnt/workspace/input")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
os.makedirs(OUT, exist_ok=True)
os.makedirs(WK, exist_ok=True)

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Clean": 0, "Mitigated": 0, "Not Evaluated": -1, "Not evaluated": -1}
HIGH_IMPACT_PKI = {
    "NTAuthCertificates",
    "CertificationAuthoritiesContainer",
    "EnrollmentServiceCA",
    "EnrollmentServicesContainer",
    "CertificateTemplatesContainer",
    "KRAContainer",
}
WRITE_TOKENS = ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty", "Write", "Full")
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.4.1.311.20.2.2", # Smart Card Logon
    "1.3.6.1.5.2.3.4",         # PKINIT Client Authentication
    "2.5.29.37.0",             # Any Purpose
}
CRA_EKU = "1.3.6.1.4.1.311.20.2.1"


def norm(s: Any) -> str:
    return "" if s is None else str(s).strip()


def truthy(v: Any) -> bool:
    return norm(v).lower() in {"true", "1", "yes", "y", "enabled", "full", "require", "required"}


def falsey(v: Any) -> bool:
    return norm(v).lower() in {"false", "0", "no", "n", "disabled", "none", ""}


def split_multi(v: Any) -> List[str]:
    text = norm(v)
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            decoded = json.loads(text)
            if isinstance(decoded, list):
                return [norm(p) for p in decoded if norm(p)]
        except json.JSONDecodeError:
            pass
    for sep in [";", "|", ","]:
        if sep in text:
            return [p.strip() for p in text.split(sep) if p.strip()]
    return [text]


def starts_hv(v: Any) -> bool:
    return norm(v).startswith("HV_")


def is_broad(v: Any) -> bool:
    return "BROAD_" in norm(v)


def has_write(rights: Any) -> bool:
    r = norm(rights)
    return any(tok.lower() in r.lower() for tok in WRITE_TOKENS)


def is_read_or_execute_only_ace(row: Dict[str, Any]) -> bool:
    """Prevent collector-side category labels from turning GenericRead into ESC5 control."""
    values = " ".join([row_get(row, "Rights"), row_get(row, "ResolvedRight")]).lower()
    if has_write(values):
        return False
    return any(token in values for token in ("genericread", "genericexecute", "readproperty", "readcontrol", "listchildren"))


def row_get(row: Dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        if k in row and row[k] is not None:
            return norm(row[k])
    return default


def load_csv(path: str) -> Tuple[List[Dict[str, str]], List[str]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return rows, list(reader.fieldnames or [])


def stable_row_key(row: Dict[str, Any]) -> str:
    """Make findings independent of collector/export row order."""
    return json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def role_for_file(name: str, cols: Iterable[str]) -> Optional[str]:
    base = name.lower()
    c = set(cols)
    # Prefer unambiguous schema checks, then filename hints.
    if {"TemplateName", "TemplateOID"} & c and ("Published" in c or "ESC1Candidate_AnyEnroll" in c or "ESC4Candidate" in c):
        return "templates"
    if "PkiObjectType" in c and "Principal" in c and "Rights" in c:
        return "acls"
    if "CA_CommonName" in c and ({"ManageCAPrincipals", "ManageCertificatesPrincipals", "ESC7Candidate"} & c):
        return "ca"
    if "DC_DnsHostName" in c and ({"StrongCertificateBindingEnforcement", "FullEnforcement"} & c):
        return "dc"
    if {"EndpointHostName", "EndpointKind"} & c and ({"Scheme", "ESC8Confirmed", "Esc8RiskFromMetadata"} & c):
        return "web"
    if "Token" in c and ("HighValueReason" in c or "high_value" in base or "hv" in base):
        return "hv"
    if ("RequestID" in c or "SerialNumber" in c) and ("CertificateTemplate" in c or "TemplateName" in c) and ({"RequesterName", "RequesterIdentityToken", "SAN_UPN", "ParseStatus"} & c):
        return "certs"
    # Filename fallback for older/newer collector variants.
    if "template" in base and "inventory" in base:
        return "templates"
    if "pki_object" in base or "pki-object" in base or "acl" in base:
        return "acls"
    if "ca_security" in base or "ca-security" in base:
        return "ca"
    if "dc_enforcement" in base or "dc-enforcement" in base:
        return "dc"
    if "web_enrollment" in base or "web-enrollment" in base:
        return "web"
    if "high_value" in base or "high-value" in base:
        return "hv"
    if "cert" in base and "scrubbed" in base:
        return "certs"
    return None


def discover_inputs() -> Dict[str, Dict[str, Any]]:
    roles = {r: {"rows": [], "files": [], "columns": set()} for r in ["certs", "templates", "acls", "ca", "dc", "web", "hv"]}
    if not os.path.isdir(IN):
        raise SystemExit(f"Input folder not found: {IN}")
    for fn in sorted(os.listdir(IN)):
        if not fn.lower().endswith(".csv"):
            continue
        path = os.path.join(IN, fn)
        rows, cols = load_csv(path)
        role = role_for_file(fn, cols)
        if not role:
            continue
        roles[role]["rows"].extend(rows)
        roles[role]["files"].append(fn)
        roles[role]["columns"].update(cols)
    for v in roles.values():
        v["rows"].sort(key=stable_row_key)
        v["columns"] = sorted(v["columns"])
    return roles


roles = discover_inputs()
certs = roles["certs"]["rows"]
tmpls = roles["templates"]["rows"]
acls = roles["acls"]["rows"]
ca_rows = roles["ca"]["rows"]
dc_rows = roles["dc"]["rows"]
web_rows = roles["web"]["rows"]
hv_rows = roles["hv"]["rows"]
hv_tokens = {row_get(h, "Token") for h in hv_rows if row_get(h, "Token")}


def is_historical_issuance(row: Dict[str, str]) -> bool:
    """Include certificates that were issued, even if later revoked; exclude non-issuance rows."""
    disposition = row_get(row, "CertDisposition", default="Issued").lower()
    return disposition in {"", "issued", "revoked", "valid", "expired"}


issuance_rows = [row for row in certs if is_historical_issuance(row)]


def parse_evidence_datetime(value: Any) -> Optional[datetime]:
    text = norm(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def assessment_date() -> str:
    supplied = norm(os.environ.get("ADCS_AUDIT_ASSESSMENT_DATE"))
    if supplied:
        return supplied
    dates = [
        parsed
        for row in certs
        for value in (row_get(row, "SubmittedWhen"), row_get(row, "ResolvedWhen"))
        for parsed in [parse_evidence_datetime(value)]
        if parsed is not None
    ]
    return max(dates).date().isoformat() if dates else "Not supplied"


def build_template_indexes(rows: List[Dict[str, str]]) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]]]:
    by_name: Dict[str, Dict[str, str]] = {}
    by_oid: Dict[str, Dict[str, str]] = {}
    for t in rows:
        name = row_get(t, "TemplateName", "Name")
        oid = row_get(t, "TemplateOID", "OID")
        if name:
            by_name[name] = t
        if oid:
            by_oid[oid] = t
    return by_name, by_oid


by_name, by_oid = build_template_indexes(tmpls)


def join_template(cert: Dict[str, str]) -> Tuple[Optional[Dict[str, str]], str, str]:
    ct = row_get(cert, "CertificateTemplate", "TemplateName", "TemplateOID")
    if ct and ct in by_name:
        return by_name[ct], "Joined", "TemplateName"
    if ct and ct in by_oid:
        return by_oid[ct], "Joined", "TemplateOID"
    return None, "Unmatched", "None"


def template_auth_capable(t: Optional[Dict[str, str]]) -> bool:
    if not t:
        return False
    if truthy(row_get(t, "AuthCapableOrAnyPurpose")) or truthy(row_get(t, "NoEKU")):
        return True
    eku_text = row_get(t, "EKU_OIDs", "AuthEKUsMatched")
    return any(oid in eku_text for oid in AUTH_EKUS)


def cert_auth_capable(c: Dict[str, str], t: Optional[Dict[str, str]] = None) -> bool:
    if truthy(row_get(c, "AuthCapableOrAnyPurpose")) or truthy(row_get(c, "HasAnyPurposeOrNoEKU")):
        return True
    if t and template_auth_capable(t):
        return True
    eku_text = row_get(c, "EKU_OIDs", "EnhancedKeyUsageOids")
    return any(oid in eku_text for oid in AUTH_EKUS)


def template_requester_supplied(t: Optional[Dict[str, str]]) -> bool:
    if not t:
        return False
    return any(truthy(row_get(t, k)) for k in [
        "SubjectOrSANSuppliedByRequester",
        "SubjectSuppliedByRequester",
        "SANSuppliedByRequester",
        "EnrolleeSuppliesSubject",
    ])


def is_esc1_template(t: Optional[Dict[str, str]]) -> bool:
    if not t:
        return False
    published = truthy(row_get(t, "Published"))
    requester_supplied = template_requester_supplied(t)
    auth = template_auth_capable(t)
    no_mgr = falsey(row_get(t, "ManagerApprovalRequired"))
    no_sig = falsey(row_get(t, "AuthorizedSignaturesRequired", "AuthorizedSignatures"))
    has_enroll = bool(row_get(t, "EnrollAllowPrincipals", "EnrollPrincipals", "BroadEnrollPrincipals")) or truthy(row_get(t, "ESC1Candidate_AnyEnroll"))
    return published and requester_supplied and auth and no_mgr and no_sig and has_enroll


def template_broad_enroll(t: Dict[str, str]) -> bool:
    return truthy(row_get(t, "ESC1Candidate_BroadEnroll")) or is_broad(row_get(t, "BroadEnrollPrincipals", "EnrollAllowPrincipals"))


def cert_san_token(c: Dict[str, str]) -> str:
    return row_get(c, "SAN_UPN_IdentityToken", "SAN_UPN", "SAN_DNS", "SAN_URI", "SAN_Email")


def cert_requester_token(c: Dict[str, str]) -> str:
    return row_get(c, "RequesterIdentityToken", "RequesterName", "Requester", "CallerName")


def cert_high_value(c: Dict[str, str]) -> bool:
    vals = [cert_san_token(c), row_get(c, "SAN_UPN"), row_get(c, "SAN_DNS"), cert_requester_token(c)]
    return any(starts_hv(v) or (v in hv_tokens) for v in vals if v)


def identity_mismatch(c: Dict[str, str]) -> Tuple[bool, str]:
    ims = row_get(c, "IdentityMappingStatus")
    if ims in {"DifferentMappedIdentity", "DifferentOrUnmappedIdentity"}:
        return True, ims
    if truthy(row_get(c, "RequesterSanUPNSameIdentity")) or ims in {"SameIdentity", "NoSANUPN"}:
        return False, ims or "SameIdentity"
    req = cert_requester_token(c)
    san = row_get(c, "SAN_UPN_IdentityToken", "SAN_UPN")
    if req and san and req != san:
        return True, "RawRequesterSanMismatch"
    return False, ims or "NotEvaluated"


def confidence_for_cert(c: Dict[str, str], template_join: str, mismatch_status: str) -> str:
    parse_ok = not row_get(c, "ParseStatus") or row_get(c, "ParseStatus") == "OK"
    if parse_ok and template_join == "Joined" and mismatch_status == "DifferentMappedIdentity" and truthy(row_get(c, "RequesterMappedToAD")) and truthy(row_get(c, "SAN_UPN_MappedToAD")):
        return "High"
    if parse_ok and (template_join == "Joined" or mismatch_status in {"DifferentMappedIdentity", "RawRequesterSanMismatch"}):
        return "Medium"
    return "Low"


R: Dict[str, Any] = {
    "meta": {
        "schema_version": "adcs-analysis/v1",
        "tool_version": "1.0.0-rc1",
        "generated_for": os.environ.get("ADCS_AUDIT_CLIENT", "Current audit dataset"),
        "generated_on": assessment_date(),
        "cert_rows": len(certs),
        "historical_issuance_rows": len(issuance_rows),
        "templates": len(tmpls),
        "pki_aces": len(acls),
        "cas": len(ca_rows),
        "dcs": len(dc_rows),
        "web_endpoints": len(web_rows),
        "hv_tokens": len(hv_tokens),
        "input_files": {k: v["files"] for k, v in roles.items() if v["files"]},
    }
}

# ---- data quality and signal counts
idcols = ["RequesterIdentityToken", "SAN_UPN_IdentityToken", "RequesterMappedToAD", "SAN_UPN_MappedToAD", "RequesterSanUPNSameIdentity", "IdentityMappingStatus"]
cert_cols = set(roles["certs"]["columns"])
R["dq"] = {
    "idcols_present": all(c in cert_cols for c in idcols) if certs else False,
    "parsestatus": dict(Counter(row_get(c, "ParseStatus", default="Unknown") for c in certs)),
    "disposition": dict(Counter(row_get(c, "CertDisposition", default="Issued") for c in certs)),
    "ims": dict(Counter(row_get(c, "IdentityMappingStatus", default="NotEvaluated") for c in certs)),
    "san_hv": sum(1 for c in certs if cert_high_value(c)),
    "san_unmapped": sum(1 for c in certs if cert_san_token(c).startswith("UNMAPPED_UPN_")),
}
R["dq"]["join"] = dict(Counter(join_template(c)[1] for c in certs))
R["dq"]["files_supplied"] = {k: bool(v["files"]) for k, v in roles.items()}

R["signals"] = {
    "esc6_san_attr": sum(1 for c in issuance_rows if truthy(row_get(c, "RequestAttributesHasSAN")) or "san:" in row_get(c, "RequestAttributes").lower()),
    "esc3_eku": sum(1 for c in issuance_rows if truthy(row_get(c, "IsEnrollmentAgentCert")) or CRA_EKU in row_get(c, "EKU_OIDs", "EnhancedKeyUsageOids")),
    "esc3_obo": sum(1 for c in issuance_rows if truthy(row_get(c, "OnBehalfOfCallerMismatch")) or (row_get(c, "CallerName") and row_get(c, "RequesterName") and row_get(c, "CallerName") != row_get(c, "RequesterName"))),
    "esc2": sum(1 for c in issuance_rows if truthy(row_get(c, "HasAnyPurposeOrNoEKU")) or "2.5.29.37.0" in row_get(c, "EKU_OIDs", "EnhancedKeyUsageOids") or ("EKU_OIDs" in c and not row_get(c, "EKU_OIDs") and row_get(c, "ParseStatus") in {"", "OK"})),
    "sid_missing": sum(
        1 for c in issuance_rows
        if row_get(c, "HasSidSecurityExtension").lower() == "false"
        and cert_auth_capable(c, join_template(c)[0])
        and truthy(row_get(join_template(c)[0] or c, "NoSecurityExtension"))
    ),
}
sidf = [c for c in issuance_rows if row_get(c, "SidExtensionMatchesRequester") == "False"]
R["signals"]["sid_mismatch_total"] = len(sidf)
R["signals"]["sid_mismatch_benign"] = sum(1 for c in sidf if truthy(row_get(c, "SidMismatchLikelyBenign")))
R["signals"]["sid_mismatch_real"] = R["signals"]["sid_mismatch_total"] - R["signals"]["sid_mismatch_benign"]

# ---- summary structures used by renderers
esc1_pub = [t for t in tmpls if is_esc1_template(t)]
R["esc1_templates"] = [{
    "name": row_get(t, "TemplateName", "Name") or "(unnamed template)",
    "display": row_get(t, "DisplayName") or row_get(t, "TemplateName", "Name") or "(unnamed template)",
    "oid": row_get(t, "TemplateOID", "OID"),
    "enroll": row_get(t, "EnrollAllowPrincipals", "EnrollPrincipals"),
    "broad": row_get(t, "BroadEnrollPrincipals"),
    "broad_enroll": str(template_broad_enroll(t)),
} for t in esc1_pub]

mismatch_rows = []
for c in issuance_rows:
    mismatch, status = identity_mismatch(c)
    if not mismatch:
        continue
    t, js, jm = join_template(c)
    mismatch_rows.append((c, status, t, js, jm))
R["esc1_issuance"] = {
    "diff_mapped_total": sum(1 for _c, st, _t, _js, _jm in mismatch_rows if st == "DifferentMappedIdentity"),
    "diff_or_unmapped": sum(1 for _c, st, _t, _js, _jm in mismatch_rows if st == "DifferentOrUnmappedIdentity"),
    "mismatch_total": len(mismatch_rows),
    "dm_auth": sum(1 for c, _st, t, _js, _jm in mismatch_rows if cert_auth_capable(c, t)),
    "dm_hv_san": sum(1 for c, _st, _t, _js, _jm in mismatch_rows if cert_high_value(c)),
    "dm_on_esc1_tmpl": sum(1 for _c, _st, t, _js, _jm in mismatch_rows if is_esc1_template(t)),
    "dm_on_esc1_tmpl_hv": sum(1 for c, _st, t, _js, _jm in mismatch_rows if is_esc1_template(t) and cert_high_value(c)),
}

# ESC4 recurring principal stats.
ctrl_by_principal: Dict[str, List[Dict[str, str]]] = defaultdict(list)
for t in tmpls:
    if not truthy(row_get(t, "ESC4Candidate")):
        continue
    for p in split_multi(row_get(t, "DangerousControlNonDefaultPrincipals", "DangerousControlAllowPrincipals")):
        ctrl_by_principal[p].append(t)
R["esc4"] = {
    "flagged": sum(1 for t in tmpls if truthy(row_get(t, "ESC4Candidate"))),
    "total": len(tmpls),
    "top_principals": [(p, len(rows)) for p, rows in sorted(ctrl_by_principal.items(), key=lambda kv: len(kv[1]), reverse=True)[:8]],
    "recurring_control_principals": [p for p, rows in ctrl_by_principal.items() if len(tmpls) and len(rows) >= max(5, int(len(tmpls) * 0.50))],
}

# ESC5 stats.
esc5_candidate_rows = [
    a for a in acls
    if truthy(row_get(a, "ESC5Candidate"))
    and not truthy(row_get(a, "IsCAHostAccount"))
    and row_get(a, "AccessType").lower() != "deny"
]
enroll_amplifiers = [a for a in acls if truthy(row_get(a, "IsEnrollRight"))]
esc5_control = []
for a in esc5_candidate_rows:
    if truthy(row_get(a, "IsEnrollRight")):
        continue
    rights_text = " ".join([row_get(a, "Rights"), row_get(a, "ResolvedRight")])
    if has_write(rights_text) or (row_get(a, "RightCategory") == "Control" and not is_read_or_execute_only_ace(a)):
        esc5_control.append(a)
esc5_by_principal: Dict[str, List[Dict[str, str]]] = defaultdict(list)
for a in esc5_control:
    esc5_by_principal[row_get(a, "Principal", default="(unknown principal)")].append(a)
R["esc5"] = {
    "candidates": len(esc5_candidate_rows),
    "rightcat": dict(Counter(row_get(a, "RightCategory", default="Unknown") for a in esc5_candidate_rows)),
    "enroll_right_total": len(enroll_amplifiers),
    "enroll_right_esc5": sum(1 for a in enroll_amplifiers if truthy(row_get(a, "ESC5Candidate"))),
    "write_control": len(esc5_control),
    "readonly_calibrated_out": max(0, len(esc5_candidate_rows) - len(esc5_control)),
    "control_principals": sorted(esc5_by_principal.keys()),
    "nonhv_highimpact": {
        p: sorted({row_get(a, "PkiObjectType", default="PKI object") for a in rows if row_get(a, "PkiObjectType") in HIGH_IMPACT_PKI})
        for p, rows in esc5_by_principal.items()
        if not starts_hv(p) and any(row_get(a, "PkiObjectType") in HIGH_IMPACT_PKI for a in rows)
    },
    "hv_control_principals": sorted([p for p in esc5_by_principal if starts_hv(p)]),
    "hv_control_objects": sorted({row_get(a, "PkiObjectType", default="PKI object") for p, rows in esc5_by_principal.items() if starts_hv(p) for a in rows}),
}

R["ca"] = {
    "count": len(ca_rows),
    "esc6_true": sum(1 for r in ca_rows if truthy(row_get(r, "EditF_AttributeSubjectAltName2", "ESC6_CAConfigFlag"))),
    "esc7_true": sum(1 for r in ca_rows if truthy(row_get(r, "ESC7Candidate"))),
    "esc11_true": sum(1 for r in ca_rows if truthy(row_get(r, "ESC11Candidate")) or row_get(r, "IF_EnforceEncryptICertRequest") == "False"),
}

# ESC6 issuance: SAN request attribute where joined template does not allow requester SAN.
e6_attr = [c for c in issuance_rows if truthy(row_get(c, "RequestAttributesHasSAN")) or "san:" in row_get(c, "RequestAttributes").lower()]
e6_strong = []
for c in e6_attr:
    t, js, jm = join_template(c)
    if t and not template_requester_supplied(t):
        e6_strong.append(c)
R["esc6_issuance"] = {
    "san_attr_rows": len(e6_attr),
    "strong_indicator_rows": len(e6_strong),
    "all_on_requester_san_tmpl": len(e6_attr) > 0 and len(e6_strong) == 0,
}

# ESC8 summary.
R["esc8"] = {
    "confirmed": sum(1 for w in web_rows if truthy(row_get(w, "ESC8Confirmed"))),
    "metadata_risk": sum(1 for w in web_rows if truthy(row_get(w, "Esc8RiskFromMetadata")) or truthy(row_get(w, "IsHttp"))),
    "needs_epa": sum(1 for w in web_rows if truthy(row_get(w, "ESC8NeedsEpaCheck")) or (truthy(row_get(w, "NtlmOffered")) and row_get(w, "EpaTokenChecking") in {"", "Unknown", "None", "Allow"})),
    "mitigated": sum(1 for w in web_rows if truthy(row_get(w, "ESC8Mitigated")) or (not truthy(row_get(w, "IsHttp")) and row_get(w, "EpaTokenChecking") == "Require")),
    "schemes": dict(Counter(row_get(w, "Scheme", default="Unknown") for w in web_rows)),
}

# ESC9/10 DC enforcement.
evaluated_dcs = [
    d for d in dc_rows
    if row_get(d, "ReadStatus") not in {"Unreadable", "Not Evaluated", "Not Collected", "Failed"}
    and bool(row_get(d, "StrongCertificateBindingEnforcement", "EnforcementLevel", "FullEnforcement"))
]
full_dcs = [d for d in evaluated_dcs if truthy(row_get(d, "FullEnforcement")) or row_get(d, "StrongCertificateBindingEnforcement") == "2" or row_get(d, "EnforcementLevel") == "Full"]
live_dcs = [d for d in evaluated_dcs if row_get(d, "ReadStatus") in {"OK", "Live"} and "SYSVOL" not in row_get(d, "ReadMethod").upper()]
R["esc910"] = {
    "dcs": len(dc_rows),
    "full": len(full_dcs),
    "all_full": len(dc_rows) > 0 and len(evaluated_dcs) == len(dc_rows) and len(full_dcs) == len(evaluated_dcs),
    "read_methods": dict(Counter(row_get(d, "ReadMethod", default="Unknown") for d in dc_rows)),
    "live_reads": len(live_dcs),
    "unreadable": len(dc_rows) - len(evaluated_dcs),
    "mitigated": len(dc_rows) > 0 and len(evaluated_dcs) == len(dc_rows) and len(full_dcs) == len(evaluated_dcs),
}

# ===== BUILD FINDINGS =====
findings: List[Dict[str, Any]] = []
finding_ids = set()


def add(**k: Any) -> None:
    k.setdefault("Principal", "")
    k.setdefault("Object", "")
    k.setdefault("Target", "")
    k.setdefault("Occurrences", "")
    k.setdefault("SampleRequestIDs", "")
    k.setdefault("EvidenceSource", "current scrubbed dataset")
    k.setdefault("RecommendedOwner", "AD/PKI administrator")
    k.setdefault("PriorityReason", "Evidence-backed current-run risk")
    identity = "|".join(norm(k.get(field)) for field in (
        "ESCType", "Category", "Principal", "Object", "Target", "EvidenceSource", "Evidence"
    ))
    finding_key = "CF-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    if finding_key in finding_ids:
        raise RuntimeError(f"Duplicate deterministic finding identity: {finding_key}")
    finding_ids.add(finding_key)
    # FindingKey is the stable machine correlation key. FindingID is assigned
    # after deterministic sorting so visible reports can use concise labels.
    k["FindingKey"] = finding_key
    findings.append(k)


def sample_ids(rows: List[Dict[str, str]], n: int = 8) -> str:
    vals = set()
    for r in rows:
        rid = row_get(r, "RequestID", "RequestId", "SerialNumber", "CertificateSerialNumber")
        if rid:
            vals.add(rid)
    return ";".join(sorted(vals)[:n])


def history_text(rows: List[Dict[str, str]]) -> str:
    dated = [
        parsed
        for row in rows
        for parsed in [parse_evidence_datetime(row_get(row, "SubmittedWhen", "ResolvedWhen"))]
        if parsed is not None
    ]
    first = min(dated).date().isoformat() if dated else "unknown"
    last = max(dated).date().isoformat() if dated else "unknown"
    revoked = sum(1 for row in rows if row_get(row, "CertDisposition").lower() == "revoked" or bool(row_get(row, "RevokedWhen")))
    return f"first={first}, last={last}, revoked={revoked}/{len(rows)}"


def ace_right_label(row: Dict[str, str]) -> str:
    """Prefer a resolved right, but never display an orphaned 'Generic.' label."""
    resolved = row_get(row, "ResolvedRight").strip()
    raw = row_get(row, "Rights").strip()
    if resolved and resolved.lower() not in {"generic", "unknown"}:
        return resolved
    if raw:
        return raw
    return "Generic rights" if resolved.lower() == "generic" else "Unknown right"


# ESC5: PKI object control grouped by principal.
for principal, rows in sorted(esc5_by_principal.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    obj_types = sorted({row_get(a, "PkiObjectType", default="PKI object") for a in rows})
    highimpact = any(o in HIGH_IMPACT_PKI for o in obj_types)
    severity = "Critical" if highimpact and not starts_hv(principal) else "High" if highimpact else "Medium"
    confidence = "High" if any(row_get(a, "RightCategory") == "Control" or has_write(row_get(a, "Rights")) for a in rows) else "Medium"
    add(
        Category="Template / PKI posture issue",
        Severity=severity,
        Confidence=confidence,
        ESCType="ESC5",
        Principal=principal,
        Object=";".join(obj_types),
        Occurrences=len(rows),
        Evidence=f"{len(rows)} dangerous PKI-object ACE(s) for {principal}: object types {', '.join(obj_types)}; dangerous rights include {', '.join(sorted({ace_right_label(a) for a in rows})[:6])}. Enroll-only rights were not counted as ESC5 control.",
        WhyThisMatters="Write/control rights over PKI AD objects can let that principal alter certificate trust, publish or modify templates, or change enrollment-service objects. That is a PKI privilege-escalation path if the principal is not an intended PKI administrator.",
        RecommendedValidation="Confirm whether the principal is an approved PKI/tier-0 administrator and whether each listed ACE is intentional.",
        RecommendedRemediation="Remove GenericAll/GenericWrite/WriteDacl/WriteOwner/WriteProperty from non-PKI-admin principals on the listed PKI objects; retain only explicit, documented PKI admin groups.",
    )

# ESC4: template control grouped by principal.
for principal, rows in sorted(ctrl_by_principal.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    published = [t for t in rows if truthy(row_get(t, "Published"))]
    recurring = principal in R["esc4"]["recurring_control_principals"]
    severity = "High" if published and not recurring else "Medium" if published else "Low"
    confidence = "Medium" if recurring else "High"
    names = [row_get(t, "TemplateName", "Name", default="(unnamed)") for t in rows[:8]]
    add(
        Category="Template / PKI posture issue",
        Severity=severity,
        Confidence=confidence,
        ESCType="ESC4",
        Principal=principal,
        Object=";".join(names),
        Occurrences=len(rows),
        Evidence=f"{principal} has dangerous template-control rights on {len(rows)} template(s); {len(published)} are published. Sample templates: {', '.join(names)}.",
        WhyThisMatters="A principal that can modify a certificate template can potentially reshape it into an ESC1-capable template and then request authentication-capable certificates.",
        RecommendedValidation="Confirm whether the principal is an intended template/PKI administrator. Recurring control across many templates may be normal PKI administration, but should be explicitly validated.",
        RecommendedRemediation="Remove Write/Full Control/WriteDacl/WriteOwner from non-PKI-admin principals on certificate templates; use a dedicated PKI admin group.",
    )

# ESC1 template posture.
if esc1_pub:
    broad_count = sum(1 for t in esc1_pub if template_broad_enroll(t))
    sev = "High" if broad_count else "Medium"
    add(
        Category="Template / PKI posture issue",
        Severity=sev,
        Confidence="High",
        ESCType="ESC1",
        Object=";".join([row_get(t, "TemplateName", "Name", default="(unnamed)") for t in esc1_pub[:12]]),
        Occurrences=len(esc1_pub),
        Evidence=f"{len(esc1_pub)} published template(s) are ESC1-shaped: requester-supplied Subject/SAN, authentication-capable EKU or Any Purpose/no EKU, no manager approval, no authorized signatures, and enrollment rights present. Broad enrollment templates: {broad_count}.",
        WhyThisMatters="An ESC1-shaped template can allow the enrollee to request a certificate that names another account and can be used for authentication.",
        RecommendedValidation="Confirm these templates genuinely require requester-supplied identity fields, and review every principal with Enroll/AutoEnroll rights.",
        RecommendedRemediation="Where possible, build subject/SAN from AD. Otherwise require manager approval or authorized signatures and restrict Enroll to tightly controlled groups.",
    )

# ESC1 suspicious issuance grouped by confidence/severity/template.
issue_groups: Dict[Tuple[str, str, str], List[Tuple[Dict[str, str], str, Optional[Dict[str, str]], str, str]]] = defaultdict(list)
for item in mismatch_rows:
    c, status, t, js, jm = item
    template_name = row_get(t or {}, "TemplateName", "Name") or row_get(c, "CertificateTemplate", default="Unmatched template")
    esc1_shape = is_esc1_template(t)
    hv = cert_high_value(c)
    if esc1_shape and hv and status == "DifferentMappedIdentity":
        sev = "Critical"
    elif esc1_shape and status in {"DifferentMappedIdentity", "RawRequesterSanMismatch"}:
        sev = "High"
    else:
        sev = "Medium"
    issue_groups[(sev, status, template_name)].append(item)
for (sev, status, template_name), items in sorted(issue_groups.items(), key=lambda kv: (-SEVERITY_ORDER[kv[0][0]], -len(kv[1])))[:20]:
    rows = [i[0] for i in items]
    hv_count = sum(1 for c in rows if cert_high_value(c))
    auth_count = sum(1 for c, _st, t, _js, _jm in items if cert_auth_capable(c, t))
    joined_count = sum(1 for _c, _st, _t, js, _jm in items if js == "Joined")
    conf = Counter(confidence_for_cert(c, js, st) for c, st, _t, js, _jm in items).most_common(1)[0][0]
    add(
        Category="Likely ESC1 misuse" if sev in {"Critical", "High"} else "Suspicious issuance needing validation",
        Severity=sev,
        Confidence=conf,
        ESCType="ESC1",
        Object=template_name,
        Target="High-value SAN target" if hv_count else "SAN target differs from requester",
        Occurrences=len(rows),
        SampleRequestIDs=sample_ids(rows),
        Evidence=f"{len(rows)} certificate issuance row(s) on template '{template_name}' have identity mismatch status {status}; {joined_count} joined to template inventory, {auth_count} are authentication-capable, and {hv_count} involve HV/high-value tokens; {history_text(rows)}. Request IDs: {sample_ids(rows) or 'not available'}.",
        WhyThisMatters="Requester/SAN identity mismatch on an authentication-capable certificate is the core signal for certificate-based impersonation. Issuance alone does not prove the certificate was used.",
        RecommendedValidation="Correlate the certificate serials/thumbprints or RequestIDs with DC/Kerberos certificate-authentication logs before claiming confirmed misuse.",
        RecommendedRemediation="If unexplained, revoke the certificates and tighten the issuing template's subject/SAN, approval, signature, and enrollment settings.",
    )

# ESC6 CA flag and issuance indicators.
for ca in ca_rows:
    if truthy(row_get(ca, "EditF_AttributeSubjectAltName2", "ESC6_CAConfigFlag")):
        add(
            Category="Template / PKI posture issue",
            Severity="Critical",
            Confidence="High",
            ESCType="ESC6",
            Object=row_get(ca, "CA_CommonName", "CA_Config", default="CA"),
            Evidence="CA configuration indicates EDITF_ATTRIBUTESUBJECTALTNAME2 / ESC6_CAConfigFlag is enabled.",
            WhyThisMatters="When the CA honors SAN values supplied in request attributes, templates that do not normally allow requester-supplied SAN can still be abused to request certificates for other identities.",
            RecommendedValidation="Confirm the CA EditFlags value from the CA host and verify whether any SAN request attributes were accepted.",
            RecommendedRemediation="Clear EDITF_ATTRIBUTESUBJECTALTNAME2 and restart the CA service after change-control validation.",
        )
if e6_strong:
    add(
        Category="Suspicious issuance needing validation",
        Severity="High" if not any(cert_high_value(c) for c in e6_strong) else "Critical",
        Confidence="High",
        ESCType="ESC6",
        Object="Issued certificates with SAN request attributes",
        Occurrences=len(e6_strong),
        SampleRequestIDs=sample_ids(e6_strong),
        Evidence=f"{len(e6_strong)} issued certificate row(s) include SAN request attributes on joined templates that do not allow requester-supplied Subject/SAN; {history_text(e6_strong)}. Request IDs: {sample_ids(e6_strong) or 'not available'}.",
        WhyThisMatters="This is an issuance-side indicator that the CA may have honored SAN values through request attributes rather than template settings.",
        RecommendedValidation="Confirm the CA's EDITF_ATTRIBUTESUBJECTALTNAME2 flag and inspect the specific request rows.",
        RecommendedRemediation="Disable the CA-wide SAN attribute behavior if not explicitly required and reissue affected certificates as needed.",
    )

# ESC2.
esc2_rows = [c for c in issuance_rows if truthy(row_get(c, "HasAnyPurposeOrNoEKU")) or "2.5.29.37.0" in row_get(c, "EKU_OIDs", "EnhancedKeyUsageOids") or ("EKU_OIDs" in c and not row_get(c, "EKU_OIDs") and row_get(c, "ParseStatus") in {"", "OK"})]
if esc2_rows:
    add(
        Category="Suspicious issuance needing validation",
        Severity="High" if any(cert_high_value(c) for c in esc2_rows) else "Medium",
        Confidence="Medium",
        ESCType="ESC2",
        Object="Any Purpose / no-EKU issued certificates",
        Occurrences=len(esc2_rows),
        SampleRequestIDs=sample_ids(esc2_rows),
        Evidence=f"{len(esc2_rows)} issued certificate row(s) have Any Purpose or no EKU evidence; high-value involvement: {sum(1 for c in esc2_rows if cert_high_value(c))}; {history_text(esc2_rows)}. Request IDs: {sample_ids(esc2_rows) or 'not available'}.",
        WhyThisMatters="Any Purpose or no-EKU certificates may be usable for client authentication depending on chain and policy context.",
        RecommendedValidation="Confirm intended EKUs and whether the certificate chain allows client authentication.",
        RecommendedRemediation="Remove Any Purpose/no-EKU issuance unless explicitly required; issue workload-specific EKUs only.",
    )

# ESC3.
esc3_cert_rows = [c for c in issuance_rows if truthy(row_get(c, "IsEnrollmentAgentCert")) or CRA_EKU in row_get(c, "EKU_OIDs", "EnhancedKeyUsageOids")]
esc3_obo_rows = [c for c in issuance_rows if truthy(row_get(c, "OnBehalfOfCallerMismatch")) or (row_get(c, "CallerName") and row_get(c, "RequesterName") and row_get(c, "CallerName") != row_get(c, "RequesterName"))]
if esc3_cert_rows or esc3_obo_rows:
    hv_obo = sum(1 for c in esc3_obo_rows if cert_high_value(c))
    add(
        Category="Suspicious issuance needing validation" if (esc3_obo_rows or esc3_cert_rows) else "Template / PKI posture issue",
        Severity="Critical" if hv_obo else "High" if esc3_obo_rows else "Medium",
        Confidence="High" if esc3_obo_rows else "Medium",
        ESCType="ESC3",
        Object="Enrollment Agent / on-behalf-of issuance",
        Occurrences=len(esc3_cert_rows) + len(esc3_obo_rows),
        SampleRequestIDs=sample_ids(esc3_obo_rows or esc3_cert_rows),
        Evidence=f"{len(esc3_cert_rows)} certificate row(s) carry the Certificate Request Agent EKU and {len(esc3_obo_rows)} on-behalf-of row(s) show caller/requester differences; high-value OBO rows: {hv_obo}; {history_text(esc3_obo_rows or esc3_cert_rows)}.",
        WhyThisMatters="Enrollment Agent capability can be legitimate, but it can also enable requesting certificates on behalf of other principals if not tightly restricted.",
        RecommendedValidation="Confirm all enrollment agents are authorized and that CA Enrollment Agent restrictions limit which templates and principals they can request for.",
        RecommendedRemediation="Restrict enrollment-agent template enrollment, configure CA Enrollment Agent restrictions, and require authorized signatures on sensitive templates.",
    )

# ESC7, ESC11.
for ca in ca_rows:
    ca_name = row_get(ca, "CA_CommonName", "CA_Config", default="CA")
    if truthy(row_get(ca, "ESC7Candidate")):
        add(
            Category="Template / PKI posture issue",
            Severity="High" if esc1_pub else "Medium",
            Confidence="High",
            ESCType="ESC7",
            Object=ca_name,
            Evidence=f"CA security export marks ESC7Candidate=True for {ca_name}; Manage CA principals: {row_get(ca, 'ManageCAPrincipals') or 'not listed'}; Manage Certificates principals: {row_get(ca, 'ManageCertificatesPrincipals') or 'not listed'}.",
            WhyThisMatters="Manage CA and Manage Certificates can permit CA configuration changes or request approvals that enable certificate abuse.",
            RecommendedValidation="Confirm every listed principal is an intended CA administrator/officer.",
            RecommendedRemediation="Remove Manage CA / Manage Certificates from non-authorized principals and use dedicated CA admin/officer groups.",
        )
    if truthy(row_get(ca, "ESC11Candidate")) or row_get(ca, "IF_EnforceEncryptICertRequest") == "False":
        add(
            Category="Template / PKI posture issue",
            Severity="High" if esc1_pub or R["ca"]["esc6_true"] else "Medium",
            Confidence="High",
            ESCType="ESC11",
            Object=ca_name,
            Evidence=f"CA security export indicates encrypted ICertRequest enforcement is not required for {ca_name} (ESC11Candidate={row_get(ca, 'ESC11Candidate')}, IF_EnforceEncryptICertRequest={row_get(ca, 'IF_EnforceEncryptICertRequest')}).",
            WhyThisMatters="If request traffic is not protected, NTLM relay paths to the CA RPC interface may be possible depending on environment controls.",
            RecommendedValidation="Confirm InterfaceFlags on the CA and whether ICertRequest encryption is enforced.",
            RecommendedRemediation="Enable encrypted ICertRequest enforcement and restart the CA service after validation.",
        )

# ESC8.
for w in web_rows:
    host = row_get(w, "EndpointHostName", "CA_CommonName", default="web enrollment endpoint")
    confirmed = truthy(row_get(w, "ESC8Confirmed"))
    risk = truthy(row_get(w, "Esc8RiskFromMetadata")) or truthy(row_get(w, "IsHttp"))
    needs_epa = truthy(row_get(w, "ESC8NeedsEpaCheck")) or (truthy(row_get(w, "NtlmOffered")) and row_get(w, "EpaTokenChecking") in {"", "Unknown", "None", "Allow"})
    if confirmed or risk or needs_epa:
        add(
            Category="Template / PKI posture issue",
            Severity="Critical" if confirmed and esc1_pub else "High" if confirmed or risk else "Medium",
            Confidence="High" if confirmed or risk else "Medium",
            ESCType="ESC8",
            Object=host,
            Evidence=f"Web enrollment endpoint {host}: Scheme={row_get(w, 'Scheme') or 'unknown'}, IsHttp={row_get(w, 'IsHttp') or 'unknown'}, NTLM offered={row_get(w, 'NtlmOffered') or 'unknown'}, EPA={row_get(w, 'EpaTokenChecking') or 'unknown'}, ESC8Confirmed={row_get(w, 'ESC8Confirmed') or 'unknown'}, NeedsEpaCheck={row_get(w, 'ESC8NeedsEpaCheck') or 'unknown'}." ,
            WhyThisMatters="AD CS web enrollment can be exposed to NTLM relay risk if HTTP/NTLM is available and EPA/channel binding is absent or unverified.",
            RecommendedValidation="Confirm endpoint reachability, authentication schemes, and IIS Extended Protection settings from the web host.",
            RecommendedRemediation="Require HTTPS, disable NTLM where possible, require Extended Protection for Authentication, or disable web enrollment if unused.",
        )

# ESC9/10.
sid_signal = R["signals"]["sid_missing"] + R["signals"]["sid_mismatch_real"]
if sid_signal:
    if not dc_rows:
        sev, conf, cat = "Medium", "Low", "Suspicious issuance needing validation"
        dc_note = "DC strong-mapping enforcement file was not provided, so exploitability cannot be determined."
    elif R["esc910"]["mitigated"]:
        sev, conf, cat = "Low", "High", "Informational / not currently exploitable"
        dc_note = f"All {len(dc_rows)} supplied DC row(s) show Full strong-mapping enforcement, so weak/missing-SID mappings should be rejected."
    else:
        sev, conf, cat = "High", "Medium", "Suspicious issuance needing validation"
        dc_note = f"{R['esc910']['full']}/{len(evaluated_dcs)} readable DC row(s) show Full enforcement; unreadable={R['esc910']['unreadable']}."
    add(
        Category=cat,
        Severity=sev,
        Confidence=conf,
        ESCType="ESC9/10",
        Object="SID security extension / DC enforcement",
        Occurrences=sid_signal,
        Evidence=f"SID-extension signals: missing={R['signals']['sid_missing']}, real mismatches={R['signals']['sid_mismatch_real']}. {dc_note}",
        WhyThisMatters="Weak certificate mapping is exploitable only when domain controllers accept weak mappings for certificates missing or mismatching the SID security extension.",
        RecommendedValidation="Confirm StrongCertificateBindingEnforcement live on every DC and correlate any suspicious certificates to authentication logs.",
        RecommendedRemediation="Set StrongCertificateBindingEnforcement=2 on all DCs and reissue certificates with the SID security extension where applicable.",
    )

# Keep reports readable while retaining a stable, non-reversible key for
# regression tests and machine correlation. Example: F01-ESC8.
findings.sort(
    key=lambda f: (
        -SEVERITY_ORDER.get(f.get("Severity"), 0),
        norm(f.get("ESCType")),
        f.get("FindingKey", ""),
    )
)
for index, finding in enumerate(findings, 1):
    esc_label = re.sub(r"[^A-Za-z0-9]+", "-", norm(finding.get("ESCType"))).strip("-").upper() or "OTHER"
    finding["FindingID"] = f"F{index:02d}-{esc_label}"

R["findings"] = findings
R["sev_counts"] = dict(Counter(f["Severity"] for f in findings))
R["cat_counts"] = dict(Counter(f["Category"] for f in findings))

# Coverage matrix from supplied data and findings.
def max_status_for(esc: str, complete: bool) -> str:
    hits = [f["Severity"] for f in findings if f["ESCType"] == esc]
    if not hits:
        return "Clean" if complete else "Not Evaluated"
    return max(hits, key=lambda s: SEVERITY_ORDER.get(s, -1))

coverage = []
coverage.append(("ESC1", max_status_for("ESC1", bool(certs and tmpls)), f"{len(esc1_pub)} ESC1-shaped published template(s); {len(mismatch_rows)} requester/SAN mismatch issuance row(s)."))
coverage.append(("ESC2", max_status_for("ESC2", bool(certs)), f"{len(esc2_rows)} Any Purpose/no-EKU issued certificate row(s)."))
coverage.append(("ESC3", max_status_for("ESC3", bool(certs)), f"{len(esc3_cert_rows)} enrollment-agent certificate row(s); {len(esc3_obo_rows)} on-behalf-of row(s)."))
coverage.append(("ESC4", max_status_for("ESC4", bool(tmpls)), f"{R['esc4']['flagged']} template(s) flagged with dangerous template-control rights."))
coverage.append(("ESC5", max_status_for("ESC5", bool(acls)), f"{len(esc5_control)} write/control PKI ACE(s) after excluding enroll-only and CA-host self-control rows."))
coverage.append(("ESC6", max_status_for("ESC6", bool(certs and tmpls and ca_rows)), f"CA flag true on {R['ca']['esc6_true']} CA row(s); {len(e6_strong)} strong issuance-side SAN-attribute indicator row(s)."))
coverage.append(("ESC7", max_status_for("ESC7", bool(ca_rows)), f"{R['ca']['esc7_true']} CA row(s) marked ESC7Candidate."))
coverage.append(("ESC8", max_status_for("ESC8", bool(web_rows)), f"{len(web_rows)} endpoint row(s); confirmed={R['esc8']['confirmed']}, metadata risk={R['esc8']['metadata_risk']}, needs EPA check={R['esc8']['needs_epa']}."))
esc910_complete = bool(certs and tmpls and dc_rows and len(evaluated_dcs) == len(dc_rows))
esc910_status = "Mitigated" if sid_signal and esc910_complete and R["esc910"]["mitigated"] else max_status_for("ESC9/10", esc910_complete)
coverage.append(("ESC9/10", esc910_status, f"SID signals={sid_signal}; DC Full enforcement {R['esc910']['full']}/{len(evaluated_dcs)} readable row(s); unreadable={R['esc910']['unreadable']}."))
coverage.append(("ESC11", max_status_for("ESC11", bool(ca_rows)), f"{R['ca']['esc11_true']} CA row(s) marked ESC11Candidate or not enforcing encrypted ICertRequest."))
R["coverage"] = coverage

# Lightweight graph model from findings, not from hard-coded examples.
graph_nodes: Dict[str, Dict[str, Any]] = {}
graph_edges: List[Dict[str, Any]] = []

def node_id(prefix: str, label: str) -> str:
    """Stable, collision-resistant IDs shared by every graph renderer/exporter."""
    digest = hashlib.sha256(f"{prefix}|{norm(label).lower()}".encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def add_node(nid: str, label: str, kind: str, severity: str = "") -> None:
    graph_nodes[nid] = {"id": nid, "label": label[:80] or kind, "kind": kind, "severity": severity}


def add_edge(src: str, dst: str, label: str, esc: str, severity: str) -> None:
    graph_edges.append({"source": src, "target": dst, "label": label, "esc": esc, "severity": severity})

for f in findings[:14]:
    src_label = f.get("Principal") or f.get("Object") or f["ESCType"]
    mid_label = f["ESCType"]
    dst_label = f.get("Target") or f.get("Object") or "PKI risk"
    src = node_id("src", src_label)
    mid = node_id("esc", f["FindingKey"] + "_" + mid_label)
    dst = node_id("dst", dst_label)
    add_node(src, src_label, "Principal/Object", f["Severity"])
    add_node(mid, f["FindingID"], "ESC finding", f["Severity"])
    add_node(dst, dst_label, "Impact/target", f["Severity"])
    add_edge(src, mid, f["Severity"], f["ESCType"], f["Severity"])
    add_edge(mid, dst, "can enable", f["ESCType"], f["Severity"])
R["graph"] = {"nodes": list(graph_nodes.values()), "edges": graph_edges}

# ===== write results and findings CSV =====
with open(os.path.join(WK, "results.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, indent=2, ensure_ascii=False, default=str)

cols = [
    "FindingID", "FindingKey", "Category", "Severity", "Confidence", "ESCType", "Principal", "Object", "Target",
    "Occurrences", "SampleRequestIDs", "EvidenceSource", "PriorityReason", "RecommendedOwner",
    "Evidence", "WhyThisMatters", "RecommendedValidation", "RecommendedRemediation",
]
with open(os.path.join(OUT, "ADCS_ESC_Findings.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for fd in findings:
        w.writerow({c: fd.get(c, "") for c in cols})

role_counts = ", ".join(f"{k}={len(v['rows'])}" for k, v in roles.items())
print(f"Inputs: {role_counts}")
print(f"Findings: {len(findings)}")
print("Severity:", dict(Counter(f["Severity"] for f in findings)))
print("Wrote working/results.json and output/ADCS_ESC_Findings.csv")
