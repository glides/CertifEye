#!/usr/bin/env python3
"""Generate large, deterministic, token-only CertifEye demonstration packages.

The generator intentionally uses only the public CertifEye schema contract. It does
not read the local client-derived sample, copy identifiers, or create a token map.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "synthetic-samples"
START = datetime(2023, 7, 1, tzinfo=timezone.utc)
END = datetime(2026, 6, 30, tzinfo=timezone.utc)
SPAN_DAYS = (END - START).days

CERT_COLUMNS = [
    "RequestID", "RequesterName", "CallerName", "SubmittedWhen", "ResolvedWhen",
    "CertificateTemplate", "SerialNumber", "CertificateHash", "NotBefore", "NotAfter",
    "CA_CommonName", "CA_DistinguishedName", "RequestAttributes", "CertSubject",
    "CertIssuer", "CertThumbprintParsed", "EKU_OIDs", "AuthCapableOrAnyPurpose",
    "SAN_UPN", "SAN_DNS", "SAN_Email", "SAN_URI", "SAN_Text",
    "HasSidSecurityExtension", "RequestAttributesHasSAN", "IsEnrollmentAgentCert",
    "HasAnyPurposeOrNoEKU", "OnBehalfOfCallerMismatch", "CertDisposition",
    "RevokedWhen", "RevokedReason", "ParseStatus", "RequesterIdentityToken",
    "SAN_UPN_IdentityToken", "RequesterMappedToAD", "SAN_UPN_MappedToAD",
    "RequesterIdentityMappingStatus", "SAN_UPN_IdentityMappingStatus",
    "RequesterSanUPNSameIdentity", "IdentityMappingStatus", "SidSecurityExtensionToken",
    "SidExtensionMatchesRequester", "SidMismatchLikelyBenign",
]

TEMPLATE_COLUMNS = [
    "TemplateName", "DisplayName", "TemplateOID", "TemplateSchemaVersion",
    "TemplateMinorRevision", "Published", "PublishingCAs", "SubjectSuppliedByRequester",
    "SANSuppliedByRequester", "SubjectOrSANSuppliedByRequester", "NameFlagDecimal",
    "NameFlagHex", "EnrollmentFlagDecimal", "EnrollmentFlagHex",
    "ManagerApprovalRequired", "AuthorizedSignaturesRequired", "RequiredSignatureCount",
    "AutoEnrollmentFlagSet", "NoSecurityExtension", "EKU_OIDs", "AuthEKUsMatched",
    "NoEKU", "AuthCapableOrAnyPurpose", "EnrollAllowPrincipals",
    "EnrollDenyPrincipals", "AutoEnrollAllowPrincipals", "BroadEnrollPrincipals",
    "DangerousControlAllowPrincipals", "DangerousControlNonDefaultPrincipals",
    "ESC4Candidate", "ESC1Candidate_AnyEnroll", "ESC1Candidate_BroadEnroll",
    "DistinguishedName", "SidExtensionMatchesRequester", "SidMismatchLikelyBenign",
]

ACL_COLUMNS = [
    "PkiObjectType", "ObjectDistinguishedName", "Principal", "Rights",
    "ObjectTypeGuid", "ResolvedRight", "RightCategory", "IsEnrollRight", "AccessType",
    "IsDangerous", "IsDefaultPrincipal", "IsCAHostAccount", "ESC5Candidate",
    "SidExtensionMatchesRequester", "SidMismatchLikelyBenign",
]

CA_COLUMNS = [
    "CA_Config", "CA_CommonName", "ManageCAPrincipals", "ManageCertificatesPrincipals",
    "SecuritySource", "EditFlagsHex", "EditF_AttributeSubjectAltName2",
    "ESC6_CAConfigFlag", "InterfaceFlagsHex", "IF_EnforceEncryptICertRequest",
    "ESC11Candidate", "ESC7Candidate", "SidExtensionMatchesRequester",
    "SidMismatchLikelyBenign",
]

DC_COLUMNS = [
    "DC_DnsHostName", "StrongCertificateBindingEnforcement", "EnforcementLevel",
    "FullEnforcement", "ReadStatus", "ReadMethod", "ReadDetail",
    "SidExtensionMatchesRequester", "SidMismatchLikelyBenign",
]

WEB_COLUMNS = [
    "CA_CommonName", "EndpointKind", "EndpointHostName", "Scheme", "IsHttp",
    "AuthFromMetadata", "Probed", "Reachable", "HttpStatus", "AuthSchemesOffered",
    "NtlmOffered", "EpaTokenChecking", "EpaSource", "EpaDetail",
    "Esc8RiskFromMetadata", "ESC8Confirmed", "ESC8NeedsEpaCheck", "ESC8Mitigated",
    "SidExtensionMatchesRequester", "SidMismatchLikelyBenign",
]

HV_COLUMNS = ["Token", "ObjectType", "TokenType", "HighValueReason", "KnownLabel"]

SCENARIOS = {
    "all-esc-enterprise": {
        "description": "Broad and recurring evidence with at least one finding for every supported ESC area.",
        "certs": 16800, "templates": 48, "acls": 84, "dcs": 12, "hv": 64,
        "expected": ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8", "ESC9/10", "ESC11"],
        "absent": [],
        "coverage": {
            "ESC1": "Critical", "ESC2": "High", "ESC3": "Critical", "ESC4": "High",
            "ESC5": "Critical", "ESC6": "Critical", "ESC7": "High", "ESC8": "Critical",
            "ESC9/10": "High", "ESC11": "High",
        },
    },
    "hardened-baseline": {
        "description": "Readable, intentionally hardened posture with benign, denied, and parse-error negative controls.",
        "certs": 15500, "templates": 46, "acls": 76, "dcs": 10, "hv": 60,
        "expected": [],
        "absent": ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8", "ESC9/10", "ESC11"],
        "coverage": {
            "ESC1": "Clean", "ESC2": "Clean", "ESC3": "Clean", "ESC4": "Clean",
            "ESC5": "Clean", "ESC6": "Clean", "ESC7": "Clean", "ESC8": "Clean",
            "ESC9/10": "Clean", "ESC11": "Clean",
        },
    },
    "mixed-enterprise": {
        "description": "A realistic mixture of open, benign, revoked, unreadable, and mitigated evidence.",
        "certs": 17250, "templates": 52, "acls": 90, "dcs": 11, "hv": 66,
        "expected": ["ESC1", "ESC3", "ESC4", "ESC5", "ESC8", "ESC9/10", "ESC11"],
        "absent": ["ESC2", "ESC6", "ESC7"],
        "coverage": {
            "ESC1": "High", "ESC2": "Clean", "ESC3": "High", "ESC4": "High",
            "ESC5": "Critical", "ESC6": "Clean", "ESC7": "Clean", "ESC8": "High",
            "ESC9/10": "High", "ESC11": "High",
        },
    },
}


def token(scenario: str, kind: str, index: int | str) -> str:
    digest = hashlib.sha256(f"certifeye-synthetic|{scenario}|{kind}|{index}".encode()).hexdigest()[:24]
    return f"{kind}_{digest}"


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def template_rows(name: str, count: int) -> list[dict[str, str]]:
    ca = token(name, "CA", 0)
    rows = []
    for index in range(count):
        template = token(name, "TPL", index)
        group = token(name, "GROUP", index % 12)
        row = {
            "TemplateName": template,
            "DisplayName": token(name, "DISPLAY", index),
            "TemplateOID": f"1.3.6.1.4.1.55555.{list(SCENARIOS).index(name) + 1}.{index + 1}",
            "TemplateSchemaVersion": "4",
            "TemplateMinorRevision": str(index % 9),
            "Published": "False" if index % 11 == 0 else "True",
            "PublishingCAs": json.dumps([ca]),
            "SubjectSuppliedByRequester": "False",
            "SANSuppliedByRequester": "False",
            "SubjectOrSANSuppliedByRequester": "False",
            "NameFlagDecimal": "0",
            "NameFlagHex": "0x00000000",
            "EnrollmentFlagDecimal": "0",
            "EnrollmentFlagHex": "0x00000000",
            "ManagerApprovalRequired": "False",
            "AuthorizedSignaturesRequired": "False",
            "RequiredSignatureCount": "0",
            "AutoEnrollmentFlagSet": "True" if index % 6 == 0 else "False",
            "NoSecurityExtension": "False",
            "EKU_OIDs": "1.3.6.1.5.5.7.3.2",
            "AuthEKUsMatched": "1.3.6.1.5.5.7.3.2",
            "NoEKU": "False",
            "AuthCapableOrAnyPurpose": "True",
            "EnrollAllowPrincipals": json.dumps([group]),
            "EnrollDenyPrincipals": "[]",
            "AutoEnrollAllowPrincipals": json.dumps([group]) if index % 6 == 0 else "[]",
            "BroadEnrollPrincipals": "",
            "DangerousControlAllowPrincipals": "",
            "DangerousControlNonDefaultPrincipals": "",
            "ESC4Candidate": "False",
            "ESC1Candidate_AnyEnroll": "False",
            "ESC1Candidate_BroadEnroll": "False",
            "DistinguishedName": token(name, "DN", f"template-{index}"),
            "SidExtensionMatchesRequester": "",
            "SidMismatchLikelyBenign": "",
        }
        rows.append(row)

    # Template index 5 is authentication-capable but omits the SID extension. It
    # becomes actionable only when matching issuance rows and DC evidence exist.
    rows[5]["NoSecurityExtension"] = "True"

    if name in {"all-esc-enterprise", "mixed-enterprise"}:
        rows[0].update({
            "Published": "True",
            "SubjectSuppliedByRequester": "True",
            "SANSuppliedByRequester": "True",
            "SubjectOrSANSuppliedByRequester": "True",
            "NameFlagDecimal": "1",
            "NameFlagHex": "0x00000001",
            "ESC1Candidate_AnyEnroll": "True",
        })
        if name == "all-esc-enterprise":
            rows[0]["EnrollAllowPrincipals"] = json.dumps(["BROAD_AUTHENTICATED_USERS"])
            rows[0]["BroadEnrollPrincipals"] = json.dumps(["BROAD_AUTHENTICATED_USERS"])
            rows[0]["ESC1Candidate_BroadEnroll"] = "True"
        rows[1].update({
            "Published": "True",
            "DangerousControlAllowPrincipals": json.dumps([token(name, "PRINCIPAL", "template-control")]),
            "DangerousControlNonDefaultPrincipals": json.dumps([token(name, "PRINCIPAL", "template-control")]),
            "ESC4Candidate": "True",
        })
    return rows


def certificate_rows(name: str, count: int, templates: list[dict[str, str]], hv: list[str]) -> list[dict[str, str]]:
    ca = token(name, "CA", 0)
    ca_dn = token(name, "DN", "ca")
    rows = []
    for index in range(count):
        submitted = START + timedelta(days=(index * 73) % (SPAN_DAYS + 1), minutes=index % 1440)
        if index == count - 1:
            submitted = END
        requester = token(name, "PRINCIPAL", index % 420)
        template = templates[6 + (index % max(1, len(templates) - 6))]["TemplateName"]
        has_san = index % 4 == 0
        revoked = index > 0 and index % 1103 == 0
        row = {
            "RequestID": token(name, "REQ", index),
            "RequesterName": requester,
            "CallerName": requester,
            "SubmittedWhen": iso(submitted),
            "ResolvedWhen": iso(submitted + timedelta(minutes=2 + index % 11)),
            "CertificateTemplate": template,
            "SerialNumber": token(name, "SERIAL", index),
            "CertificateHash": token(name, "HASH", index),
            "NotBefore": iso(submitted),
            "NotAfter": iso(submitted + timedelta(days=365 + index % 30)),
            "CA_CommonName": ca,
            "CA_DistinguishedName": ca_dn,
            "RequestAttributes": "",
            "CertSubject": token(name, "SUBJECT", index),
            "CertIssuer": token(name, "ISSUER", 0),
            "CertThumbprintParsed": token(name, "THUMBPRINT", index),
            "EKU_OIDs": "1.3.6.1.5.5.7.3.2",
            "AuthCapableOrAnyPurpose": "True",
            "SAN_UPN": requester if has_san else "",
            "SAN_DNS": token(name, "COMPUTER", index % 260) if index % 9 == 0 else "",
            "SAN_Email": "",
            "SAN_URI": "",
            "SAN_Text": "",
            "HasSidSecurityExtension": "True",
            "RequestAttributesHasSAN": "False",
            "IsEnrollmentAgentCert": "False",
            "HasAnyPurposeOrNoEKU": "False",
            "OnBehalfOfCallerMismatch": "False",
            "CertDisposition": "Revoked" if revoked else "Issued",
            "RevokedWhen": iso(submitted + timedelta(days=45)) if revoked else "",
            "RevokedReason": "Superseded" if revoked else "",
            "ParseStatus": "OK",
            "RequesterIdentityToken": requester,
            "SAN_UPN_IdentityToken": requester if has_san else "",
            "RequesterMappedToAD": "True",
            "SAN_UPN_MappedToAD": "True" if has_san else "",
            "RequesterIdentityMappingStatus": "Mapped",
            "SAN_UPN_IdentityMappingStatus": "Mapped" if has_san else "NotPresent",
            "RequesterSanUPNSameIdentity": "True",
            "IdentityMappingStatus": "SameIdentity" if has_san else "NoSANUPN",
            "SidSecurityExtensionToken": token(name, "SID", index % 420),
            "SidExtensionMatchesRequester": "True",
            "SidMismatchLikelyBenign": "False",
        }
        rows.append(row)

    def esc1(index: int, high_value: bool) -> None:
        requester = token(name, "PRINCIPAL", f"esc1-{index}")
        target = hv[index % len(hv)] if high_value else token(name, "PRINCIPAL", f"target-{index}")
        rows[index].update({
            "CertificateTemplate": templates[0]["TemplateName"],
            "RequesterName": requester,
            "CallerName": requester,
            "RequesterIdentityToken": requester,
            "SAN_UPN": target,
            "SAN_UPN_IdentityToken": target,
            "RequesterMappedToAD": "True",
            "SAN_UPN_MappedToAD": "True",
            "RequesterSanUPNSameIdentity": "False",
            "IdentityMappingStatus": "DifferentMappedIdentity",
            "SidExtensionMatchesRequester": "True",
        })

    if name == "all-esc-enterprise":
        for index in range(0, 16):
            esc1(index, high_value=index < 6)
        for index in range(24, 36):
            rows[index].update({
                "CertificateTemplate": templates[3]["TemplateName"],
                "EKU_OIDs": "2.5.29.37.0",
                "HasAnyPurposeOrNoEKU": "True",
                "RequesterName": hv[0] if index == 24 else rows[index]["RequesterName"],
                "RequesterIdentityToken": hv[0] if index == 24 else rows[index]["RequesterIdentityToken"],
            })
        for index in range(44, 56):
            caller = token(name, "PRINCIPAL", f"agent-{index % 3}")
            target = hv[index % 2] if index < 47 else token(name, "PRINCIPAL", f"obo-{index}")
            rows[index].update({
                "CertificateTemplate": templates[4]["TemplateName"],
                "RequesterName": target,
                "RequesterIdentityToken": target,
                "CallerName": caller,
                "EKU_OIDs": "1.3.6.1.4.1.311.20.2.1",
                "IsEnrollmentAgentCert": "True",
                "OnBehalfOfCallerMismatch": "True",
            })
        for index in range(64, 74):
            rows[index].update({
                "CertificateTemplate": templates[2]["TemplateName"],
                "RequesterName": hv[2] if index == 64 else rows[index]["RequesterName"],
                "RequesterIdentityToken": hv[2] if index == 64 else rows[index]["RequesterIdentityToken"],
                "RequestAttributes": f"SAN:UPN={hv[index % len(hv)]}",
                "RequestAttributesHasSAN": "True",
            })
        for index in range(84, 96):
            rows[index].update({
                "CertificateTemplate": templates[5]["TemplateName"],
                "HasSidSecurityExtension": "False",
                "SidSecurityExtensionToken": "",
                "SidExtensionMatchesRequester": "False",
                "SidMismatchLikelyBenign": "False",
            })
        for index in range(104, 124):
            rows[index].update({"SidExtensionMatchesRequester": "False", "SidMismatchLikelyBenign": "True"})
    elif name == "mixed-enterprise":
        for index in range(0, 10):
            esc1(index, high_value=False)
        for index in range(24, 30):
            caller = token(name, "PRINCIPAL", f"agent-{index % 2}")
            rows[index].update({
                "CertificateTemplate": templates[4]["TemplateName"],
                "CallerName": caller,
                "EKU_OIDs": "1.3.6.1.4.1.311.20.2.1",
                "IsEnrollmentAgentCert": "True",
                "OnBehalfOfCallerMismatch": "True",
            })
        for index in range(44, 51):
            rows[index].update({
                "CertificateTemplate": templates[5]["TemplateName"],
                "HasSidSecurityExtension": "False",
                "SidSecurityExtensionToken": "",
                "SidExtensionMatchesRequester": "False",
                "SidMismatchLikelyBenign": "False",
            })
        for index in range(60, 80):
            rows[index].update({"SidExtensionMatchesRequester": "False", "SidMismatchLikelyBenign": "True"})

    # Negative controls: they resemble findings but were never issued, or failed
    # parsing. They must not become issuance findings.
    denied_start = 140 if name == "all-esc-enterprise" else 100
    for index in range(denied_start, denied_start + 8):
        rows[index].update({
            "CertDisposition": "Denied",
            "EKU_OIDs": "",
            "HasAnyPurposeOrNoEKU": "True",
            "RequestAttributes": f"SAN:UPN={hv[0]}",
            "RequestAttributesHasSAN": "True",
            "HasSidSecurityExtension": "False",
        })
    if name == "hardened-baseline":
        for index in range(20, 28):
            rows[index].update({"ParseStatus": "ParseError", "EKU_OIDs": "", "HasAnyPurposeOrNoEKU": "False"})
    return rows


def acl_rows(name: str, count: int) -> list[dict[str, str]]:
    object_types = [
        "NTAuthCertificates", "CertificationAuthoritiesContainer", "EnrollmentServiceCA",
        "EnrollmentServicesContainer", "CertificateTemplatesContainer", "KRAContainer",
    ]
    rows = []
    for index in range(count):
        rows.append({
            "PkiObjectType": object_types[index % len(object_types)],
            "ObjectDistinguishedName": token(name, "DN", f"pki-{index % 18}"),
            "Principal": token(name, "HV_GROUP", index % 8),
            "Rights": "ReadProperty",
            "ObjectTypeGuid": token(name, "GUID", index % 10),
            "ResolvedRight": "ReadProperty",
            "RightCategory": "Read",
            "IsEnrollRight": "False",
            "AccessType": "Allow",
            "IsDangerous": "False",
            "IsDefaultPrincipal": "True",
            "IsCAHostAccount": "False",
            "ESC5Candidate": "False",
            "SidExtensionMatchesRequester": "",
            "SidMismatchLikelyBenign": "",
        })
    if name in {"all-esc-enterprise", "mixed-enterprise"}:
        risk_count = 4 if name == "all-esc-enterprise" else 2
        for index in range(risk_count):
            rows[index].update({
                "Principal": token(name, "PRINCIPAL", "pki-control"),
                "Rights": ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"][index],
                "ResolvedRight": ["GenericAll", "WriteDacl", "WriteOwner", "GenericWrite"][index],
                "RightCategory": "Control",
                "IsDangerous": "True",
                "IsDefaultPrincipal": "False",
                "ESC5Candidate": "True",
            })
    rows[5].update({
        "Principal": token(name, "PRINCIPAL", "enroll-only"),
        "Rights": "ExtendedRight",
        "ResolvedRight": "Enroll",
        "RightCategory": "Enroll",
        "IsEnrollRight": "True",
        "IsDefaultPrincipal": "False",
        "ESC5Candidate": "True",
    })
    rows[6].update({
        "Principal": token(name, "COMPUTER", "ca-host"),
        "Rights": "GenericAll",
        "ResolvedRight": "GenericAll",
        "RightCategory": "Control",
        "IsDangerous": "True",
        "IsDefaultPrincipal": "False",
        "IsCAHostAccount": "True",
        "ESC5Candidate": "True",
    })
    rows[7].update({
        "Principal": token(name, "PRINCIPAL", "denied-control"),
        "Rights": "WriteDacl",
        "ResolvedRight": "WriteDacl",
        "RightCategory": "Control",
        "AccessType": "Deny",
        "IsDangerous": "False",
        "IsDefaultPrincipal": "False",
        "ESC5Candidate": "True",
    })
    return rows


def ca_rows(name: str) -> list[dict[str, str]]:
    risky = name == "all-esc-enterprise"
    esc11 = name in {"all-esc-enterprise", "mixed-enterprise"}
    return [{
        "CA_Config": token(name, "CA_CONFIG", 0),
        "CA_CommonName": token(name, "CA", 0),
        "ManageCAPrincipals": json.dumps([token(name, "PRINCIPAL", "ca-manager") if risky else token(name, "HV_GROUP", "pki-admin")]),
        "ManageCertificatesPrincipals": json.dumps([token(name, "PRINCIPAL", "certificate-officer") if risky else token(name, "HV_GROUP", "certificate-officer")]),
        "SecuritySource": "Live",
        "EditFlagsHex": "0x00040000" if risky else "0x00000000",
        "EditF_AttributeSubjectAltName2": str(risky),
        "ESC6_CAConfigFlag": str(risky),
        "InterfaceFlagsHex": "0x00000000" if esc11 else "0x00000200",
        "IF_EnforceEncryptICertRequest": str(not esc11),
        "ESC11Candidate": str(esc11),
        "ESC7Candidate": str(risky),
        "SidExtensionMatchesRequester": "",
        "SidMismatchLikelyBenign": "",
    }]


def dc_rows(name: str, count: int) -> list[dict[str, str]]:
    rows = []
    for index in range(count):
        full = name == "hardened-baseline" or (name == "all-esc-enterprise" and index < count // 2) or (name == "mixed-enterprise" and index < 6)
        row = {
            "DC_DnsHostName": token(name, "COMPUTER", f"dc-{index}"),
            "StrongCertificateBindingEnforcement": "2" if full else "1",
            "EnforcementLevel": "Full" if full else "Compatibility",
            "FullEnforcement": str(full),
            "ReadStatus": "OK" if index % 2 == 0 else "Live",
            "ReadMethod": "RemoteRegistry" if index % 2 == 0 else "WinRM",
            "ReadDetail": "READ_OK",
            "SidExtensionMatchesRequester": "",
            "SidMismatchLikelyBenign": "",
        }
        rows.append(row)
    if name == "mixed-enterprise":
        rows[-1].update({
            "StrongCertificateBindingEnforcement": "",
            "EnforcementLevel": "",
            "FullEnforcement": "",
            "ReadStatus": "Unreadable",
            "ReadMethod": "RemoteRegistry",
            "ReadDetail": "ACCESS_DENIED",
        })
    return rows


def web_rows(name: str) -> list[dict[str, str]]:
    ca = token(name, "CA", 0)

    def row(index: int, scheme: str, http: bool, ntlm: str, epa: str, confirmed: bool, needs: bool, mitigated: bool, risk: bool, reachable: bool = True) -> dict[str, str]:
        return {
            "CA_CommonName": ca,
            "EndpointKind": "certsrv" if index % 2 == 0 else "CES",
            "EndpointHostName": token(name, "COMPUTER", f"web-{index}"),
            "Scheme": scheme,
            "IsHttp": str(http),
            "AuthFromMetadata": "Windows",
            "Probed": str(reachable),
            "Reachable": str(reachable),
            "HttpStatus": "401" if reachable else "",
            "AuthSchemesOffered": json.dumps(["Negotiate", "NTLM"]) if ntlm == "True" else json.dumps(["Negotiate"]),
            "NtlmOffered": ntlm,
            "EpaTokenChecking": epa,
            "EpaSource": "IIS live read" if epa == "Require" else "Probe",
            "EpaDetail": "READ_OK" if reachable else "NOT_PROBED",
            "Esc8RiskFromMetadata": str(risk),
            "ESC8Confirmed": str(confirmed),
            "ESC8NeedsEpaCheck": str(needs),
            "ESC8Mitigated": str(mitigated),
            "SidExtensionMatchesRequester": "",
            "SidMismatchLikelyBenign": "",
        }

    if name == "hardened-baseline":
        return [
            row(0, "https", False, "False", "Require", False, False, True, False),
            row(1, "https", False, "False", "Require", False, False, True, False),
            row(2, "https", False, "False", "Require", False, False, True, False),
        ]
    if name == "all-esc-enterprise":
        return [
            row(0, "http", True, "True", "None", True, False, False, True),
            row(1, "https", False, "True", "Require", False, False, True, False),
            row(2, "https", False, "True", "Unknown", False, True, False, False),
            row(3, "https", False, "", "Unknown", False, True, False, False, False),
        ]
    return [
        row(0, "http", True, "True", "None", False, False, False, True),
        row(1, "https", False, "True", "Unknown", False, True, False, False),
        row(2, "https", False, "False", "Require", False, False, True, False),
        row(3, "https", False, "", "Unknown", False, True, False, False, False),
    ]


def high_value_rows(name: str, count: int) -> tuple[list[dict[str, str]], list[str]]:
    values = [token(name, "HV_PRINCIPAL", index) for index in range(count)]
    rows = [{
        "Token": value,
        "ObjectType": "user" if index % 3 else "group",
        "TokenType": "HV_PRINCIPAL" if index % 3 else "HV_GROUP",
        "HighValueReason": ["Tier 0 membership", "PKI administration", "Delegated control plane"][index % 3],
        "KnownLabel": "",
    } for index, value in enumerate(values)]
    return rows, values


def generate_scenario(name: str, config: dict) -> dict:
    root = DESTINATION / name / "Scrubbed"
    root.mkdir(parents=True, exist_ok=True)
    templates = template_rows(name, config["templates"])
    hv_rows, hv_values = high_value_rows(name, config["hv"])
    datasets = {
        "adcs_template_inventory_scrubbed.csv": (TEMPLATE_COLUMNS, templates),
        "exported_certs_normalized_scrubbed.csv": (CERT_COLUMNS, certificate_rows(name, config["certs"], templates, hv_values)),
        "adcs_pki_object_acls_scrubbed.csv": (ACL_COLUMNS, acl_rows(name, config["acls"])),
        "adcs_ca_security_scrubbed.csv": (CA_COLUMNS, ca_rows(name)),
        "adcs_dc_enforcement_scrubbed.csv": (DC_COLUMNS, dc_rows(name, config["dcs"])),
        "adcs_web_enrollment_scrubbed.csv": (WEB_COLUMNS, web_rows(name)),
        "high_value_targets_scrubbed.csv": (HV_COLUMNS, hv_rows),
    }
    manifest_files = []
    for filename, (columns, rows) in datasets.items():
        path = root / filename
        write_csv(path, columns, rows)
        manifest_files.append({
            "file": filename,
            "role": filename.replace("_scrubbed.csv", ""),
            "rows": len(rows),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    manifest = {
        "schemaVersion": "adcs-upload-manifest/v1",
        "scenarioSchemaVersion": "certifeye-synthetic-scenario/v1",
        "tool": "CertifEye",
        "synthetic": True,
        "scenario": name,
        "description": config["description"],
        "assessmentDate": END.date().isoformat(),
        "evidenceWindow": {"first": START.date().isoformat(), "last": END.date().isoformat(), "days": SPAN_DAYS},
        "tokenContractVersion": "synthetic-opaque/v1",
        "hmacLength": 24,
        "reviewRequired": True,
        "files": manifest_files,
        "warnings": ["SYNTHETIC_DATA_ONLY", "NO_TOKEN_MAP_EXISTS"],
    }
    (root / "adcs_upload_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {
        "description": config["description"],
        "expectedEscTypes": config["expected"],
        "expectedAbsentEscTypes": config["absent"],
        "expectedCoverage": config["coverage"],
        "minimumRows": {item["role"]: item["rows"] for item in manifest_files},
        "assessmentDate": END.date().isoformat(),
        "minimumEvidenceDays": 730,
    }


def main() -> None:
    DESTINATION.mkdir(parents=True, exist_ok=True)
    expectations = {
        "schemaVersion": "certifeye-synthetic-expectations/v1",
        "generatedBy": Path(__file__).name,
        "scenarios": {name: generate_scenario(name, config) for name, config in SCENARIOS.items()},
    }
    (DESTINATION / "scenario_expectations.json").write_text(
        json.dumps(expectations, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Generated {len(SCENARIOS)} CertifEye scenarios under {DESTINATION}")


if __name__ == "__main__":
    main()
