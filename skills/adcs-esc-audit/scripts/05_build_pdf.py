#!/usr/bin/env python3
"""Generic three-part AD CS ESC Audit PDF report.

All narrative, counts, findings, and coverage statements are derived from working/results.json.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, Flowable, NextPageTemplate, CondPageBreak
from reportlab.pdfgen import canvas

WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")
OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
LOCAL_ONLY = os.environ.get("ADCS_AUDIT_LOCAL_ONLY", "").strip() == "1"
R = json.load(open(os.path.join(WK, "results.json"), encoding="utf-8"))
os.makedirs(OUT, exist_ok=True)
m = R.get("meta", {})
findings = R.get("findings", [])

NAVY = colors.HexColor("#15365c")
TEAL = colors.HexColor("#2a9d8f")
INK = colors.HexColor("#2b3441")
CARD = colors.HexColor("#eef3f8")
ZEBRA = colors.HexColor("#f5f8fc")
GRID = colors.HexColor("#c8d4e0")
AMBER = colors.HexColor("#d99a00")
AMBERBG = colors.HexColor("#fbf3dd")
GREEN = colors.HexColor("#3f8f5b")
GREENBG = colors.HexColor("#eaf7ef")
SEV = {
    "Critical": colors.HexColor("#b00020"),
    "High": colors.HexColor("#d9534f"),
    "Medium": colors.HexColor("#d99a00"),
    "Low": colors.HexColor("#3f8f5b"),
    "Clean": colors.HexColor("#3f8f5b"),
    "Mitigated": colors.HexColor("#2a9d8f"),
    "Not evaluated": colors.HexColor("#6b7482"),
}
SEV_HEX = {
    "Critical": "#b00020",
    "High": "#d9534f",
    "Medium": "#d99a00",
    "Low": "#3f8f5b",
}
ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

ss = getSampleStyleSheet()
body = ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica", fontSize=9.4, leading=13.2, textColor=INK, spaceAfter=6)
small = ParagraphStyle("small", parent=body, fontSize=8.1, leading=10.5)
small_green = ParagraphStyle("small_green", parent=small, textColor=GREEN)
cell = ParagraphStyle("cell", parent=body, fontSize=7.8, leading=9.8, spaceAfter=0)
cell_wrap = ParagraphStyle("cell_wrap", parent=cell, wordWrap="CJK")
cell_white = ParagraphStyle("cell_white", parent=cell, textColor=colors.white)
h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, spaceBefore=10, spaceAfter=3)
h3 = ParagraphStyle("h3", parent=body, fontName="Helvetica-Bold", fontSize=10.5, textColor=NAVY, spaceBefore=7, spaceAfter=2)
rem_title = ParagraphStyle("rem_title", parent=body, fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=NAVY, spaceAfter=0)
rem_badge = ParagraphStyle("rem_badge", parent=body, fontName="Helvetica-Bold", fontSize=9.5, leading=11, textColor=colors.white, alignment=1, spaceAfter=0)
rem_step = ParagraphStyle("rem_step", parent=body, fontSize=9, leading=12, leftIndent=16, firstLineIndent=-12, spaceAfter=2)

PAGE_W, PAGE_H = LETTER
LM = RM = 0.7 * inch
TMARGIN = 0.7 * inch
BM = 0.7 * inch
CW = PAGE_W - LM - RM


def safe(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Banner(Flowable):
    def __init__(self, eyebrow, title, w):
        super().__init__()
        self.e = eyebrow
        self.t = title
        self.w = w
        self.h = 46

    def draw(self):
        c = self.canv
        c.setFillColor(NAVY)
        c.roundRect(0, 0, self.w, self.h, 3, fill=1, stroke=0)
        c.setFillColor(TEAL)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(14, self.h - 17, self.e.upper())
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 15)
        c.drawString(14, 8, self.t)
        c.setStrokeColor(TEAL)
        c.setLineWidth(2.5)
        c.line(14, 4, self.w - 14, 4)


class Rule(Flowable):
    def __init__(self, w, color=TEAL, lw=2.2, length=70):
        super().__init__()
        self.w = w
        self.c = color
        self.lw = lw
        self.L = length
        self.h = 4

    def draw(self):
        self.canv.setStrokeColor(self.c)
        self.canv.setLineWidth(self.lw)
        self.canv.line(0, 1, self.L, 1)


def footer(canv, doc):
    canv.saveState()
    canv.setStrokeColor(TEAL)
    canv.setLineWidth(1.1)
    canv.line(LM, BM - 10, PAGE_W - RM, BM - 10)
    canv.setFillColor(colors.HexColor("#6b7785"))
    canv.setFont("Helvetica", 7.6)
    canv.drawString(LM, BM - 22, "CertifEye AD CS Audit - Confidential")
    canv.drawRightString(PAGE_W - RM, BM - 22, f"Page {canv.getPageNumber()}")
    canv.restoreState()


def cover_banner(canv, doc):
    canv.saveState()
    y = PAGE_H - 1.4 * inch
    canv.setFillColor(NAVY)
    canv.rect(0, y, PAGE_W, 1.55 * inch, fill=1, stroke=0)
    canv.setFillColor(TEAL)
    canv.setFont("Helvetica-Bold", 11)
    canv.drawString(LM, y + 1.15 * inch, "SECURITY ASSESSMENT")
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 26)
    canv.drawString(LM, y + 0.6 * inch, "CertifEye AD CS ESC Audit Report")
    canv.setFont("Helvetica", 13)
    canv.drawString(LM, y + 0.32 * inch, "CertifEye - Active Directory Certificate Services defensive review")
    canv.setStrokeColor(TEAL)
    canv.setLineWidth(3)
    canv.line(LM, y + 0.16 * inch, PAGE_W - RM, y + 0.16 * inch)
    footer(canv, doc)
    canv.restoreState()


def sect(title):
    return [Spacer(1, 3), Paragraph(title, h2), Rule(CW), Spacer(1, 4)]


def pillcell(text, w=62):
    c = SEV.get(text, colors.grey)
    t = Table([[Paragraph(safe(text), cell_white)]], colWidths=[w])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def para_list(items, style=body):
    out = []
    for item in items:
        out.append(Paragraph("• " + safe(item), style))
    return out


REMEDIATION = {
    "ESC1": {
        "title": "Templates let requesters name the certificate identity",
        "what": "A published authentication-capable template allows the requester to supply the subject or SAN.",
        "risk": "A requester can ask for a certificate naming a different account when enrollment scope and approval controls permit it.",
        "steps": [
            "Open Certificate Templates (certtmpl.msc) and identify every flagged published template.",
            "On Subject Name, select Build from this Active Directory information unless requester-supplied identity is required.",
            "If requester input is required, enable CA manager approval or require authorized signatures.",
            "On Security, restrict Enroll and Autoenroll to the smallest approved group; remove broad/default enrollment.",
            "Revoke and reissue affected certificates when validation confirms inappropriate issuance.",
        ],
        "verify": "Re-export templates and issuance. Confirm requester-supplied subject/SAN is disabled or approval/signature controls are present, and review remaining mismatches.",
    },
    "ESC2": {
        "title": "Any Purpose or no-EKU certificates permit overly broad use",
        "what": "A certificate with Any Purpose or no EKU may be accepted for more purposes than intended.",
        "risk": "A broadly usable certificate increases the impact of weak enrollment or identity controls.",
        "steps": [
            "Identify the issuing template for each flagged certificate and confirm the business purpose.",
            "Replace Any Purpose or empty EKU configuration with only the required application-policy OIDs.",
            "Restrict enrollment and add approval where broad certificate use cannot be removed immediately.",
            "Revoke and reissue certificates that exceed the documented purpose.",
        ],
        "verify": "Re-export template EKUs and issuance; confirm only documented application policies remain.",
    },
    "ESC3": {
        "title": "Enrollment-agent and on-behalf-of issuance needs tight restriction",
        "what": "Enrollment Agent capability permits approved identities to request certificates on behalf of others.",
        "risk": "An over-broad agent population or missing agent restrictions can allow unauthorized delegated issuance.",
        "steps": [
            "Inventory every Enrollment Agent certificate and validate its owner, purpose, validity, and revocation state.",
            "Configure CA Enrollment Agent restrictions to limit which agents may use which templates for which subjects.",
            "Restrict Enrollment Agent template enrollment and require authorized signatures where appropriate.",
            "Remove stale agents and revoke certificates that no longer have an approved owner or purpose.",
        ],
        "verify": "Re-export agent and on-behalf-of issuance; confirm every agent is approved and CA restrictions cover its permitted templates and subjects.",
    },
    "ESC4": {
        "title": "Non-PKI principals can modify certificate templates",
        "what": "Template-control rights can allow a principal to reshape a template into a higher-risk configuration.",
        "risk": "Control over publication, subject-name behavior, EKUs, approval, or security can create an unsafe enrollment path.",
        "steps": [
            "Open each flagged template in certtmpl.msc and review its Security descriptor.",
            "Remove GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty, and Full Control from non-PKI administrators.",
            "Use a dedicated, documented PKI administration group for template changes.",
            "Review inherited permissions and the parent Certificate Templates container for the source of access.",
            "Compare the final template settings with the approved baseline before republishing.",
        ],
        "verify": "Re-export template ACLs; confirm only approved PKI administrators retain modification rights.",
    },
    "ESC5": {
        "title": "Loose permissions on core PKI directory objects",
        "what": "Core Public Key Services objects determine trusted CAs, enrollment services, and available certificate templates.",
        "risk": "Write or ownership control can alter enterprise trust or PKI publication. Enroll-only rights and a CA host controlling its own CA object are not treated as control.",
        "steps": [
            "Open ADSI Edit and navigate to Configuration -> CN=Public Key Services,CN=Services.",
            "For each flagged object, open Properties -> Security and confirm the principal's approved role.",
            "Remove GenericAll, GenericWrite, WriteDacl, WriteOwner, or equivalent control from non-PKI administrators and broad principals.",
            "Retain the CA computer account on its own CA object only when required and documented.",
            "Review parent-container inheritance so removed access is not reapplied.",
        ],
        "verify": "Re-export PKI object ACLs; confirm dangerous control ACEs for non-administrative principals are gone.",
    },
    "ESC6": {
        "title": "CA-wide SAN request attributes can override template intent",
        "what": "EDITF_ATTRIBUTESUBJECTALTNAME2 permits SAN values from request attributes across the issuing CA.",
        "risk": "A template that appears to build identity from AD may still accept requester-controlled SAN data through the CA-wide flag.",
        "steps": [
            "Confirm the live EditFlags value on every issuing CA and document any application dependency.",
            "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 when it is not explicitly required.",
            "Where removal is delayed, restrict enrollment, require approval, and monitor SAN request-attribute issuance.",
            "Restart Certificate Services during an approved maintenance window after changing the flag.",
        ],
        "verify": "Re-read the live CA flag and issue an approved validation request that confirms unauthorized SAN request attributes are rejected.",
    },
    "ESC7": {
        "title": "CA administrative rights require least privilege",
        "what": "Manage CA and Manage Certificates are powerful CA officer and administration rights.",
        "risk": "Unnecessary CA administration can change configuration, approve requests, or manage issued certificates.",
        "steps": [
            "Review Manage CA and Manage Certificates assignments on every issuing CA.",
            "Remove stale, broad, or non-PKI principals and separate administration from certificate-manager duties.",
            "Use dedicated groups with documented membership and privileged-access controls.",
            "Review CA officer procedures, approval requirements, and audit logging.",
        ],
        "verify": "Re-export CA security and confirm only approved role groups retain each administrative right.",
    },
    "ESC8": {
        "title": "Web enrollment authentication and EPA need hardening",
        "what": "AD CS web endpoints may expose Windows authentication over HTTP or HTTPS without confirmed Extended Protection.",
        "risk": "An exposed NTLM-capable endpoint can satisfy a relay prerequisite when transport and EPA protections are absent.",
        "steps": [
            "Inventory every certsrv, CES, and CEP endpoint and confirm whether it is still required.",
            "Disable HTTP bindings; require HTTPS with a valid certificate and redirect or remove legacy listeners.",
            "Disable NTLM where feasible and require Extended Protection for Authentication on Windows-authenticated endpoints.",
            "Restrict network reachability to approved enrollment clients and monitor endpoint authentication.",
            "Retire unused web enrollment roles instead of leaving them partially configured.",
        ],
        "verify": "Recollect endpoint evidence and confirm HTTP is absent, NTLM exposure is reduced, and EPA is Required or otherwise explicitly validated.",
    },
    "ESC9/10": {
        "title": "Certificate-to-account mapping needs full enforcement",
        "what": "Certificates missing or mismatching the SID security extension require strong domain-controller mapping enforcement.",
        "risk": "Weak mapping modes may accept a certificate for an unintended account; unreadable or intended-only policy does not prove protection.",
        "steps": [
            "Confirm StrongCertificateBindingEnforcement live on every writable and read-only domain controller.",
            "Move all DCs to Full enforcement after completing Microsoft's compatibility review.",
            "Identify and reissue certificates that lack the SID security extension where the template should include it.",
            "Investigate actionable identity mismatches and document benign mapping cases separately.",
            "Monitor certificate-authentication events during and after enforcement rollout.",
        ],
        "verify": "Recollect live DC values and confirm every readable DC reports Full enforcement; validate remaining certificate mappings through approved authentication testing.",
    },
    "ESC11": {
        "title": "Certificate requests must require encrypted RPC",
        "what": "The CA RPC interface may accept certificate requests without packet privacy when IF_ENFORCEENCRYPTICERTREQUEST is not set.",
        "risk": "Unprotected request traffic can satisfy a relay prerequisite depending on other environmental controls.",
        "steps": [
            "Confirm InterfaceFlags live on every issuing CA and identify legacy clients that may be affected.",
            "Enable IF_ENFORCEENCRYPTICERTREQUEST during an approved maintenance window.",
            "Restart Certificate Services and validate approved enrollment clients.",
            "Pair the change with NTLM reduction, SMB/LDAP hardening, and monitoring of failed enrollment requests.",
        ],
        "verify": "Re-read InterfaceFlags and confirm the CA rejects enrollment requests that do not provide the required RPC protection.",
    },
}


def overall_posture():
    if R.get("sev_counts", {}).get("Critical"):
        return "CRITICAL — one or more critical AD CS paths require validation/remediation"
    if R.get("sev_counts", {}).get("High"):
        return "ELEVATED — high-risk AD CS findings require validation/remediation"
    if R.get("sev_counts", {}).get("Medium"):
        return "MODERATE — suspicious or incomplete evidence requires validation"
    if findings:
        return "LOW — only low-severity or informational findings were generated"
    return "NO FINDINGS GENERATED — review missing inputs and coverage before treating as clean"


def summary_verdict():
    if not findings:
        return "The supplied scrubbed data did not generate open findings. This does not prove the environment is clean unless the coverage matrix shows the relevant ESC areas were evaluated. Collect any missing exports listed as Not evaluated."
    top = sorted(findings, key=lambda f: (-ORDER.get(f.get("Severity"), 0), f.get("FindingID", "")))[:3]
    bits = [f"{f.get('FindingID')} ({f.get('Severity')}; {f.get('Category')})" for f in top]
    return "The highest-priority issues in this dataset are: " + "; ".join(bits) + ". Treat issuance evidence as proof of issuance only until authentication-use logs confirm use."


story = []

# Cover
story.append(Spacer(1, 1.7 * inch))
meta = [
    ["Prepared for", m.get("generated_for", "Current audit dataset")],
    ["Date", m.get("generated_on", "")],
    ["Scope", ("LOCAL-ONLY, non-tokenized AD CS exports — DO NOT UPLOAD" if LOCAL_ONLY else "Scrubbed AD CS exports — issuance + posture; no authentication-use logs assumed")],
    ["Data analyzed", f"{m.get('cert_rows', 0):,} certificate rows · {m.get('templates', 0)} templates · {m.get('pki_aces', 0)} PKI ACEs · {m.get('cas', 0)} CA row(s) · {m.get('dcs', 0)} DC row(s) · {m.get('web_endpoints', 0)} web endpoint row(s) · {m.get('hv_tokens', 0)} high-value token(s)"],
    ["Overall posture", overall_posture()],
]
mt = Table([[Paragraph(f"<b>{safe(k)}</b>", small), Paragraph(safe(v), small)] for k, v in meta], colWidths=[1.35 * inch, CW - 1.35 * inch])
mt.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), CARD),
    ("BOX", (0, 0), (-1, -1), 0.6, GRID),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.white),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 9),
    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ("TOPPADDING", (0, 0), (-1, -1), 7),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
]))
story.append(mt)
story.append(Spacer(1, 14))
cav = Table([[Paragraph("<b>Read first.</b> Issued-certificate evidence proves a certificate was <i>issued</i> — not that it was used to authenticate. Confirmation requires DC/Kerberos certificate-authentication logs. Posture findings describe conditions that can enable abuse, not proof that abuse occurred. Every remediation item is advisory and should be validated by a PKI administrator.", small)]], colWidths=[CW])
cav.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), AMBERBG),
    ("LINEBEFORE", (0, 0), (0, -1), 4, AMBER),
    ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ("TOPPADDING", (0, 0), (-1, -1), 9),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
]))
story.append(cav)
story.append(NextPageTemplate("main"))
story.append(PageBreak())

# Part 1
story.append(Banner("Part 1", "Executive Summary", CW))
story.append(Spacer(1, 10))
story.append(Paragraph("Overall verdict", h3))
story.append(Paragraph(safe(summary_verdict()), body))

story.append(Paragraph("Findings by severity and category", h3))
sevc = R.get("sev_counts", {})
catc = R.get("cat_counts", {})
srow = [Paragraph("<b>Severity</b>", cell)] + [pillcell(k) for k in ["Critical", "High", "Medium", "Low"]]
crow = [Paragraph("<b>Count</b>", cell)] + [Paragraph(str(sevc.get(k, 0)), cell) for k in ["Critical", "High", "Medium", "Low"]]
st = Table([srow, crow], colWidths=[1.0 * inch] + [(CW - 1.0 * inch) / 4] * 4)
st.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (0, -1), CARD),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ("BOX", (0, 0), (-1, -1), 0.5, GRID),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
]))
story.append(st)
story.append(Spacer(1, 8))
cat_rows = [[Paragraph("<b>Category</b>", cell_white), Paragraph("<b>Count</b>", cell_white)]] + [[Paragraph(safe(k), cell), Paragraph(str(v), cell)] for k, v in catc.items()]
if len(cat_rows) == 1:
    cat_rows.append([Paragraph("No findings", cell), Paragraph("0", cell)])
cat_t = Table(cat_rows, colWidths=[CW - 0.9 * inch, 0.9 * inch])
cat_t.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
    ("BOX", (0, 0), (-1, -1), 0.5, GRID),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
    ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]))
story.append(cat_t)

story.append(Paragraph("Top risks", h3))
top_findings = sorted(findings, key=lambda f: (-ORDER.get(f.get("Severity"), 0), f.get("FindingID", "")))[:5]
if top_findings:
    for finding in top_findings:
        severity = finding.get("Severity", "")
        story.append(Paragraph(
            f"- <b>{safe(finding.get('FindingID'))}</b> · "
            f"<font color='{SEV_HEX.get(severity, '#6b7482')}'><b>{safe(severity)}</b></font><br/>"
            f"{safe(finding.get('Evidence'))}",
            small,
        ))
else:
    story += para_list(["No findings were generated. Review Not evaluated rows in the coverage matrix before interpreting this as a clean result."], small)

story.append(Paragraph("Prioritized recommendations", h3))
recs = []
top_by_esc = defaultdict(list)
for finding in top_findings:
    top_by_esc[finding.get("ESCType", "Other")].append(finding)
for esc_type, grouped in top_by_esc.items():
    representative = grouped[0]
    refs = ", ".join(f.get("FindingID", "") for f in grouped)
    validation = next((f.get("RecommendedValidation") for f in grouped if f.get("RecommendedValidation")), None)
    if validation:
        recs.append(("Validate", f"{esc_type} findings ({len(grouped)}; {refs})", representative, validation))
    remediation = next((f.get("RecommendedRemediation") for f in grouped if f.get("Severity") in {"Critical", "High"} and f.get("RecommendedRemediation")), None)
    if remediation:
        recs.append(("Remediate", f"{esc_type} findings ({len(grouped)}; {refs})", representative, remediation))
if not recs:
    story.append(Paragraph("- <b>Collect missing evidence.</b> Collect any missing input files for areas marked Not evaluated, then rerun the audit.", body))
else:
    for action, label, finding, guidance in recs[:5]:
        action_color = "#2a9d8f" if action == "Validate" else SEV_HEX.get(finding.get("Severity"), "#b00020")
        story.append(Paragraph(
            f"- <font color='{action_color}'><b>{action} {safe(label)}.</b></font> {safe(guidance)}",
            body,
        ))
story.append(PageBreak())

# Part 2 remediation
story.append(Banner("Part 2", "Remediation Guide", CW))
story.append(Spacer(1, 8))
story.append(Paragraph("Every step below is advisory. Validate ownership and business need before making PKI changes.", small))
by_esc = defaultdict(list)
for f in findings:
    by_esc[f.get("ESCType", "Other")].append(f)
if not by_esc:
    story.append(Paragraph("No remediation blocks were generated because there were no open findings. Use the coverage matrix to decide whether more data should be collected.", body))
for esc_type, fs in sorted(by_esc.items(), key=lambda kv: -max(ORDER.get(f.get("Severity"), 0) for f in kv[1])):
    max_sev = max((f.get("Severity", "Low") for f in fs), key=lambda s: ORDER.get(s, 0))
    guidance = REMEDIATION.get(esc_type, {
        "title": "AD CS posture finding requires validation",
        "what": fs[0].get("WhyThisMatters", "This finding identifies an AD CS configuration or issuance pattern that can increase certificate abuse risk."),
        "risk": fs[0].get("WhyThisMatters", "The current evidence should be validated by the PKI owner."),
        "steps": [
            fs[0].get("RecommendedValidation", "Validate the evidence with the PKI owner."),
            fs[0].get("RecommendedRemediation", "Apply least privilege and remove unneeded risky settings."),
        ],
        "verify": "Re-export the relevant scrubbed data and confirm the finding no longer appears or is documented as intended.",
    })
    story.append(CondPageBreak(3.1 * inch))
    header = Table(
        [[Paragraph(safe(esc_type), rem_badge), Paragraph(
            f"<b>{safe(guidance['title'])}</b><br/><font color='#6b7785' size='8'>Severity: {safe(max_sev)} · {len(fs)} finding(s)</font>",
            rem_title,
        )]],
        colWidths=[0.78 * inch, CW - 0.78 * inch],
        rowHeights=[0.48 * inch],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), SEV.get(max_sev, AMBER)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (0, 0), 5),
        ("RIGHTPADDING", (0, 0), (0, 0), 5),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
        ("RIGHTPADDING", (1, 0), (1, 0), 5),
    ]))
    story.append(header)
    story.append(Spacer(1, 5))
    story.append(Paragraph(f"<font color='#2a9d8f'><b>What it is.</b></font> {safe(guidance['what'])}", body))
    story.append(Paragraph(f"<font color='#2a9d8f'><b>How it can be abused.</b></font> {safe(guidance['risk'])}", body))
    story.append(Paragraph("<font color='#2a9d8f'><b>How to fix it.</b></font>", body))
    for step_number, step in enumerate(guidance["steps"], 1):
        story.append(Paragraph(f"{step_number}. {safe(step)}", rem_step))
    story.append(Paragraph(f"<font color='#2a9d8f'><b>How to verify.</b></font> {safe(guidance['verify'])}", body))
    story.append(Spacer(1, 8))
story.append(PageBreak())

# Part 3 technical
story.append(Banner("Part 3", "Technical Analysis", CW))
story += sect("Methodology")
story.append(Paragraph("The analysis uses explicit field checks over the supplied scrubbed CSVs. Files are matched by schema and filename hints, not by one fixed client export name. Missing files lower coverage rather than causing clean claims. Counts, categories, and findings are computed programmatically from the current data only.", body))

story += sect("Data quality & coverage")
dq = R.get("dq", {})
sg = R.get("signals", {})
files_supplied = dq.get("files_supplied", {})
dqrows = [
    ["Certificate rows", f"{m.get('cert_rows', 0):,}; ParseStatus OK: {dq.get('parsestatus', {}).get('OK', 0):,}; Issued: {dq.get('disposition', {}).get('Issued', 0):,}; Revoked: {dq.get('disposition', {}).get('Revoked', 0):,}"],
    ["Identity mapping", "present" if dq.get("idcols_present") else "absent or partial"],
    ["IdentityMappingStatus", ", ".join(f"{k} {v}" for k, v in dq.get("ims", {}).items()) or "not present"],
    ["Template join", ", ".join(f"{k} {v}" for k, v in dq.get("join", {}).items()) or "not evaluated"],
    ["Issuance signals", f"ESC6 SAN-attr {sg.get('esc6_san_attr', 0)} · ESC3 agent {sg.get('esc3_eku', 0)} · ESC3 OBO {sg.get('esc3_obo', 0)} · ESC2 {sg.get('esc2', 0)} · SID missing {sg.get('sid_missing', 0)} · SID mismatch real {sg.get('sid_mismatch_real', 0)}"],
    ["Files supplied", ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in files_supplied.items())],
    ["DC strong mapping", f"Full enforcement {R.get('esc910', {}).get('full', 0)}/{R.get('esc910', {}).get('dcs', 0)}; live reads {R.get('esc910', {}).get('live_reads', 0)}; methods {', '.join(R.get('esc910', {}).get('read_methods', {}).keys()) or 'not supplied'}"],
]
dqt = Table([[Paragraph(f"<b>{safe(k)}</b>", cell), Paragraph(safe(v), cell)] for k, v in dqrows], colWidths=[1.65 * inch, CW - 1.65 * inch])
dqt.setStyle(TableStyle([
    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, ZEBRA]),
    ("BOX", (0, 0), (-1, -1), 0.5, GRID),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]))
story.append(dqt)

story += sect("ESC coverage matrix")
cov_rows = [[Paragraph("<b>ESC</b>", cell_white), Paragraph("<b>Status</b>", cell_white), Paragraph("<b>Evidence</b>", cell_white)]]
for esc_type, status, note in R.get("coverage", []):
    cov_rows.append([Paragraph(safe(esc_type), cell), pillcell(status, 0.76 * inch), Paragraph(safe(note), cell_wrap)])
cov = Table(cov_rows, colWidths=[0.65 * inch, 0.9 * inch, CW - 1.55 * inch], repeatRows=1)
cov.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
    ("BOX", (0, 0), (-1, -1), 0.5, GRID),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
]))
story.append(cov)

verified = [
    f"{esc_type} - {note}"
    for esc_type, status, note in R.get("coverage", [])
    if status in {"Clean", "Mitigated"}
]
if verified:
    story += sect("Controls verified clean / mitigated")
    verified_box = Table(
        [[Paragraph("• " + safe(item), small_green)] for item in verified],
        colWidths=[CW],
    )
    verified_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GREENBG),
        ("TEXTCOLOR", (0, 0), (-1, -1), GREEN),
        ("LINEBEFORE", (0, 0), (0, -1), 4, GREEN),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9bcdb0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(verified_box)


def findings_table(category):
    rows = [[Paragraph("<b>Finding</b>", cell_white), Paragraph("<b>Sev</b>", cell_white), Paragraph("<b>Conf</b>", cell_white), Paragraph("<b>Evidence</b>", cell_white)]]
    for f in findings:
        if f.get("Category") != category:
            continue
        rows.append([Paragraph(f"<b>{safe(f.get('FindingID'))}</b>", cell_wrap), pillcell(f.get("Severity"), 0.56 * inch), Paragraph(safe(f.get("Confidence")), cell), Paragraph(safe(f.get("Evidence")), cell_wrap)])
    if len(rows) == 1:
        return None
    t = Table(rows, colWidths=[0.95 * inch, 0.76 * inch, 0.66 * inch, CW - 2.37 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
        ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t

for category in ["Likely ESC1 misuse", "Suspicious issuance needing validation", "Template / PKI posture issue", "Informational / not currently exploitable"]:
    t = findings_table(category)
    if t:
        story.append(CondPageBreak(2.8 * inch))
        story += sect(f"Findings — {category}")
        story.append(t)

story += sect("Evidence trail — High & Critical findings")
hi = [f for f in findings if f.get("Severity") in {"Critical", "High"}]
if not hi:
    story.append(Paragraph("No High or Critical findings were generated.", small))
for f in hi:
    severity = f.get("Severity", "")
    story.append(Paragraph(
        f"<b>{safe(f.get('FindingID'))}</b> · "
        f"<font color='{SEV_HEX.get(severity, '#6b7482')}'><b>{safe(severity)}</b></font>",
        h3,
    ))
    story.append(Paragraph(f"<b>Evidence:</b> {safe(f.get('Evidence'))}", small))
    story.append(Paragraph(f"<b>Why it matters:</b> {safe(f.get('WhyThisMatters'))}", small))
    story.append(Paragraph(f"<b>Validation:</b> {safe(f.get('RecommendedValidation'))}", small))
    story.append(Paragraph(f"<b>Remediation:</b> {safe(f.get('RecommendedRemediation'))}", small))
    story.append(Spacer(1, 5))

story.append(CondPageBreak(7.3 * inch))
story += sect("Attack-path graph")
img = os.path.join(OUT, "ADCS_Attack_Path_Graph.png")
if os.path.exists(img) and os.path.getsize(img) > 0:
    source_width, source_height = ImageReader(img).getSize()
    iw = CW
    ih = iw * source_height / source_width
    max_height = 7.4 * inch
    if ih > max_height:
        scale = max_height / ih
        ih = max_height
        iw *= scale
    story.append(Image(img, width=iw, height=ih))
else:
    story.append(Paragraph("Graph PNG was not available; use ADCS_Attack_Path_Graph.svg or the HTML report.", small))

story += sect("Appendix — assumptions, token model, limitations")
story += para_list([
    ("This is a LOCAL-ONLY report built with tokenization disabled. Values may identify people, hosts, or PKI objects; do not upload, email, or provide it to an AI service."
     if LOCAL_ONLY else
     "All inputs are assumed scrubbed. Tokens such as PRINCIPAL_x, HV_PRINCIPAL_x, GROUP_x, COMPUTER_x, TEMPLATE_x, CA_x, and X500_x are anonymized; broad/default labels are intentionally preserved for risk scoring."),
    "No real identities were inferred or reverse-mapped.",
    "Issued-certificate evidence proves issuance, not authentication or use. Confirmation requires DC/Kerberos certificate-authentication logs.",
    "If an ESC area is marked Not evaluated, the corresponding input file was not supplied or did not contain recognizable columns.",
    "All remediation is advisory guidance for a PKI administrator to validate and apply in a maintenance window.",
], small)

frame = Frame(LM, BM, CW, PAGE_H - TMARGIN - BM, id="f")
doc = BaseDocTemplate(os.path.join(OUT, "ADCS_ESC_Audit_Report.pdf"), pagesize=LETTER, leftMargin=LM, rightMargin=RM, topMargin=TMARGIN, bottomMargin=BM, title="CertifEye AD CS ESC Audit Report")
doc.addPageTemplates([
    PageTemplate(id="cover", frames=[frame], onPage=cover_banner),
    PageTemplate(id="main", frames=[frame], onPage=footer),
])
story.insert(0, NextPageTemplate("cover"))
def invariant_canvas(filename, **kwargs):
    kwargs["invariant"] = 1
    return canvas.Canvas(filename, **kwargs)

doc.build(story, canvasmaker=invariant_canvas)
print("Wrote ADCS_ESC_Audit_Report.pdf")
