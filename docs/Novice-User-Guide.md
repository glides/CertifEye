# CertifEye novice user guide

This guide is for an operator who is comfortable opening PowerShell but is not
expected to be an AD CS or ESC specialist.

## What CertifEye does

CertifEye collects read-only Microsoft Active Directory Certificate Services
evidence, replaces sensitive identities with consistent tokens, and creates a
defensive ESC1–ESC11 posture report. It helps answer:

- Which certificate templates or CA settings need review?
- Did historical issuance show unusual requester/SAN, EKU, agent, or SID signals?
- Which PKI permissions, web enrollment settings, or DC mapping controls matter?
- Which areas were genuinely evaluated, and which remain unknown?
- What should an AD/PKI administrator validate or remediate first?

An issued certificate is evidence of issuance—not proof that authentication,
compromise, or abuse occurred.

## Before you start

For a synthetic demonstration you need:

- Windows PowerShell 5.1 or PowerShell 7.
- Python 3.9 or newer for report generation.
- ReportLab for PDF output and CairoSVG for optional PNG output. CertifEye still
  creates the other reports when an optional renderer is unavailable.
- A writable output folder such as `C:\Temp\CertifEye-Demo`.

For a live collection you additionally need:

- A Windows host that can reach the CA and Active Directory.
- Read access to the CA database and AD/LDAP.
- Appropriate remote-read access if live DC enforcement or IIS EPA evidence is
  expected.
- An approved private working folder. Treat the collection host as Tier 0.

Run the collector's `doctor` and `plan` commands before live collection. The
collector is PowerShell-first; Python is required only for offline analysis and
report rendering.

## Fastest safe demonstration

From the `Security Assessment Tools` folder:

```powershell
.\CertifEye\tools\Invoke-CertifEyeSyntheticDemo.ps1 `
  -Scenario All `
  -Destination C:\Temp\CertifEye-Demo
```

This analyzes three large fictional environments:

1. `all-esc-enterprise` contains evidence for every supported ESC category.
2. `hardened-baseline` contains readable, evaluated controls and no open findings.
3. `mixed-enterprise` contains a realistic mix of open, clean, mitigated,
   benign, revoked, and unreadable evidence.

The command refuses to reuse a non-empty destination. Add `-Replace` only when
you intentionally want to delete and rebuild that demo folder.

To run one scenario:

```powershell
.\CertifEye\tools\Invoke-CertifEyeSyntheticDemo.ps1 `
  -Scenario mixed-enterprise `
  -Destination C:\Temp\CertifEye-Demo
```

## Run analysis manually

The canonical PowerShell path is:

```powershell
.\CertifEye\Invoke-ADCSAuditPipeline.ps1 `
  -Action Analyze `
  -NonInteractive `
  -InputDir "C:\Path\To\Scrubbed" `
  -OutputDir "C:\Temp\CertifEye\Reports" `
  -WorkingDir "C:\Temp\CertifEye\Working"
```

The direct Python equivalent is:

```powershell
python .\CertifEye\skills\adcs-esc-audit\scripts\00_run_all.py `
  --input-dir "C:\Path\To\Scrubbed" `
  --output-dir "C:\Temp\CertifEye\Reports" `
  --working-dir "C:\Temp\CertifEye\Working"
```

Use `--skip-qa` when a montage is not needed. Always use separate input, report,
and working folders.

## Local-only reports without tokenization

Use this only when reports will stay inside the client environment and will
**not** be uploaded to an AI tool, vendor portal, email thread, or ticket. It
is an explicit command-line choice, not an interactive-console option:

```powershell
.\CertifEye\Invoke-ADCSAuditPipeline.ps1 `
  -WorkDir C:\Secure\CertifEye-Local `
  -Stage All `
  -NoTokenization

.\CertifEye\Invoke-ADCSAuditPipeline.ps1 `
  -WorkDir C:\Secure\CertifEye-Local `
  -Stage Analyze `
  -NoTokenization `
  -NonInteractive
```

This creates no salt, token map, `Scrubbed` package, upload manifest, or safe
ZIP. Raw collection files remain in `Raw_DO_NOT_UPLOAD`; reports and results
remain under `Private_DO_NOT_UPLOAD`. `validate` correctly reports that this
mode is not upload-safe. Choose normal tokenized collection whenever AI review
or external sharing is even a possibility.

## Run the interactive collector

Start the console:

```powershell
Set-Location .\CertifEye
.\Invoke-ADCSAuditPipeline.ps1
```

Use this sequence:

```text
doctor
set WorkDir C:\Secure\CertifEye-Run
set SaltFile C:\Secure\CertifEye-Run.salt
set Stage All
plan
collect
analyze
validate
last
```

`plan` performs no collection. `collect` remains interactive so the operator sees
the CA, year range, remote-read, and web-enrollment choices. Prefer a private
`SaltFile`; do not place literal salts in shell history.

## Understand the folders

```text
Raw_DO_NOT_UPLOAD/       original local exports; never share
Scrubbed/                reviewed tokenized CSV inputs
Private_DO_NOT_UPLOAD/   salt, token map, and private evidence; never share
Output/ or Reports/      generated reports; review before sharing
Working/                 results.json and QA intermediates; local working data
```

Only share reviewed scrubbed files and a validated safe manifest. Never share raw
exports, salts, token maps, private manifests, exception details, or an entire
working directory.

## Know the seven input roles

| Role | What it contributes |
|---|---|
| Issued certificates | Historical requester, SAN, EKU, disposition, revocation, SID, and identity-mapping evidence |
| Templates | Publication, subject/SAN behavior, EKUs, approvals, signatures, enrollment scope, and template control |
| CA security | ESC6, ESC7, and ESC11 configuration evidence |
| PKI object ACLs | ESC5 control rights, enroll-only negative controls, and CA-host self-control context |
| DC enforcement | Strong certificate-mapping context for ESC9/10 |
| Web enrollment | HTTP/HTTPS, NTLM, reachability, and EPA context for ESC8 |
| High-value targets | Tokenized priority context; never real identity labels |

Files are classified by their columns. Renaming a CSV does not change its
meaning. Missing roles produce `Not Evaluated`, not `Clean`.

## Read the reports

Start with:

1. `ADCS_ESC_Audit_Report.pdf` for the executive summary, plain-language actions,
   and technical evidence.
2. `ADCS_Attack_Path_Report.html` for interactive findings and graph context.
3. `ADCS_ESC_Findings.csv` for filtering, assignment, and remediation tracking.
4. `adcs_upload_manifest.json` for coverage and generated-artifact verification.

Supporting exports include SVG/optional PNG, graph JSON, and Cypher.

### Severity and confidence are different

- Severity estimates potential impact and urgency.
- Confidence describes evidence quality and joins.
- A Critical/Low-confidence item needs prompt validation, not a compromise claim.
- A Medium/High-confidence posture issue may be a straightforward hardening task.

### Coverage states

- `Clean`: required evidence was readable and a supported rule evaluated it with
  no open finding.
- `Mitigated`: a relevant signal exists, but supplied enforcement evidence shows
  the tested path is currently blocked.
- `Critical`, `High`, `Medium`, or `Low`: an open evidence-backed finding exists.
- `Not Evaluated`: required evidence was missing, unreadable, or incomplete.

### ESC quick reference

| Area | Plain-language question |
|---|---|
| ESC1 | Can an enrollee supply another identity on an authentication certificate? |
| ESC2 | Are Any Purpose or no-EKU certificates being issued? |
| ESC3 | Are enrollment-agent or on-behalf-of paths controlled and expected? |
| ESC4 | Can an unexpected principal modify a certificate template? |
| ESC5 | Can an unexpected principal control important PKI directory objects? |
| ESC6 | Does the CA honor SAN request attributes outside template intent? |
| ESC7 | Are Manage CA or Manage Certificates rights tightly assigned? |
| ESC8 | Could web enrollment accept relay-prone HTTP/NTLM without required EPA? |
| ESC9/10 | Do SID-extension signals combine with weak DC certificate mapping? |
| ESC11 | Does the CA require encryption for ICertRequest RPC traffic? |

## Hand the package to the CertifEye skill

Provide only one current-run scrubbed folder and its safe manifest. A suitable
request is:

```text
Use the CertifEye AD CS assessment skill on this current-run scrubbed package.
Run the deterministic offline pipeline first. Summarize scope, coverage, highest
priority findings, historical recurrence, validation steps, remediation owners,
and missing evidence. Do not reverse tokens or claim certificate use from
issuance alone.
```

The skill must not rely on known sample names, counts, tokens, or expected
findings. The three synthetic packages are intentionally different to verify
that behavior.

## Presentation checklist

- Run all three synthetic scenarios before the session.
- Open the all-ESC PDF/HTML to demonstrate breadth.
- Open the hardened report to show that CertifEye can return evaluated Clean
  results instead of manufacturing findings.
- Open the mixed report to discuss prioritization and coverage caveats.
- Show that the same templates/requesters correlate by token within one package,
  while tokens differ across independent packages.
- State clearly that findings are defensive posture and historical issuance
  evidence, not proof of exploitation.
- Keep any client-derived sample and its outputs out of slides and shared folders
  unless separately approved.

## Common problems

### Python was not found

Install or make Python 3.9+ available on `PATH`, then run `python --version`.
Collection remains available without Python; report generation does not.

### PDF or PNG is missing

Run `doctor`. Install ReportLab for PDF and CairoSVG for PNG if those optional
formats are required. CertifEye must not create empty placeholder files.

### A role is Not Evaluated

Check the source manifest, input folder, CSV headers, and collection warning.
Do not rename a missing result to Clean.

### DC evidence is intended rather than live

Treat SYSVOL/GPO evidence as intended policy. Confirm live values on every DC
before calling ESC9/10 mitigated.

### The destination already exists

Choose a new folder. For synthetic demos only, use `-Replace` when intentionally
rebuilding an existing demo output.

## Final safety rule

Review every scrubbed package and report before sharing. Tokenization reduces
exposure; it is not a formal guarantee of anonymity.
