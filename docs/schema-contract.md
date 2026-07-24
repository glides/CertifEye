# AD CS scrubbed schema contract

Schema family: `adcs-exports/v1`

This contract is the boundary between the local collector and the reusable
analysis/report pipeline. File names are helpful hints only; analyzers must
classify files by columns and then report the recognized role in the manifest.

## Upload-safe files

| Role | Preferred file | Required identifying columns |
|---|---|---|
| Issued certificates | `exported_certs_normalized_scrubbed.csv` | `RequestID` or `SerialNumber`, `CertificateTemplate`, and one of `RequesterName`, `RequesterIdentityToken`, `SAN_UPN`, or `ParseStatus` |
| Templates | `adcs_template_inventory_scrubbed.csv` | `TemplateName` or `TemplateOID`, plus `Published`, `EKU_OIDs`, or an ESC helper flag |
| CA security | `adcs_ca_security_scrubbed.csv` | `CA_CommonName` plus one of `ManageCAPrincipals`, `ESC7Candidate`, `EditF_AttributeSubjectAltName2`, or `ESC11Candidate` |
| PKI ACLs | `adcs_pki_object_acls_scrubbed.csv` | `PkiObjectType`, `Principal`, and `Rights` |
| DC enforcement | `adcs_dc_enforcement_scrubbed.csv` | `DC_DnsHostName` plus `StrongCertificateBindingEnforcement` or `FullEnforcement` |
| Web enrollment | `adcs_web_enrollment_scrubbed.csv` | `EndpointHostName` or `EndpointKind`, plus `Scheme`, `ESC8Confirmed`, or `Esc8RiskFromMetadata` |
| High-value targets | `high_value_targets_scrubbed.csv` | `Token` and `HighValueReason` |

Older names such as `issued_certs_scrubbed.csv` remain supported. Missing roles
are `Not Evaluated`; they are never treated as clean.

## Common value rules

- Timestamps are UTC ISO 8601 strings when present.
- Boolean values are accepted case-insensitively as `True`/`False`, `1`/`0`,
  and `Yes`/`No`; `Unknown`, blank, and missing remain unevaluated.
- Multi-value fields may be JSON arrays or legacy `;`, `|`, or `,` separated
  values. New collectors should prefer JSON arrays or row-per-relationship
  exports so token correlation is not lost.
- Tokens are opaque. Equal tokens indicate correlation within the same salt/map
  scope; reviewers must not infer the original identity.
- `BROAD_*` and `HV_*` labels are intentionally retained because they are risk
  metadata rather than customer identifiers.

## Analysis result contract

`working/results.json` uses `adcs-analysis/v1` and contains `meta`, `dq`,
`signals`, `coverage`, `findings`, and `graph` objects. `output/ADCS_ESC_Findings.csv`
uses stable columns including readable `FindingID`, durable `FindingKey`, `Category`, `Severity`, `Confidence`,
`ESCType`, `Principal`, `Object`, `Target`, `Occurrences`, `SampleRequestIDs`,
`EvidenceSource`, `PriorityReason`, `RecommendedOwner`, `Evidence`,
`WhyThisMatters`, `RecommendedValidation`, and `RecommendedRemediation`.

## Local-only artifacts

Raw exports, salts, token maps, detailed leak reports, and private manifests must
remain under `Raw_DO_NOT_UPLOAD/` or `Private_DO_NOT_UPLOAD/`. The safe upload
manifest contains only schema, coverage, row counts, filenames, and review flags.
