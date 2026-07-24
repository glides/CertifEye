# Confidence and prioritization

## Confidence

- High: the source parses cleanly, the relevant join is present, identity mapping
  is reliable, and the signal is explicit rather than a helper flag alone.
- Medium: the signal is clear but one evidence link is weak, such as an unmatched
  template, unmapped identity, metadata-only endpoint, or intended-not-live value.
- Low: parsing is incomplete, required columns are absent, or the conclusion rests
  mainly on an inferred or legacy field.

## Severity modifiers

Increase priority for published templates, broad enrollment, high-value tokens,
auth-capable certificates, CA-wide settings, high-impact PKI objects, reachable
HTTP/NTLM endpoints, and evidence of repeated or recent issuance. Decrease or mark
mitigated when strong DC enforcement, required approval/signatures, or confirmed
HTTPS EPA closes the relevant path.

## Fix-first queue

Reports sort by severity, confidence, and recency, then group repeated evidence by
template/requester/SAN or principal/object. Each top action includes the technical
owner, validation step, remediation, and a reason it reduces risk first.
