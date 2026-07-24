# AD CS ESC detection rules

The analyzer separates three evidence classes:

1. Historical issuance: a certificate was issued; this does not prove use.
2. Posture: a template, CA, web endpoint, DC, or PKI ACL enables a condition.
3. Confirmed use: requires supplied authentication evidence, such as DC/Kerberos
   certificate-authentication logs.

## Required calibration

- ESC1 requires publication, requester-supplied subject/SAN, authentication-capable
  EKU, no approval/signature gate, and enrollment rights.
- ESC2 covers Any Purpose, no-EKU, and SubCA-like issuance signals.
- ESC3 covers Enrollment Agent EKU and on-behalf-of issuance; authorized agent use
  is still a validation question.
- ESC4 is dangerous template control, not ordinary enrollment.
- ESC5 is dangerous control over PKI AD objects. `Enroll` and `AutoEnroll` are
  enrollment amplifiers, not object-control findings when precise rights exist.
- ESC6 is authoritative when the CA EditFlags setting confirms requester-supplied
  SAN support; issuance-side SAN attributes are a separate signal.
- ESC7 covers unexpected Manage CA or Manage Certificates principals.
- ESC8 distinguishes HTTP/NTLM metadata, active confirmation, and HTTPS EPA state.
  EPA on HTTPS does not mitigate an HTTP endpoint.
- ESC9/10 requires a missing/mismatched SID extension plus DC enforcement context.
  Exclude rows explicitly marked `SidMismatchLikelyBenign` from the actionable count.
- ESC11 is an encrypted-ICertRequest posture issue; severity increases when a
  certificate issuance path makes the condition relevant.

Every finding must name the source columns that drove the conclusion and list the
missing evidence that prevents a stronger claim.
