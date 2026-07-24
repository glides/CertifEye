# Defensive remediation reference

All actions are advisory and require PKI/AD owner validation, change control,
maintenance windows, and rollback planning.

- ESC1: build subject/SAN from AD where possible; otherwise require approval or
  authorized signatures and restrict enrollment.
- ESC2: remove Any Purpose/no-EKU issuance unless explicitly required; use only
  workload-specific EKUs.
- ESC3: restrict Enrollment Agent issuance and CA agent restrictions.
- ESC4: remove template control rights from non-PKI administrators.
- ESC5: remove dangerous control rights from non-PKI principals on PKI objects.
- ESC6: clear requester-supplied SAN CA behavior when not explicitly required.
- ESC7: restrict Manage CA and Manage Certificates to approved administrators.
- ESC8: remove HTTP, require HTTPS EPA, disable NTLM where possible, or remove
  unused web enrollment roles.
- ESC9/10: complete KB5014754 rollout and move DC strong mapping to full enforcement.
- ESC11: require encrypted ICertRequest traffic and restart the CA after validation.
